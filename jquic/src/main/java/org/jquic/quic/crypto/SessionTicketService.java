/*
 * Copyright 2026 Fedor Malyshev
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jquic.quic.crypto;

import org.jquic.quic.ConnectionMetadata;
import org.jquic.quic.QuicException;
import org.jquic.quic.QuicTransportError;
import org.jquic.quic.buffers.CryptoBufferPool;
import org.jquic.quic.buffers.PoolBuffer;
import org.jquic.quic.struct.BloomFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SessionTicketService {
    private static final Logger log = LoggerFactory.getLogger(SessionTicketService.class);
    public static final int AGE_VARIATION_ALLOWANCE_MS = 3000;
    private static final AtomicLong ticketIdGenerator = new AtomicLong(QuicCrypto.secureRandom.get().nextLong());

    private static BloomFilter period1 = new BloomFilter();
    private static BloomFilter period2 = new BloomFilter();
    private static volatile long lastSwitch;

    private static final ConcurrentHashMap<ByteBuffer, ThreadLocal<NativeCrypto>> stekKeys = new ConcurrentHashMap<>();
    private static final AtomicReference<Stek> currentStek =  new AtomicReference<>();

    private record Stek(byte[] uuid, ThreadLocal<NativeCrypto> crypto) {}

    public static synchronized void addStekKey(byte[] uuid, byte[] key) {
        ThreadLocal<NativeCrypto> currentNativeCrypto = ThreadLocal.withInitial(() -> {
            ByteBuffer stekBuf = QuicCrypto.wrapDirect(key);
            try {
                return new NativeCrypto(new QuicCrypto.PacketProtectionKeysWithHP(stekBuf, null, null), CipherMode.TLS_AES_256_GCM_SHA384_ID);
            } catch (QuicException e) {
                throw new RuntimeException(e);
            }
        });
        currentStek.set(new Stek(uuid, currentNativeCrypto));
        stekKeys.put(ByteBuffer.wrap(uuid), currentNativeCrypto);
    }

    private static synchronized void swapFilters(long now) {
        if (now - lastSwitch > AGE_VARIATION_ALLOWANCE_MS) {
            lastSwitch = now;
            period2.clear();
            BloomFilter t = period1; period1 = period2; period2 = t;
        }
    }

    private static  boolean checkAndMarkId(long now, long id) {
        if (now - lastSwitch > AGE_VARIATION_ALLOWANCE_MS) {
            swapFilters(now);
        }
        boolean present = (period1.contains(id) || period2.contains(id));
        period1.markAdd(id);
        return present;
    }

    private static synchronized Stek getCurrentStek() {
        return currentStek.get();
    }

    public static NativeCrypto getStekCrypto(byte[] uuid) {
        return stekKeys.get(ByteBuffer.wrap(uuid)).get();
    }

    static ConnectionMetadata.ClientMetadataNegotiated tryParsePreSharedKey(long now, ConnectionMetadata metadata, ByteBuffer buf) throws QuicException {
        int transcriptUpdStart = buf.position();

        long selectedIdentityIdx = -1;
        byte[] selectedPsk = null;
        ConnectionMetadata.ClientMetadataNegotiated selectedMetadata = null;
        int identitiesListLen = buf.getShort() & 0xFFFF;
        int identitiesListEnd = buf.position() + identitiesListLen;
        int identityIdx = 0;
        while (buf.position() < identitiesListEnd) {
            int identityLen = buf.getShort() & 0xFFFF;
            if (buf.remaining() < identityLen + 4) { // identity + obfuscated_ticket_age
                throw new QuicException("Truncated PSK identity");
            }
            if (selectedIdentityIdx == -1) {
                int currentPos = buf.position();
                ByteBuffer ticketBuf = buf.duplicate();
                ticketBuf.position(currentPos);
                ticketBuf.limit(currentPos + identityLen);

                ByteBuffer cp = ByteBuffer.allocateDirect(ticketBuf.remaining());
                cp.put(ticketBuf).flip();
                try {
                    SessionTicketInfo info = parseSessionTicket(cp.rewind());
                    selectedIdentityIdx = identityIdx;
                    selectedPsk = info.psk();
                    selectedMetadata = info.metadata();

                    buf.position(currentPos + identityLen);
                    
                    long obfuscatedTicketAge = buf.getInt();

                    if ( Math.abs( (obfuscatedTicketAge - info.ticketAgeAdd) & 0xFFFFFFFFL - (now - info.timestamp) ) > AGE_VARIATION_ALLOWANCE_MS) {
                        log.info("Session Ticket Age Mismatch {} (OTA) - {} (ADD) = {} <> {} (now) - {} timestamp = {} ", obfuscatedTicketAge, info.ticketAgeAdd,
                                (obfuscatedTicketAge - info.ticketAgeAdd) & 0xFFFFFFFFL, now, info.timestamp,  now - info.timestamp );
                        throw new QuicException("Invalid ticket age");
                    }

                    if (info.metadata.selectedCipherSuite == null) {
                        throw new QuicException("Invalid cipher suite");
                    }

                    if (checkAndMarkId(now, info.uniqueNumber)) {
                        throw new QuicException("Used ticket id.");
                    }

                    log.debug("Found suitable PSK identity: {}", selectedIdentityIdx);
                } catch (Exception e) {
                    log.info("Failed to parse PSK identity: {}", selectedIdentityIdx, e);
                } finally {
                    buf.position(currentPos + identityLen + 4);
                }
            } else {
                buf.position(buf.position() + identityLen + 4);
            }
            identityIdx++;
        }

        if (selectedIdentityIdx == -1) {
            log.warn("No suitable PSK identity");
            return null;
        }

        metadata.updateTranscript(buf.duplicate().position(transcriptUpdStart).limit(buf.position()));
        transcriptUpdStart = buf.position();
        byte[] transcriptHash = metadata.transcriptHash();

        ByteBuffer b = ByteBuffer.allocate(buf.position());
        b.put(buf.duplicate().position(0).limit(buf.position()));

        int bindersListLen = buf.getShort() & 0xFFFF;
        int bindersListEnd = buf.position() + bindersListLen;
        int binderIdx = 0;
        while (buf.position() < bindersListEnd) {
            int binderLen = buf.get() & 0xFF;
            if (binderIdx == selectedIdentityIdx) {
                byte[] binderProvided = new byte[binderLen];
                buf.get(binderProvided);
                verifyBinder(transcriptHash, selectedPsk, binderProvided);
            } else {
                buf.position(buf.position() + binderLen);
            }
            binderIdx++;
        }

        metadata.updateTranscript(buf.duplicate().position(transcriptUpdStart).limit(buf.position()));

        if (selectedMetadata != null) {
            // Return a copy of the metadata with the selected identity and RMS
            return new ConnectionMetadata.ClientMetadataNegotiated(
                    selectedMetadata.alpn, selectedMetadata.maxIdleTimeoutMs, selectedMetadata.supportedGroups,
                    selectedMetadata.clientKeys, selectedMetadata.maxUdpPayloadSize,
                    selectedMetadata.initialStreamLimits.maxData,
                    selectedMetadata.initialStreamLimits.maxStreamDataBidiLocal,
                    selectedMetadata.initialStreamLimits.maxStreamDataBidiRemote,
                    selectedMetadata.initialStreamLimits.maxStreamDataUni,
                    selectedMetadata.initialStreamLimits.maxBidi,
                    selectedMetadata.initialStreamLimits.maxUni,
                    selectedMetadata.supportedSignatures,
                    selectedMetadata.ackDelayExponent,
                    selectedMetadata.availableVersions,
                    selectedMetadata.selectedCipherSuite,
                    null, selectedIdentityIdx, selectedPsk
            );
        }

        return null;
    }

    /**
     * Parses and decrypts a session ticket.
     */
    public static SessionTicketInfo parseSessionTicket(ByteBuffer ticket) throws QuicException {
        if (ticket.remaining() < 16 + QuicCrypto.GCM_NONCE_LENGTH + QuicCrypto.GCM_TAG_LENGTH) {
            throw new QuicException("Invalid session ticket: too short");
        }

        byte[] ticketUuid = new byte[16];
        ticket.get(ticketUuid);
        NativeCrypto stekCrypto = getStekCrypto(ticketUuid);

        if (stekCrypto == null) {
            throw new QuicException("Invalid STEK UUID in session ticket");
        }

        ByteBuffer nonceBuf = ticket.duplicate().limit(ticket.position() + QuicCrypto.GCM_NONCE_LENGTH);
        ticket.position(ticket.position() + QuicCrypto.GCM_NONCE_LENGTH);

        try {
            stekCrypto.decryptAeadInPlace(ticket, null, nonceBuf);
        } catch (Exception e) {
            throw new QuicException("Failed to decrypt session ticket", e);
        }

        try {
            byte[] psk = new byte[32];
            ticket.get(psk);

            int alpnLen = ticket.get() & 0xFF;
            String alpn = null;
            if (alpnLen > 0) {
                byte[] alpnBytes = new byte[alpnLen];
                ticket.get(alpnBytes);
                alpn = new String(alpnBytes, UTF_8);
            }

            long maxIdleTimeoutMs = ticket.getLong();
            long maxUdpPayloadSize = ticket.getLong();
            long maxData = ticket.getLong();
            long bidiLocal = ticket.getLong();
            long bidiRemote = ticket.getLong();
            long uni = ticket.getLong();
            long maxBidi = ticket.getLong();
            long maxUni = ticket.getLong();

            int sigCount = ticket.getShort() & 0xFFFF;
            List<Short> signatures = new ArrayList<>(sigCount);
            for (int i = 0; i < sigCount; i++) {
                signatures.add(ticket.getShort());
            }

            int groupCount = ticket.getShort() & 0xFFFF;
            List<Short> groups = new ArrayList<>(groupCount);
            for (int i = 0; i < groupCount; i++) {
                groups.add(ticket.getShort());
            }

            long ackDelayExponent = ticket.getLong();
            CipherMode cipherSuite = CipherMode.fromInt(ticket.getShort() & 0xFFFF);

            int verCount = ticket.getShort() & 0xFFFF;
            List<Integer> versions = new ArrayList<>(verCount);
            for (int i = 0; i < verCount; i++) {
                versions.add(ticket.getInt());
            }

            long uniqueNumber = ticket.getLong();
            long timestamp = ticket.getLong();
            long ticketAgeAdd = ticket.getLong();


            ConnectionMetadata.ClientMetadataNegotiated ticketMetadata = new ConnectionMetadata.ClientMetadataNegotiated(
                    alpn, maxIdleTimeoutMs, groups, new HashMap<>(), maxUdpPayloadSize,
                    maxData, bidiLocal, bidiRemote, uni, maxBidi, maxUni,
                    signatures, ackDelayExponent, versions, cipherSuite, null, -1, psk
            );

            return new SessionTicketInfo(psk, ticketMetadata, uniqueNumber, timestamp, ticketAgeAdd);
        } catch (Exception e) {
            throw new QuicException("Failed to parse session ticket", e);
        }
    }

    static void verifyBinder(byte[] transcriptHash, byte[] psk, byte[] binderProvided) throws QuicException {
        try {
            // Early Secret = HKDF-Extract(0, PSK)
            byte[] earlySecret = QuicCrypto.hkdfExtract(new byte[32], psk);

            // resumption_binder_key = HKDF-Expand-Label(earlySecret, "res binder",   transcript_hash(empty))
            // Empty transcript hash (SHA-256) is e3b0c442... but HKDF-Expand-Label in TLS 1.3
            // uses a zero-length context if no context is provided.
            // RFC 8446 Section 7.1: "The 'context' for the resumption binder is a zero-length Octet String."
            byte[] resumptionBinderKey = QuicCrypto.hkdfExpandLabel(earlySecret, "res binder", QuicCrypto.sha256(new byte[0]), 32);
            byte[] verifier = QuicCrypto.hkdfExpandLabel(resumptionBinderKey, "finished", new byte[0], 32);

            // Binder = HMAC(resumptionBinderKey, transcriptHash)
            Mac mac = QuicCrypto.MAC.get();
            mac.init(new SecretKeySpec(verifier, "HmacSHA256"));

            byte[] expectedBinder = mac.doFinal(transcriptHash);

            if (!MessageDigest.isEqual(expectedBinder, binderProvided)) {
                log.warn("Failed to verify binder expected {} got {}", HexFormat.of().formatHex(expectedBinder), HexFormat.of().formatHex(binderProvided));
                throw new QuicException("PSK binder verification failed", QuicTransportError.PROTOCOL_VIOLATION);
            }
        } catch (GeneralSecurityException e) {
            throw new QuicException("Failed to verify PSK binder", e);
        }
    }

    /**
     * Generates an encrypted session ticket directly into the output buffer.
     */
    public static void generateSessionTicket(ByteBuffer output, byte[] PSK, ConnectionMetadata.ClientMetadataNegotiated metadata, long uniqueNumber, long timestamp, long ticketAgeAdd) throws QuicException {
        Stek stek = SessionTicketService.getCurrentStek();

        NativeCrypto stekCrypto = stek.crypto().get();
        if (stekCrypto == null) {
            throw new QuicException("STEK not initialized");
        }

        int start = output.position();

        output.put(stek.uuid());

        byte[] finalNonce = new byte[QuicCrypto.GCM_NONCE_LENGTH];
        QuicCrypto.secureRandom.get().nextBytes(finalNonce);
        output.put(finalNonce);

        ByteBuffer nonceBuf = output.duplicate().position(output.position() - QuicCrypto.GCM_NONCE_LENGTH).limit(output.position());

        int startPayload = output.position();

        output.put(PSK);
        if (metadata.alpn != null) {
            byte[] alpnBytes = metadata.alpn.getBytes(UTF_8);
            output.put((byte) alpnBytes.length);
            output.put(alpnBytes);
        } else {
            output.put((byte) 0);
        }

        output.putLong(metadata.maxIdleTimeoutMs);
        output.putLong(metadata.maxUdpPayloadSize);
        output.putLong(metadata.initialStreamLimits.maxData);
        output.putLong(metadata.initialStreamLimits.maxStreamDataBidiLocal);
        output.putLong(metadata.initialStreamLimits.maxStreamDataBidiRemote);
        output.putLong(metadata.initialStreamLimits.maxStreamDataUni);
        output.putLong(metadata.initialStreamLimits.maxBidi);
        output.putLong(metadata.initialStreamLimits.maxUni);

        output.putShort((short) metadata.supportedSignatures.size());
        for (short sig : metadata.supportedSignatures) {
            output.putShort(sig);
        }

        output.putShort((short) metadata.supportedGroups.size());
        for (short group : metadata.supportedGroups) {
            output.putShort(group);
        }

        output.putLong(metadata.ackDelayExponent);
        output.putShort((short) metadata.selectedCipherSuite.val);

        output.putShort((short) metadata.availableVersions.size());
        for (int ver : metadata.availableVersions) {
            output.putInt(ver);
        }

        output.putLong(uniqueNumber);
        output.putLong(timestamp);
        output.putLong(ticketAgeAdd);

        output.limit(output.position());
        output.position(startPayload);

        // Encrypt in-place in the direct buffer 'plain'
        stekCrypto.encryptAeadInPlace(output, java.lang.foreign.MemorySegment.NULL, nonceBuf);

        // Result of encryption is in 'plain' from startPayload to limit
        output.position(start);
    }

    public static void generateSessionTicket(PoolBuffer output, byte[] PSK, ConnectionMetadata.ClientMetadataNegotiated metadata, long uniqueNumber, long timestamp, long ticketAgeAdd) throws QuicException {
        generateSessionTicket(output.buf(), PSK, metadata, uniqueNumber, timestamp, ticketAgeAdd);
    }

    /**
     * Creates a TLS 1.3 NewSessionTicket message (RFC 8446 Section 4.6.1).
     *
     * <p>Wire format:
     * <pre>
     *   HandshakeType (1) = 0x04 (new_session_ticket)
     *   Length        (3)
     *   ticket_lifetime (4)
     *   ticket_age_add  (4)
     *   ticket_nonce    (1 + n)
     *   ticket          (2 + n)
     *   extensions      (2 + n)
     * </pre>
     *
     * @param metadata  the live {@link ConnectionMetadata}
     * @param timestamp the creation timestamp
     * @param output    the stream to write to
     * @throws QuicException if ticket generation fails
     * @throws IOException   if writing to the stream fails
     */
    public static void createNewSessionTicket(CryptoBufferPool pool, ConnectionMetadata metadata, long timestamp, DataOutputStream output) throws QuicException, IOException {
        long ticketId = ticketIdGenerator.incrementAndGet();
        long ticketAgeAdd = QuicCrypto.secureRandom.get().nextInt() & 0xFFFFFFFFL;

        byte[] ticketNonce = new byte[QuicCrypto.GCM_NONCE_LENGTH];
        QuicCrypto.secureRandom.get().nextBytes(ticketNonce);

        // Derive unique resumption secret for this ticket
        byte[] PSK = QuicCrypto.hkdfExpandLabel(metadata.resumptionMasterSecret, "resumption", ticketNonce, 32);

        PoolBuffer buffer = pool.requestCryptoBuffer(QuicCrypto.MAX_SESSION_TICKET_SIZE);
        try {
            generateSessionTicket(buffer, PSK, metadata.clientMetadata, ticketId, timestamp, ticketAgeAdd);

            // ticket_lifetime (4) + ticket_age_add (4) + nonce_len(1) + nonce(12) + ticket_len(2) + ticket + extensions_len(2) + extension_early_data(2+2+4)
            int extensionsLen = 2 + 2 + 4; // EARLY_DATA extension type(2) + len(2) + max_early_data_size(4)
            int ticketMsgLen = 4 + 4 + 1 + ticketNonce.length + 2 + buffer.buf().remaining() + 2 + extensionsLen;

            output.write((byte) 0x04); // HandshakeType: new_session_ticket
            output.write((byte) ((ticketMsgLen >>> 16) & 0xFF));
            output.write((byte) ((ticketMsgLen >>> 8) & 0xFF));
            output.write((byte) (ticketMsgLen & 0xFF));

            output.writeInt(86400); // ticket_lifetime: 24 hours
            output.writeInt((int) ticketAgeAdd); // ticket_age_add

            output.write((byte) ticketNonce.length);
            output.write(ticketNonce);

            byte[] ticketBytes = new byte[buffer.buf().remaining()];
            buffer.buf().duplicate().get(ticketBytes);

            output.writeShort(ticketBytes.length);
            output.write(ticketBytes);

            output.writeShort(extensionsLen);
            output.writeShort(42); // ExtensionType: early_data (42)
            output.writeShort(4);  // ExtensionData length: 4
            output.writeInt(0xFFFFFFFF); // max_early_data_size
        } finally {
            buffer.release();
        }
    }

    public record SessionTicketInfo(byte[] psk, ConnectionMetadata.ClientMetadataNegotiated metadata, long uniqueNumber,
                                    long timestamp, long ticketAgeAdd) {
    }
}
