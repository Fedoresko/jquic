/*
 * Copyright 2026 Fedor Malyshev
 *
 * Licensed under the Apache License, Version 2.0 (the "License") ;
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

import org.jquic.boringssl.EVP_AEAD_CTX;
import org.jquic.boringssl.EVP_CIPHER_CTX;
import org.jquic.boringssl.err_h;
import org.jquic.boringssl.evp_h;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.jquic.boringssl.evp_h.*;
import static org.jquic.quic.crypto.QuicCrypto.GCM_NONCE_LENGTH;

public class NativeCrypto implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(NativeCrypto.class);

    private final Arena arena = Arena.ofConfined();
    private final ByteBuffer nonceBuf = ByteBuffer.allocateDirect(GCM_NONCE_LENGTH);
    private final MemorySegment aeadCtx = EVP_AEAD_CTX.allocate(arena);
    private final MemorySegment retLen = arena.allocate(ValueLayout.JAVA_LONG);
    private final MemorySegment ecbCtx = EVP_CIPHER_CTX.allocate(arena);

    private final QuicCrypto.PacketProtectionKeysWithHP keys;

    /**
     * Set ecnription keys used for the all further encription calls.
     * @param keys - encryption key parameters
     * @throws QuicCrypto.CryptoException - exception if crypto problems
     */
    public NativeCrypto(QuicCrypto.PacketProtectionKeysWithHP keys) throws QuicCrypto.CryptoException {
        this.keys = keys;

        if (keys.headerProtection() != null) {
            EVP_CIPHER_CTX_init(ecbCtx);
            try {
                if (EVP_EncryptInit_ex(ecbCtx, EVP_aes_128_ecb(), MemorySegment.NULL,
                        MemorySegment.ofBuffer(keys.headerProtection()), MemorySegment.NULL) != 1) {
                    logErrorAndThrow("Failed to init AES / ECB");
                }

                if (EVP_CIPHER_CTX_set_padding(ecbCtx, 0) != 1) {
                    logErrorAndThrow("Failed to set padding AES / ECB");
                }
            } catch (Exception e) {
                EVP_CIPHER_CTX_cleanup(ecbCtx);
                throw e;
            }
        }

        if (keys.key() != null) {
            MemorySegment aead_engine = evp_h.EVP_aead_aes_128_gcm();
            if (EVP_AEAD_CTX_init(aeadCtx, aead_engine, MemorySegment.ofBuffer(keys.key()),
                    keys.key().remaining(), EVP_AEAD_DEFAULT_TAG_LENGTH(), MemorySegment.NULL) != 1) {

                String error = "Failed to initialize EVP_AEAD_CTX";
                logErrorAndThrow(error);
            }
        }
    }

    public ByteBuffer getHpKey() {
        return keys == null ? null : keys.headerProtection();
    }

    @Override
    public void close() throws Exception {
        EVP_CIPHER_CTX_cleanup(ecbCtx);
        EVP_AEAD_CTX_cleanup(aeadCtx);

        arena.close();
    }

    /**
     * Decrypts a QUIC packet with AES-128-GCM AEAD. Uses direct ByteBuffer for efficiency.
     * RFC 9001 Section 5.3: AEAD function usage in QUIC
     * The AEAD function protects packet payloads and authenticates packet headers.
     * Associated Data (AD) = packet header (from first byte through unprotected packet number)
     * Plaintext = packet payload (QUIC frames)
     * Output = ciphertext + 16-byte GCM authentication tag
     * The GCM tag authenticates BOTH the header (via AD) and the encrypted payload.
     *
     * @param encrypted      The encrypted data to decrypt (QUIC frames)
     * @param packetNumber   QUIC packet number (used to construct nonce via XOR with base IV)
     * @param associatedData Packet header bytes to authenticate (RFC 9001 Section 5.4.1)
     * @throws QuicCrypto.CryptoException if decryption fails
     */
    public void decryptAeadInPlace(ByteBuffer encrypted, long packetNumber, ByteBuffer associatedData) throws QuicCrypto.CryptoException {
        ByteBuffer nonce = generateNonce(packetNumber, keys.iv());
        decryptAeadInPlace(encrypted, MemorySegment.ofBuffer(associatedData), nonce);
    }

    /**
     * Encrypts a QUIC packet with AES-128-GCM AEAD. Uses direct ByteBuffer for efficiency.
     * RFC 9001 Section 5.3: AEAD function usage in QUIC
     * The AEAD function protects packet payloads and authenticates packet headers.
     * Associated Data (AD) = packet header (from first byte through unprotected packet number)
     * Plaintext = packet payload (QUIC frames)
     * Output = ciphertext + 16-byte GCM authentication tag
     * The GCM tag authenticates BOTH the header (via AD) and the encrypted payload.
     *
     * @param plaintext      The plaintext data to encrypt (QUIC frames)
     * @param packetNumber   QUIC packet number (used to construct nonce via XOR with base IV)
     * @param associatedData Packet header bytes to authenticate (RFC 9001 Section 5.4.1)
     * @throws QuicCrypto.CryptoException if encryption fails
     */
    public void encryptPacketInPlace(ByteBuffer plaintext, long packetNumber,
                                            ByteBuffer associatedData) throws QuicCrypto.CryptoException {
        ByteBuffer nonce = generateNonce(packetNumber, keys.iv());
        encryptAeadInPlace(plaintext, MemorySegment.ofBuffer(associatedData), nonce);
    }

    /**
     * Encpript using plain AES/ECB cipher over the 128-bit current key.
     * @param plaintext - plaintext
     * @throws QuicCrypto.CryptoException if encryption fails
     */
    public void encryptEcbInPlace(ByteBuffer plaintext) throws QuicCrypto.CryptoException {
        if (EVP_EncryptUpdate(ecbCtx, MemorySegment.ofBuffer(plaintext), retLen,
                MemorySegment.ofBuffer(plaintext), plaintext.remaining()) != 1) {
            logErrorAndThrow("Failed to encrypt AES / ECB");
        }
    }

    private void decryptAeadInPlace(ByteBuffer encrypted, MemorySegment associatedData, ByteBuffer nonce) throws QuicCrypto.CryptoException {
        int ret = EVP_AEAD_CTX_open(aeadCtx,
                MemorySegment.ofBuffer(encrypted), retLen, encrypted.remaining(),
                MemorySegment.ofBuffer(nonce.rewind()), GCM_NONCE_LENGTH,
                MemorySegment.ofBuffer(encrypted), encrypted.remaining(),
                associatedData, associatedData.byteSize());

        if (ret != 1) {
            logErrorAndThrow("Failed to open EVP_AEAD_CTX(" + ret + ") ");
        }
        encrypted.limit(encrypted.position() + (int) retLen.get(ValueLayout.JAVA_LONG, 0));
    }

    private void encryptAeadInPlace(ByteBuffer plaintext, MemorySegment associatedData, ByteBuffer nonce) throws QuicCrypto.CryptoException {
        if (EVP_AEAD_CTX_seal(aeadCtx,
                MemorySegment.ofBuffer(plaintext), retLen, plaintext.remaining() + QuicCrypto.GCM_TAG_LENGTH,
                MemorySegment.ofBuffer(nonce.rewind()), GCM_NONCE_LENGTH,
                MemorySegment.ofBuffer(plaintext), plaintext.remaining(),
                associatedData, associatedData.byteSize()) != 1) {
            logErrorAndThrow("Failed to seal EVP_AEAD_CTX");
        }
        plaintext.limit(plaintext.position() + (int) retLen.get(ValueLayout.JAVA_LONG, 0));
    }


    private @NonNull ByteBuffer generateNonce(long packetNumber, byte[] baseIv) {
        ByteBuffer nonce = nonceBuf;
        nonce.rewind().put(baseIv);
        for (int i = 0; i < 8; i++) {
            nonce.put(GCM_NONCE_LENGTH - 1 - i,
                    (byte) (baseIv[GCM_NONCE_LENGTH - 1 - i] ^ (byte) (packetNumber >> (i * 8))));
        }
        return nonce;
    }

    private static void logSslError(String error) {
        int errorCode = err_h.ERR_get_error();
        if (errorCode > 0) {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment errorBuffer = arena.allocate(256);
                err_h.ERR_error_string_n(errorCode, errorBuffer, errorBuffer.byteSize());
                logger.error(error + " code: {}, {}", errorCode, errorBuffer.getString(0, StandardCharsets.US_ASCII));
            }
        }
    }

    private static void logErrorAndThrow(String error) throws QuicCrypto.CryptoException {
        logSslError(error);
        throw new QuicCrypto.CryptoException(error);
    }

}
