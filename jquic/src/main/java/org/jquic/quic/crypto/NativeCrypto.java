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
import org.jquic.quic.QuicException;
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
    private final MemorySegment zeroIn = arena.allocate(16);
    private final MemorySegment errorBuffer = arena.allocate(256);
    private final MemorySegment sealOutLen = arena.allocate(ValueLayout.JAVA_LONG);
    private final MemorySegment openOutLen = arena.allocate(ValueLayout.JAVA_LONG);

    private final QuicCrypto.PacketProtectionKeysWithHP keys;
    private final CipherMode mode;

    /**
     * Set ecnription keys used for the all further encription calls.
     *
     * @param keys - encryption key parameters
     * @param mode
     * @throws QuicException - exception if crypto problems
     */
    public NativeCrypto(QuicCrypto.PacketProtectionKeysWithHP keys, CipherMode mode) throws QuicException {
        this.keys = keys;
        this.mode = mode;

        if (keys.headerProtection() != null) {
            if (mode == CipherMode.TLS_AES_128_GCM_SHA256_ID || mode == CipherMode.TLS_AES_256_GCM_SHA384_ID) {
                EVP_CIPHER_CTX_init(ecbCtx);
                try {
                    MemorySegment cipher = mode == CipherMode.TLS_AES_128_GCM_SHA256_ID ? EVP_aes_128_ecb() : EVP_aes_256_ecb();
                    if (EVP_EncryptInit_ex(ecbCtx, cipher, MemorySegment.NULL,
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
        }

        if (keys.key() != null) {
            MemorySegment aead_engine = switch (mode) {
                case TLS_AES_128_GCM_SHA256_ID -> EVP_aead_aes_128_gcm();
                case TLS_AES_256_GCM_SHA384_ID -> EVP_aead_aes_256_gcm();
                case TLS_CHACHA20_POLY1305_SHA256 -> EVP_aead_chacha20_poly1305();
                default -> throw new QuicException("Unsupported cipher mode: " + mode);
            };
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
     * @throws QuicException if decryption fails
     */
    public void decryptAeadInPlace(ByteBuffer encrypted, long packetNumber, ByteBuffer associatedData) throws QuicException {
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
     * @throws QuicException if encryption fails
     */
    public void encryptPacketInPlace(ByteBuffer plaintext, long packetNumber,
                                            ByteBuffer associatedData) throws QuicException {
        ByteBuffer nonce = generateNonce(packetNumber, keys.iv());
        encryptAeadInPlace(plaintext, MemorySegment.ofBuffer(associatedData), nonce);
    }

    /**
     * Encpript using plain AES/ECB cipher over the 128-bit current key or ChaCha20 block function.
     * @param plaintext - plaintext
     * @throws QuicException if encryption fails
     */
    public void encryptEcbInPlace(ByteBuffer plaintext) throws QuicException {
        if (mode == CipherMode.TLS_AES_128_GCM_SHA256_ID || mode == CipherMode.TLS_AES_256_GCM_SHA384_ID) {
            if (EVP_EncryptUpdate(ecbCtx, MemorySegment.ofBuffer(plaintext), retLen,
                    MemorySegment.ofBuffer(plaintext), plaintext.remaining()) != 1) {
                logErrorAndThrow("Failed to encrypt AES / ECB");
            }
        } else if (mode == CipherMode.TLS_CHACHA20_POLY1305_SHA256) {
            // RFC 9001 5.4.4: The block function takes a 256-bit key and a 16-byte sample.
            // The first 4 bytes of the sample are used as a block counter and the next 12 bytes are used as a nonce.
            // CRYPTO_chacha_20(uint8_t *out, const uint8_t *in, size_t in_len, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter)
            MemorySegment sample = MemorySegment.ofBuffer(plaintext);
            MemorySegment hpKey = MemorySegment.ofBuffer(keys.headerProtection());
            MemorySegment nonce = sample.asSlice(4, 12);
            int counter = sample.get(ValueLayout.JAVA_INT.withOrder(java.nio.ByteOrder.LITTLE_ENDIAN), 0);

            // We need a 16-byte zero input to get the keystream block
            org.jquic.boringssl.chacha_h.CRYPTO_chacha_20(sample, zeroIn, 16, hpKey, nonce, counter);
        }
    }

    private void decryptAeadInPlace(ByteBuffer encrypted, MemorySegment associatedData, ByteBuffer nonce) throws QuicException {
        int ret = EVP_AEAD_CTX_open(aeadCtx,
                MemorySegment.ofBuffer(encrypted), openOutLen, encrypted.remaining(),
                MemorySegment.ofBuffer(nonce.rewind()), GCM_NONCE_LENGTH,
                MemorySegment.ofBuffer(encrypted), encrypted.remaining(),
                associatedData, associatedData.byteSize());

        if (ret != 1) {
            logErrorAndThrow("Failed to open EVP_AEAD_CTX(" + ret + ") ");
        }
        encrypted.limit(encrypted.position() + (int) openOutLen.get(ValueLayout.JAVA_LONG, 0));
    }

    private void encryptAeadInPlace(ByteBuffer plaintext, MemorySegment associatedData, ByteBuffer nonce) throws QuicException {
        if (EVP_AEAD_CTX_seal(aeadCtx,
                MemorySegment.ofBuffer(plaintext), sealOutLen, plaintext.remaining() + QuicCrypto.GCM_TAG_LENGTH,
                MemorySegment.ofBuffer(nonce.rewind()), GCM_NONCE_LENGTH,
                MemorySegment.ofBuffer(plaintext), plaintext.remaining(),
                associatedData, associatedData.byteSize()) != 1) {
            logErrorAndThrow("Failed to seal EVP_AEAD_CTX");
        }
        plaintext.limit(plaintext.position() + (int) sealOutLen.get(ValueLayout.JAVA_LONG, 0));
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

    private void logSslError(String error) {
        int errorCode = err_h.ERR_get_error();
        if (errorCode > 0) {
            err_h.ERR_error_string_n(errorCode, errorBuffer, errorBuffer.byteSize());
            logger.error(error + " code: {}, {}", errorCode, errorBuffer.getString(0, StandardCharsets.US_ASCII));
        }
    }

    private void logErrorAndThrow(String error) throws QuicException {
        logSslError(error);
        throw new QuicException(error);
    }

}
