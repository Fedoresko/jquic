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
package org.jquic.quic;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Manages loading of private keys and certificates from PKCS12 keystore.
 */
public class KeystoreManager {
    private static final Logger logger = LoggerFactory.getLogger(KeystoreManager.class);

    private final PrivateKey privateKey;
    private final X509Certificate[] certificateChain;

    /**
     * Loads keystore and extracts private key and certificate chain.
     * 
     * @param config Server configuration containing keystore settings
     * @throws KeyStoreException if keystore loading fails
     */
    public KeystoreManager(QuicServerConfig config) throws KeyStoreException {
        try {
            // Load PKCS12 keystore
            KeyStore keystore = KeyStore.getInstance("PKCS12");

            try (FileInputStream fis = new FileInputStream(config.getKeystorePath())) {
                keystore.load(fis, config.getKeystorePassword());
                logger.info("Loaded keystore from: {}", config.getKeystorePath());
            }

            // Extract private key
            Key key = keystore.getKey(config.getKeyAlias(), config.getKeystorePassword());
            if (key == null || !(key instanceof PrivateKey)) {
                throw new KeyStoreException("No private key found for alias: " + config.getKeyAlias());
            }
            this.privateKey = (PrivateKey) key;
            logger.debug("Loaded private key with algorithm: {}", privateKey.getAlgorithm());

            // Extract certificate chain
            Certificate[] certs = keystore.getCertificateChain(config.getKeyAlias());
            if (certs == null || certs.length == 0) {
                throw new KeyStoreException("No certificate chain found for alias: " + config.getKeyAlias());
            }

            this.certificateChain = new X509Certificate[certs.length];
            for (int i = 0; i < certs.length; i++) {
                if (!(certs[i] instanceof X509Certificate)) {
                    throw new KeyStoreException("Certificate is not X.509 format");
                }
                this.certificateChain[i] = (X509Certificate) certs[i];
            }

            logger.info("Loaded certificate chain with {} certificates", certificateChain.length);
            logger.debug("Server certificate subject: {}", certificateChain[0].getSubjectX500Principal());

        } catch (IOException | NoSuchAlgorithmException | java.security.cert.CertificateException | 
                 UnrecoverableKeyException e) {
            throw new KeyStoreException("Failed to load keystore", e);
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public X509Certificate[] getCertificateChain() {
        return certificateChain;
    }


    private Signature getSignature(Short signatureSchemeId) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        TlsSignatureMapping.JcaSchemeInfo info = TlsSignatureMapping.resolve(signatureSchemeId);
        Signature signature = Signature.getInstance(info.jcaAlgorithm);
        if (info.parameterSpec != null) {
            signature.setParameter(info.parameterSpec);
        }
        return signature;
    }

    public Short selectSignatureScheme(List<Short> clientSchemes) {
        String keyAlgorithm = privateKey.getAlgorithm(); // e.g., "RSA" or "EC"

        for (short scheme : clientSchemes) {
            TlsSignatureMapping.JcaSchemeInfo info = TlsSignatureMapping.resolve(scheme);
            if (info == null) continue; // Skip if our mapping doesn't recognize it

            // 1. Check if the scheme matches your loaded private key type
            if (keyAlgorithm.equalsIgnoreCase("RSA")) {
                // Is it an RSA-PSS or standard RSA scheme?
                if (!info.jcaAlgorithm.contains("RSA")) continue;
            } else if (keyAlgorithm.equalsIgnoreCase("EC")) {
                // Is it an ECDSA scheme?
                if (!info.jcaAlgorithm.contains("ECDSA")) continue;
            } else if (keyAlgorithm.equalsIgnoreCase("Ed25519") || keyAlgorithm.equalsIgnoreCase("EdDSA")) {
                if (!info.jcaAlgorithm.equalsIgnoreCase("Ed25519")) continue;
            } else {
                continue; // Unsupported key type
            }

            // 2. Verify that your underlying Java Runtime actually supports this algorithm
            try {
                Signature.getInstance(info.jcaAlgorithm);
                // If it didn't throw an exception, this scheme is available and safe to use!
                return scheme;
            } catch (Exception e) {
                // Local Java security provider lacks this specific algorithm; try next
            }
        }

        throw new IllegalStateException("No mutually supported signature schemes found between client and server.");
    }

    /**
     * Encodes certificate chain in TLS Certificate message format (RFC 8446 Section 4.4.2).
     * Format: certificate_list &lt;0..2^24-1&gt; where each entry is:
     *   - cert_data&lt;1..2^24-1&gt; (DER-encoded certificate)
     *   - extensions&lt;0..2^16-1&gt; (empty for now)
     */
    public byte[] encodeCertificateChainTls() throws CertificateEncodingException {
        // Calculate total size
        int totalSize = 3; // certificate_list length (3 bytes)
        for (X509Certificate cert : certificateChain) {
            totalSize += 3; // cert_data length (3 bytes)
            totalSize += cert.getEncoded().length;
            totalSize += 2; // extensions length (2 bytes)
        }

        byte[] encoded = new byte[totalSize];
        int offset = 0;

        // Certificate list length (24-bit)
        int certListLength = totalSize - 3;
        encoded[offset++] = (byte) ((certListLength >> 16) & 0xFF);
        encoded[offset++] = (byte) ((certListLength >> 8) & 0xFF);
        encoded[offset++] = (byte) (certListLength & 0xFF);

        // Encode each certificate
        for (X509Certificate cert : certificateChain) {
            byte[] certBytes = cert.getEncoded();

            // Cert data length (24-bit)
            encoded[offset++] = (byte) ((certBytes.length >> 16) & 0xFF);
            encoded[offset++] = (byte) ((certBytes.length >> 8) & 0xFF);
            encoded[offset++] = (byte) (certBytes.length & 0xFF);

            // Cert data
            System.arraycopy(certBytes, 0, encoded, offset, certBytes.length);
            offset += certBytes.length;

            // Extensions (empty for now)
            encoded[offset++] = 0x00;
            encoded[offset++] = 0x00;
        }

        return encoded;
    }

    /**
     * Signs data using the private key.
     * Used for TLS CertificateVerify message.
     */
    public byte[] sign(byte[] data, short signatureScheme) throws GeneralSecurityException {
        Signature signature = getSignature(signatureScheme);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
}

