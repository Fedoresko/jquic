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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Manages loading of private keys and certificates from PKCS12 keystore or PEM files.
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
        if ("PEM".equalsIgnoreCase(config.getKeystoreType())) {
            this.privateKey = loadPrivateKeyFromPem(config.getKeyPath());
            this.certificateChain = loadCertificateChainFromPem(config.getCertPath());
        } else {
            // Load PKCS12 keystore
            try {
                KeyStore keystore = KeyStore.getInstance("PKCS12");
                if (config.getKeystorePath() == null || config.getKeystorePath().equalsIgnoreCase("dummy")) {
                    this.privateKey = null;
                    this.certificateChain = null;
                    return;
                }

                try (FileInputStream fis = new FileInputStream(config.getKeystorePath())) {
                    keystore.load(fis, config.getKeystorePassword());
                    logger.info("Loaded keystore from: {}", config.getKeystorePath());
                }

                // Extract private key
                Key key = keystore.getKey(config.getKeyAlias(), config.getKeystorePassword());
                if (!(key instanceof PrivateKey)) {
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
    }



    PrivateKey loadPrivateKeyFromPem(String keyPath) throws KeyStoreException {
        try {
            String pem = Files.readString(Paths.get(keyPath));

            Pattern pattern = Pattern.compile("-----BEGIN (RSA |EC |)PRIVATE KEY-----((.|\\s)*)-----END (RSA |EC |)PRIVATE KEY-----");
            Matcher matcher = pattern.matcher(pem);

            String base64;
            if (matcher.find()) {
                base64 = matcher.group(2).replaceAll("\\s", "");
            } else {
                throw new KeyStoreException("Invalid private key format");
            }

            byte[] keyBytes = Base64.getMimeDecoder().decode(base64);

            // Standard ASN.1 algorithm identifier structure for prime256v1 (secp256r1)
            byte[] algId = new byte[] {
                    0x30, 0x13, // Sequence wrapper
                    0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01, // OID: EC Public Key
                    0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07 // OID: prime256v1
            };

            // Dynamically compute the ASN.1 lengths to prevent "Invalid lenByte"
            byte[] pkcs8Bytes = createPkcs8Structure(algId, keyBytes);

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
            PrivateKey key;
            for (String algo : List.of("RSA", "EC", "EdDSA")) {
                try {
                    key = KeyFactory.getInstance(algo).generatePrivate(spec);
                    logger.info("Loaded private key from PEM: {} (algorithm: {})", keyPath, algo);
                    return key;
                } catch (Exception ignored) {}
            }
            throw new KeyStoreException("Unsupported private key algorithm in " + keyPath);
        } catch (Exception e) {
            throw new KeyStoreException("Failed to load private key from " + keyPath, e);
        }
    }

    private static byte[] createPkcs8Structure(byte[] algId, byte[] privateKeyBytes) {
        // Wrapper Octet String for the private key
        byte[] octetStringHeader = encodeAsn1Length(0x04, privateKeyBytes.length);

        // Version integer: v0 (0x02, 0x01, 0x00)
        byte[] version = new byte[] { 0x02, 0x01, 0x00 };

        // Total content length calculation
        int totalContentLength = version.length + algId.length + octetStringHeader.length + privateKeyBytes.length;
        byte[] sequenceHeader = encodeAsn1Length(0x30, totalContentLength);

        // Stitch everything sequentially
        byte[] pkcs8 = new byte[sequenceHeader.length + totalContentLength];
        int pos = 0;

        System.arraycopy(sequenceHeader, 0, pkcs8, pos, sequenceHeader.length); pos += sequenceHeader.length;
        System.arraycopy(version, 0, pkcs8, pos, version.length); pos += version.length;
        System.arraycopy(algId, 0, pkcs8, pos, algId.length); pos += algId.length;
        System.arraycopy(octetStringHeader, 0, pkcs8, pos, octetStringHeader.length); pos += octetStringHeader.length;
        System.arraycopy(privateKeyBytes, 0, pkcs8, pos, privateKeyBytes.length);

        return pkcs8;
    }

    private static byte[] encodeAsn1Length(int tag, int length) {
        if (length < 128) {
            return new byte[] { (byte) tag, (byte) length };
        } else if (length < 256) {
            return new byte[] { (byte) tag, (byte) 0x81, (byte) length };
        } else {
            return new byte[] { (byte) tag, (byte) 0x82, (byte) (length >> 8), (byte) (length & 0xFF) };
        }
    }

    private X509Certificate[] loadCertificateChainFromPem(String certPath) throws KeyStoreException {
        try (FileInputStream fis = new FileInputStream(certPath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs = cf.generateCertificates(fis);
            if (certs.isEmpty()) {
                throw new KeyStoreException("No certificates found in " + certPath);
            }
            X509Certificate[] chain = certs.toArray(new X509Certificate[0]);
            logger.info("Loaded certificate chain from PEM: {} ({} certificates)", certPath, chain.length);
            return chain;
        } catch (Exception e) {
            throw new KeyStoreException("Failed to load certificate chain from " + certPath, e);
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
        assert info != null;
        Signature signature = Signature.getInstance(info.jcaAlgorithm);
        if (info.parameterSpec != null) {
            signature.setParameter(info.parameterSpec);
        }
        return signature;
    }

    public Short selectSignatureScheme(List<Short> clientSchemes) {
        String keyAlgorithm = privateKey.getAlgorithm(); // e.g., "RSA" or "EC"

        if (clientSchemes.contains((short) 0x807) && checkSchemeCompatible((short) 0x807, keyAlgorithm)) {
            return 0x807;
        }
        if (clientSchemes.contains((short) 0x403) && checkSchemeCompatible((short) 0x403, keyAlgorithm)) {
            return 0x403;
        }

        for (short scheme : clientSchemes) {
            if (checkSchemeCompatible(scheme, keyAlgorithm)) return scheme;
        }

        throw new IllegalStateException("No mutually supported signature schemes found between client and server.");
    }

    private static boolean checkSchemeCompatible(short scheme, String keyAlgorithm) {
        TlsSignatureMapping.JcaSchemeInfo info = TlsSignatureMapping.resolve(scheme);
        if (info == null) return false;

        // 1. Check if the scheme matches your loaded private key type
        if (keyAlgorithm.equalsIgnoreCase("RSA")) {
            if (!info.jcaAlgorithm.equals("RSASSA-PSS")) {
                return false;
            }
        } else if (keyAlgorithm.equalsIgnoreCase("EC")) {
            // Is it an ECDSA scheme?
            if (!info.jcaAlgorithm.contains("ECDSA")) return false;
        } else if (keyAlgorithm.equalsIgnoreCase("Ed25519") || keyAlgorithm.equalsIgnoreCase("EdDSA")) {
            if (!info.jcaAlgorithm.equalsIgnoreCase("Ed25519")) return false;
        } else {
            System.err.println("Unsupported scheme "+scheme+" and key algorithm: " + keyAlgorithm);
            return false;
        }

        // 2. Verify that your underlying Java Runtime actually supports this algorithm
        try {
            Signature.getInstance(info.jcaAlgorithm);
            // If it didn't throw an exception, this scheme is available and safe to use!
            return true;
        } catch (Exception e) {
            // Local Java security provider lacks this specific algorithm; try next
            System.err.println("Unsupported scheme "+scheme+" and key algorithm: " + keyAlgorithm + " "+ e.getMessage());
        }
        return false;
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

