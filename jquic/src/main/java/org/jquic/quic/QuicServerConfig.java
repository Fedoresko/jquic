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

/**
 * Configuration for QUIC server, including TLS keystore settings.
 */
public class QuicServerConfig {
    private final String keystoreType;
    private final String keystorePath;
    private final char[] keystorePassword;
    private final String keyAlias;
    private final String certPath;
    private final String keyPath;

    /**
     * Creates server configuration with keystore settings.
     * 
     * @param keystoreType Type of keystore ("PKCS12" or "PEM")
     * @param keystorePath Path to PKCS12 keystore file
     * @param keystorePassword Password for the keystore
     * @param keyAlias Alias of the private key entry in the keystore
     * @param certPath Path to certificate file (.crt)
     * @param keyPath Path to private key file (.key)
     */
    public QuicServerConfig(String keystoreType, String keystorePath, String keystorePassword, String keyAlias, String certPath, String keyPath) {
        this.keystoreType = keystoreType;
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword != null ? keystorePassword.toCharArray() : null;
        this.keyAlias = keyAlias;
        this.certPath = certPath;
        this.keyPath = keyPath;
    }

    public String getKeystoreType() {
        return keystoreType;
    }

    public String getKeystorePath() {
        return keystorePath;
    }

    public char[] getKeystorePassword() {
        return keystorePassword;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public String getCertPath() {
        return certPath;
    }

    public String getKeyPath() {
        return keyPath;
    }

    /**
     * Creates a default configuration.
     * Values are loaded from QuicProperties.
     */
    public static QuicServerConfig createDefault() {
        return new QuicServerConfig(
            QuicProperties.KEYSTORE_TYPE,
            QuicProperties.KEYSTORE_PATH,
            QuicProperties.KEYSTORE_PASSWORD,
            QuicProperties.KEY_ALIAS,
            QuicProperties.CERT_PATH,
            QuicProperties.KEY_PATH
        );
    }
}

