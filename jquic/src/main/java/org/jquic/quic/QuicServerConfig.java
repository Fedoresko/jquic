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
    private final String keystorePath;
    private final char[] keystorePassword;
    private final String keyAlias;

    /**
     * Creates server configuration with keystore settings.
     * 
     * @param keystorePath Path to PKCS12 keystore file
     * @param keystorePassword Password for the keystore
     * @param keyAlias Alias of the private key entry in the keystore
     */
    public QuicServerConfig(String keystorePath, String keystorePassword, String keyAlias) {
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword.toCharArray();
        this.keyAlias = keyAlias;
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

    /**
     * Creates a default configuration for testing.
     * Points to a local keystore with default credentials.
     */
    public static QuicServerConfig createDefault() {
        return new QuicServerConfig(
            "server.p12", 
            "changeit", 
            "server-alias"
        );
    }
}

