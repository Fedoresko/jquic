package org.fmalyshev.quic;

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
