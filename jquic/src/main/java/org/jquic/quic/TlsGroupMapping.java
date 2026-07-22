package org.jquic.quic;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.List;
import java.util.Set;

public class TlsGroupMapping {

    public static class JcaGroupInfo {
        public final String keyPairGeneratorAlgorithm; // "EC", "XDH", or "DH"
        public final AlgorithmParameterSpec parameterSpec;
        public final String standardName;

        public JcaGroupInfo(String algo, AlgorithmParameterSpec spec, String name) {
            this.keyPairGeneratorAlgorithm = algo;
            this.parameterSpec = spec;
            this.standardName = name;
        }
    }

    /**
     * Maps a 2-byte TLS 1.3 Supported Group ID to Java specifications.
     * Refs: RFC 8446 Section 4.2.7
     */
    public static JcaGroupInfo resolve(short groupId) {
        switch (groupId) {
            // --- Elliptic Curve Groups (XDH - Modern) ---
            case (short) 0x001D: // x25519
                return new JcaGroupInfo("XDH", NamedParameterSpec.X25519, "X25519");
            case (short) 0x001E: // x448
                return new JcaGroupInfo("XDH", NamedParameterSpec.X448, "X448");

            // --- Elliptic Curve Groups (Traditional SECP) ---
            case (short) 0x0017: // secp256r1 (NIST P-256)
                return new JcaGroupInfo("EC", new ECGenParameterSpec("secp256r1"), "secp256r1");
            case (short) 0x0018: // secp384r1 (NIST P-384)
                return new JcaGroupInfo("EC", new ECGenParameterSpec("secp384r1"), "secp384r1");
            case (short) 0x0019: // secp521r1 (NIST P-521)
                return new JcaGroupInfo("EC", new ECGenParameterSpec("secp521r1"), "secp521r1");

            // --- Brainpool Curves (Optional in TLS 1.3, supported in newer JVMs) ---
            case (short) 0x001A: // brainpoolP256r1tls
                return new JcaGroupInfo("EC", new ECGenParameterSpec("brainpoolP256r1"), "brainpoolP256r1");

            default:
                // Group is either legacy TLS 1.2 FFDHE (0x0100+) or unrecognized
                return null;
        }
    }


    public static class SelectionResult {
        public final short chosenGroupId;
        public final boolean requiresHelloRetryRequest;

        public SelectionResult(short chosenGroupId, boolean requiresHelloRetryRequest) {
            this.chosenGroupId = chosenGroupId;
            this.requiresHelloRetryRequest = requiresHelloRetryRequest;
        }
    }

    // Define your server's ordered preference of cryptographic groups
    // Here we prefer X25519 (0x001D) over secp256r1 (0x0017)
    private static final List<Short> SERVER_PREFERRED_GROUPS = List.of(
            (short) 0x001D, // X25519
            (short) 0x0017  // secp256r1
    );

    /**
     * Selects the best mutual group based on RFC 8446 priority logic.
     *
     * @param clientGroups Ordered list of groups from client's supported_groups extension
     * @param clientKeyShares List of groups the client actually provided public keys for
     * @return SelectionResult mapping the group ID and state tracking parameters
     */
    public static SelectionResult selectGroup(List<Short> clientGroups, Set<Short> clientKeyShares) {

        // PASS 1: Look for the highest client priority group that HAS a matching key share
        for (short clientGroup : clientGroups) {
            if (SERVER_PREFERRED_GROUPS.contains(clientGroup) && clientKeyShares.contains(clientGroup)) {
                // Verify local JVM runtime capabilities before solidifying selection
                if (isGroupSupportedByJvm(clientGroup)) {
                    return new SelectionResult(clientGroup, false); // Instant Match!
                }
            }
        }

        // PASS 2: Fallback. No pre-sent key share matched. Find the first mutual group we support.
        // This will force our state engine to issue an explicit HelloRetryRequest frame.
        for (short clientGroup : clientGroups) {
            if (SERVER_PREFERRED_GROUPS.contains(clientGroup)) {
                if (isGroupSupportedByJvm(clientGroup)) {
                    return new SelectionResult(clientGroup, true); // Requires HRR
                }
            }
        }

        // PASS 3: No overlap exists anywhere. Handshake must terminate.
        return null;
    }

    private static boolean isGroupSupportedByJvm(short groupId) {
        TlsGroupMapping.JcaGroupInfo info = TlsGroupMapping.resolve(groupId);
        if (info == null) return false;

        try {
            // Check if local security provider can instantiate the key generator
            java.security.KeyPairGenerator.getInstance(info.keyPairGeneratorAlgorithm);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}