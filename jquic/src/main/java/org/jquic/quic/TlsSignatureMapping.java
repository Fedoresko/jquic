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

import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class TlsSignatureMapping {

    public static class JcaSchemeInfo {
        public final String jcaAlgorithm;
        public final PSSParameterSpec parameterSpec; // Null unless RSA-PSS

        public JcaSchemeInfo(String jcaAlgorithm, PSSParameterSpec parameterSpec) {
            this.jcaAlgorithm = jcaAlgorithm;
            this.parameterSpec = parameterSpec;
        }
    }

    public static JcaSchemeInfo resolve(short signatureScheme) {
        switch (signatureScheme) {
            // ECDSA Schemes
            case (short) 0x0403: // ecdsa_secp256r1_sha256
                return new JcaSchemeInfo("SHA256withECDSA", null);
            case (short) 0x0503: // ecdsa_secp384r1_sha384
                return new JcaSchemeInfo("SHA384withECDSA", null);
            case (short) 0x0603: // ecdsa_secp521r1_sha512
                return new JcaSchemeInfo("SHA512withECDSA", null);

            // EdDSA Schemes
            case (short) 0x0807: // ed25519
                return new JcaSchemeInfo("Ed25519", null);

            // RSA-PSS Schemes (Requires Parameter Specs)
            case (short) 0x0804: // rsa_pss_rsae_sha256
                return new JcaSchemeInfo("RSASSA-PSS", createPssSpec("SHA-256", 32));
            case (short) 0x0805: // rsa_pss_rsae_sha384
                return new JcaSchemeInfo("RSASSA-PSS", createPssSpec("SHA-384", 48));
            case (short) 0x0806: // rsa_pss_rsae_sha512
                return new JcaSchemeInfo("RSASSA-PSS", createPssSpec("SHA-512", 64));

            // Legacy RSA PKCS#1 v1.5 (Supported in TLS 1.3 only for reverse compatibility)
            case (short) 0x0101: // rsa_pkcs1_sha256
                return new JcaSchemeInfo("SHA256withRSA", null);

            default:
                return null; // Unsupported or unknown algorithm
        }
    }

    private static PSSParameterSpec createPssSpec(String digestAlgo, int saltLen) {
        // TLS 1.3 explicitly dictates: Salt Length MUST equal the Hash Output Length
        return new PSSParameterSpec(
                digestAlgo,
                "MGF1",
                new MGF1ParameterSpec(digestAlgo),
                saltLen,
                1
        );
    }
}
