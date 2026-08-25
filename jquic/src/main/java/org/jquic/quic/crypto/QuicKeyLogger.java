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

import org.jquic.quic.QuicProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HexFormat;

/**
 * Utility to log QUIC secrets to a file in the SSLKEYLOGFILE format.
 * As described in RFC 9001 and draft-ietf-tls-keylog.
 */
public class QuicKeyLogger {
    private static final Logger logger = LoggerFactory.getLogger(QuicKeyLogger.class);
    private static final String logFile = QuicProperties.SSLKEYLOGFILE;
    private static final HexFormat hex = HexFormat.of();

    /**
     * Logs a secret to the SSLKEYLOGFILE if the property is set.
     *
     * @param label        The secret label (e.g., "CLIENT_HANDSHAKE_TRAFFIC_SECRET")
     * @param clientRandom The 32-byte client random
     * @param secret       The secret bytes
     */
    public static void log(String label, byte[] clientRandom, byte[] secret) {
        if (logFile == null || logFile.isEmpty()) {
            return;
        }

        File file = new File(logFile);
        if (!file.exists()) {
            try {
                //noinspection ResultOfMethodCallIgnored
                file.createNewFile();
            } catch (IOException e) {
                return;
            }
        }

        if (clientRandom == null || secret == null) {
            return;
        }

        String line = label + " " + hex.formatHex(clientRandom) + " " + hex.formatHex(secret);
        
        synchronized (QuicKeyLogger.class) {
            try (PrintWriter writer = new PrintWriter(new FileWriter(logFile, true))) {
                writer.println(line);
                writer.flush();
            } catch (IOException e) {
                logger.error("Failed to write to SSLKEYLOGFILE: {}", logFile, e);
            }
        }
    }
}
