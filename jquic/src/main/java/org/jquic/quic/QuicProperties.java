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
import java.io.InputStream;
import java.util.Properties;

public class QuicProperties {
    private static final Logger logger = LoggerFactory.getLogger(QuicProperties.class);
    private static final Properties props = new Properties();

    static {
        loadProperties();
    }

    private static void loadProperties() {
        try (InputStream input = new FileInputStream("quic.properties")) {
            props.load(input);
            logger.info("Loaded properties from quic.properties");
        } catch (IOException ex) {
            logger.warn("Could not find or load quic.properties, using defaults");
        }
    }

    public static int getInt(String key, int defaultValue) {
        String value = System.getProperty(key);
        if (value == null) {
            value = props.getProperty(key);
        }
        if (value != null) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                logger.warn("Invalid value for {}: {}, using default {}", key, value, defaultValue);
            }
        }
        return defaultValue;
    }

    public static long getLong(String key, long defaultValue) {
        String value = System.getProperty(key);
        if (value == null) {
            value = props.getProperty(key);
        }
        if (value != null) {
            try {
                return Long.parseLong(value);
            } catch (NumberFormatException e) {
                logger.warn("Invalid value for {}: {}, using default {}", key, value, defaultValue);
            }
        }
        return defaultValue;
    }

    public static String getString(String key, String defaultValue) {
        String value = System.getProperty(key);
        if (value == null) {
            value = props.getProperty(key);
        }
        return value != null ? value : defaultValue;
    }

    // Constants
    public static final int PORT = getInt("quic.port", 4433);
    public static final int SELECTOR_COUNT = getInt("quic.selector_count", 4);
    public static final int WORKER_COUNT = getInt("quic.worker_count", 4);

    public static final int OUTBOUND_APP_QUEUE_SIZE = getInt("quic.outbound_app_queue_size", 1000);
    public static final int HANDSHAKE_QUEUE_CAP = getInt("quic.handshake_queue_cap", 1000);
    public static final int MAX_RECEIVE_BATCH = getInt("quic.max_receive_batch", 64);
    public static final int MAX_SEND_BATCH = getInt("quic.max_send_batch", 128);
    public static final long TIMEOUT_CHECK_INTERVAL_MS = getLong("quic.timeout_check_interval_ms", 1000);

    public static final long DEFAULT_IDLE_TIMEOUT_MS = getLong("quic.default_idle_timeout_ms", 30_000);

    // InitialStreamLimits
    public static final long INITIAL_MAX_BIDI = getInt("quic.initial_max_bidi", 128);
    public static final long INITIAL_MAX_UNI = getInt("quic.initial_max_uni", 128);
    public static final long INITIAL_MAX_STREAM_DATA_UNI = getInt("quic.initial_max_stream_data_uni", 1048576);
    public static final long INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = getInt("quic.initial_max_stream_data_bidi_local", 1048576);
    public static final long INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = getInt("quic.initial_max_stream_data_bidi_remote", 1048576);
    public static final long INITIAL_MAX_DATA = getInt("quic.initial_max_data", 1048576);
    public static final long CONNECTION_IDS_LIMIT = getLong("quic.connection_ids_limit", 3);

    // QuicServerConfig
    public static final String KEYSTORE_TYPE = getString("quic.keystore_type", "PKCS12");
    public static final String KEYSTORE_PATH = getString("quic.keystore_path", "server.p12");
    public static final String KEYSTORE_PASSWORD = getString("quic.keystore_password", "changeit");
    public static final String KEY_ALIAS = getString("quic.key_alias", "server-alias");

    public static final String CERT_PATH = getString("quic.cert_path", "server.crt");
    public static final String KEY_PATH = getString("quic.key_path", "server.key");

    // Bootstrap & Monitoring
    public static final int BOOTSTRAP_PORT = getInt("quic.bootstrap.port", 443);
    public static final String MONITORING_BASE_DIR = getString("quic.monitoring.base_dir", "/home/fedoresko");

    public static final boolean PREFER_V2 = Boolean.parseBoolean(getString("quic.prefer_v2", "false"));

    public static final int DEFENCE_COOLDOWN = getInt("quic.defence.cooldown_ms", 30000);
    public static final int RETRY_TOKEN_EXPIRATION = getInt("quic.defence.retry_token_expiration_ms", 3000);
    public static final boolean START_IN_DEFENCE = Boolean.parseBoolean(getString("quic.defence.start_on", "false"));

    public static boolean ENABLE_SESSION_RESUMPTION = Boolean.parseBoolean(getString("quic.enable_session_resumption", "true"));

    public static final String SSLKEYLOGFILE = getString("SSLKEYLOGFILE", getString("quic.ssl_keylog", System.getenv("SSLKEYLOGFILE")));
}
