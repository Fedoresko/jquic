#!/bin/bash
#
# Copyright 2026 Fedor Malyshev
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#/
if [ -f /setup.sh ]; then
      /setup.sh
else
    echo "Warning: /setup.sh not found. Network routing might fail."
fi

case "$TESTCASE" in
    "handshake"|"transfer"|"multistream"|"multiple_connections"|"retry"|"chacha20"|"http3"|"multiplexing"|"ecn"|"longrtt"|"resumption"|"zerortt"|"blackhole"|"keyupdate"|"amplificationlimit"|"handshakeloss"|"transferloss"|"handshakecorruption"|"transfercorruption"|"ipv6"|"v2"|"rebind-port"|"rebind-addr"|"connectionmigration")
        echo "Valid testcase matched: $TESTCASE. Proceeding to boot..."
        ;;
    *)
        echo "COMPLIANCE CHECK: Caught unknown slug [$TESTCASE]. Exiting with 127."
        exit 127
        ;;
esac

echo "Starting compiled BPF C program with root privileges..."
chmod +x /app/loader
/app/loader
mkdir -p /logs
chmod 777 /logs
tcpdump -i any -w /logs/capture.pcap -U &

# Give tcpdump half a second to initialize its hook into the kernel
sleep 0.5

export SSLKEYLOGFILE=/logs/keys.log

cd /app
# Start the Java application in the background and capture its PID
QUIC_V2_PREFERENCE="false"
if [ "$TESTCASE" == "v2" ]; then
    QUIC_V2_PREFERENCE="true"
fi

QUIC_DEFENCE_DEFAULT="false"
if [ "$TESTCASE" == "retry" ]; then
  QUIC_DEFENCE_DEFAULT="true"
fi

exec ${JAVA_HOME}/bin/java -Djava.net.preferIPv4Stack=false\
   --add-opens java.base/sun.nio.ch=ALL-UNNAMED --add-opens java.base/java.io=ALL-UNNAMED --enable-native-access=ALL-UNNAMED\
   -Dlog.level=INFO -DJQUIC_LOG_FILE=/logs/jquic.log\
   -Dquic.prefer_v2=$QUIC_V2_PREFERENCE -Dquic.defence.start_on=$QUIC_DEFENCE_DEFAULT -Dquic.port=443 -Dquic.keystore_type=PEM\
   -Dquic.cert_path=/certs/cert.pem -Dquic.key_path=/certs/priv.key -jar jquic.jar