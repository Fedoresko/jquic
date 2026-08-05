#!/bin/bash
if [ -f /setup.sh ]; then
      /setup.sh
else
    echo "Warning: /setup.sh not found. Network routing might fail."
fi

echo "Starting compiled BPF C program with root privileges..."
chmod +x /app/loader
strace -e bpf /app/loader &
mkdir /logs
tcpdump -i any -w /logs/capture.pcap -U &

# Give tcpdump half a second to initialize its hook into the kernel
sleep 0.5

case "$TESTCASE" in
    "handshake"|"transfer"|"multistream"|"multiple_connections"|"retry"|"chacha20"|"key_update")
        echo "Valid testcase matched: $TESTCASE. Proceeding to boot..."
        ;;
    *)
        echo "COMPLIANCE CHECK: Caught unknown slug [$TESTCASE]. Exiting with 127."
        exit 127
        ;;
esac

export SSLKEYLOGFILE=/logs/keys.log

cd /app
# Start the Java application in the background and capture its PID
exec ${JAVA_HOME}/bin/java -Djava.net.preferIPv4Stack=true\
   --add-opens java.base/sun.nio.ch=ALL-UNNAMED --add-opens java.base/java.io=ALL-UNNAMED --enable-native-access=ALL-UNNAMED -Dlog.level=DEGUG\
   -Dquic.port=443 -Dquic.keystore_type=PEM -Dquic.cert_path=/certs/cert.pem -Dquic.key_path=/certs/priv.key -jar jquic.jar