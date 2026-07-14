# Use the official minimal Debian slim image
FROM azul/zulu-openjdk:22-latest AS java-vendor
FROM debian:stable-slim

ENV JAVA_HOME=/usr/lib/jvm/zulu22-ca
ENV PATH="${JAVA_HOME}/bin:${PATH}"
COPY --from=java-vendor /usr/lib/jvm/zulu22-ca-amd64 $JAVA_HOME

LABEL authors="fmmalyshev"

# Install vsftpd (FTP server), and clean cache to keep the image slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    lsof \
    vsftpd \
    curl \
    ca-certificates \
    gcc \
    llvm \
    clang \
    libc-dev \
    libbpf-dev \
    libelf-dev \
    ethtool \
    strace \
    && mkdir -p /opt/async-profiler \
    && curl -L https://github.com/async-profiler/async-profiler/releases/download/v4.4/async-profiler-4.4-linux-x64.tar.gz | tar -xzf - --strip-components=1 -C /opt/async-profiler

# Add async-profiler binary launcher to path
ENV PATH="/opt/async-profiler/bin:${PATH}"

# Configure vsftpd for basic anonymous or local FTP access
RUN mkdir -p /var/run/vsftpd/empty && \
    echo "listen=YES" > /etc/vsftpd.conf && \
    echo "anonymous_enable=NO" >> /etc/vsftpd.conf && \
    echo "local_enable=YES" >> /etc/vsftpd.conf && \
    echo "write_enable=YES" >> /etc/vsftpd.conf && \
    echo "local_umask=022" >> /etc/vsftpd.conf && \
    echo "chroot_local_user=YES" >> /etc/vsftpd.conf && \
    echo "allow_writeable_chroot=YES" >> /etc/vsftpd.conf && \
    echo "seccomp_sandbox=NO" >> /etc/vsftpd.conf && \
    echo "pasv_enable=YES" >> /etc/vsftpd.conf && \
    echo "pasv_address=127.0.0.1" >> /etc/vsftpd.conf && \
    echo "pasv_min_port=30000" >> /etc/vsftpd.conf && \
    echo "pasv_max_port=30000" >> /etc/vsftpd.conf

RUN useradd -m -s /bin/bash fedoresko && \
    echo "fedoresko:colibri" | chpasswd

# Create a dedicated app directory
WORKDIR /app

# Copy your local Java application into the container image layer
COPY build/libs/jquic-1.0-SNAPSHOT-all.jar /app/jquic.jar
COPY server.p12 /app/server.p12
COPY src/main/c/ /app/

RUN gcc -O2 /app/loader.c -o /app/loader -lbpf -lelf && \
    clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c quic_router.bpf.c -o quic_router.bpf.o

RUN  gcc -shared -fPIC \
    -I"${JAVA_HOME}/include" \
    -I"${JAVA_HOME}/include/linux" \
    javabpf.c -lbpf \
    -o libjavabpf.so

RUN  gcc -shared -fPIC \
    -I"${JAVA_HOME}/include" \
    -I"${JAVA_HOME}/include/linux" \
    quic_ecn.c -lbpf \
    -o libquic_ecn.so

RUN mkdir -p /usr/java/packages/lib && \
    cp libjavabpf.so /usr/java/packages/lib && \
    cp libquic_ecn.so /usr/java/packages/lib

# Give fedoresko ownership of the app directory for FTP uploads
RUN chown -R fedoresko:fedoresko /app
RUN chown -R fedoresko:fedoresko /app/server.p12


# Explicitly document the container's open network ports
EXPOSE 8080 433 4433 21 20 30000-30010

# Create a startup script to run both vsftpd and your Java app concurrently
RUN echo '#!/bin/sh\n\
service vsftpd start\n\
\n\
ulimit -l unlimited\n\
\n\
echo "Starting compiled BPF C program with root privileges..."\n\
strace -e bpf /app/loader &&\n\
\n\
# Start the Java application in the background and capture its PID\n\
su - fedoresko -c "cd /app && ${JAVA_HOME}/bin/java -XX:+UnlockDiagnosticVMOptions -XX:+DebugNonSafepoints -Djava.net.preferIPv4Stack=true\
   --add-opens java.base/sun.nio.ch=ALL-UNNAMED --add-opens java.base/java.io=ALL-UNNAMED -Dlog.level=WARN\
   -agentpath:/opt/async-profiler/lib/libasyncProfiler.so=start,event=cpu,alloc=2m,loop=1m,file=/home/fedoresko/profile-%t.jfr\
   -jar jquic.jar" &\n\
JAVA_PID=$!\n\
\n\
# Launch the looping profiler script as a parallel background task\n\
echo "Waiting 5 seconds for Java app to warm up..."\n\
sleep 5\n\
\n\
# Loop infinitely as long as the Java process remains active\n\
while (true) do\n\
  sleep 5\n\
  find /home/fedoresko -type f -name "*.jfr" -printf "%T@ %p\n" | \
                                                sort -rn | \
                                                awk '\''{sub(/^[^ ]+ /, ""); print}'\'' | \
                                                tail -n +2 | while read -r FILE; do\n\
      echo "Processing: $FILE"\n\
      BASE_NAME="${FILE%.*}"\n\
      OUTPUT_FILE="${BASE_NAME}.html"\n\
      /opt/async-profiler/bin/jfrconv -o heatmap "$FILE" "$OUTPUT_FILE"\n\
      if [ $? -eq 0 ]; then\n\
          echo "Success. Deleting original file..."\n\
          rm "$FILE"\n\
      else\n\
          echo "Error: Conversion failed for $FILE. Keeping original file."\n\
      fi\n\
  done\n\
done\n\
\n\
# Keep the Docker container running by tying it to the main Java process\n\
wait $JAVA_PID' > /app/start.sh && \
    chmod +x /app/start.sh

# Set the execution entry point
ENTRYPOINT ["/app/start.sh"]