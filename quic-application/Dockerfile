# Use the official minimal Debian slim image
FROM azul/zulu-openjdk:25-latest AS java-vendor
FROM debian:stable-slim

ENV JAVA_HOME=/usr/lib/jvm/zulu25-ca
ENV PATH="${JAVA_HOME}/bin:${PATH}"
COPY --from=java-vendor /usr/lib/jvm/zulu25-ca-amd64 $JAVA_HOME

LABEL authors="fmmalyshev"

# Install vsftpd (FTP server), and clean cache to keep the image slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    lsof \
    vsftpd \
    curl \
    ca-certificates \
    libbpf1 \
    libelf1 \
    ethtool \
    strace \
    tcpdump \
    && mkdir -p /opt/async-profiler \
    && curl -L https://github.com/async-profiler/async-profiler/releases/download/v4.4/async-profiler-4.4-linux-x64.tar.gz | tar -xzf - --strip-components=1 -C /opt/async-profiler

USER root

# Add async-profiler binary launcher to path
ENV PATH="/opt/async-profiler/bin:${PATH}"

# Configure vsftpd for basic anonymous or local FTP access
COPY ./src/main/docker/vsftpd.conf /etc/vsftpd.conf
RUN mkdir -p /var/run/vsftpd/empty
RUN useradd -m -s /bin/bash fedoresko && \
    echo "fedoresko:colibri" | chpasswd

# Create a dedicated app directory
WORKDIR /app

# Copy your local Java application into the container image layer
COPY ./build/libs/quic-application-1.0-SNAPSHOT-all.jar /app/jquic.jar
COPY ./server.p12 /app/server.p12
COPY ./bmloadw /app/bmloadw

RUN cd /app & jar -xf jquic.jar loader quic_router.bpf.o

# Give fedoresko ownership of the app directory for FTP uploads
RUN chown -R fedoresko:fedoresko /app
RUN chown -R fedoresko:fedoresko /app/server.p12

# Explicitly document the container's open network ports
EXPOSE 8080 433 4433 21 20 30000-30010

# Create a startup script to run both vsftpd and your Java app concurrently
COPY --chmod=755 ./src/main/docker/start.sh /app/start.sh
COPY --chmod=755 ./src/main/docker/run_endpoint.sh /app/run_endpoint.sh

# Set the execution entry point
ENTRYPOINT ["/app/run_endpoint.sh"]