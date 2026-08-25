ARG BASE_IMAGE=martenseemann/quic-network-simulator-endpoint:latest
ARG JAR_FILE=build/libs/quic-application-1.1-all.jar
ARG ENTRYPOINT_SCRIPT=/app/start.sh

# --- Stage 1: Temporary Workspace (Will be completely discarded) ---
FROM ubuntu:latest AS extractor
WORKDIR /tmp-extract

# Build argument for the JAR file path
ARG JAR_FILE

# Install unzip to pull the file out
RUN apt-get update && apt-get install -y unzip

# Copy your local jar file into this temporary block
COPY ${JAR_FILE} ./jquic.jar

# Extract ONLY the specific file you need
RUN unzip jquic.jar "loader" -d /tmp-extract/
RUN unzip jquic.jar "quic_router.bpf.o" -d /tmp-extract/

FROM bellsoft/liberica-openjre-alpine:25 AS java-vendor
FROM ${BASE_IMAGE}

ENV JAVA_HOME=/usr/lib/jvm/jre
ENV PATH="${JAVA_HOME}/bin:${PATH}"
COPY --from=java-vendor /usr/lib/jvm/jre $JAVA_HOME

LABEL authors="fmmalyshev"

# Install vsftpd (FTP server), and clean cache to keep the image slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    lsof \
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
RUN useradd -m -s /bin/bash fedoresko && \
    echo "fedoresko:colibri" | chpasswd

# Create a dedicated app directory
WORKDIR /app

# Copy your local Java application into the container image layer
ARG JAR_FILE
COPY ${JAR_FILE} /app/jquic.jar
COPY ./src/main/docker/quic.properties /app/quic.properties

#RUN cd /app & jar -xf jquic.jar loader quic_router.bpf.o
#RUN python3 -c "import zipfile; zipfile.ZipFile('/app/jquic.jar').extract('loader', '/app').extract('quic_router.bpf.o', '/app/')"
COPY --from=extractor /tmp-extract/loader /app/loader
COPY --from=extractor /tmp-extract/quic_router.bpf.o /app/quic_router.bpf.o

# Give fedoresko ownership of the app directory for FTP uploads
RUN chown -R fedoresko:fedoresko /app

# Explicitly document the container's open network ports
EXPOSE 8080 433 4433 21 20 30000-30010

# Create a startup script to run both vsftpd and your Java app concurrently
COPY ./src/main/docker/start.sh /app/start.sh
COPY ./src/main/docker/run_endpoint.sh /app/run_endpoint.sh
RUN chmod 755 /app/start.sh /app/run_endpoint.sh

ARG ENTRYPOINT_SCRIPT
ENV FINAL_ENTRYPOINT=$ENTRYPOINT_SCRIPT
ENTRYPOINT $FINAL_ENTRYPOINT