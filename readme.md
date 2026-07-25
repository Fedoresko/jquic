<img src="jquic.svg" align="left" width="200" alt="jQuic" style="margin: 20px; margin-right: 60px">

# jQuic: High-Performance Java QUIC Server

**jQuic** is a high-performance Java library for serving incoming QUIC connections and shaping traffic. It is designed for front-facing application servers that require low latency and high throughput.

### Key Features

*   **Full QUIC & HTTP/3 Support**: Complete implementation of the QUIC transport protocol and HTTP/3 application protocol.
*   **High-Performance Architecture**:
    *   **Multi-threaded Engine**: Decoupled selector and worker threads for maximum throughput.
    *   **Consistent Hashing**: Connection IDs are mapped to specific worker threads using consistent hashing, minimizing synchronization overhead.
    *   **Zero-Copy Handover**: Efficient data transfer between network threads and application workers using SPSC queues.
*   **Advanced Congestion Control**:
    *   **BBRv3**: Google's latest model-based congestion control for high throughput and low latency.
    *   **TCP Prague**: Designed for L4S (Low Latency, Low Loss, Scalable throughput) using ECN.
    *   **Copa**: Delay-based congestion control for practical internet use.
    *   **TCP Cubic**: RFC 8312 compliant standard congestion control.
    *   **Whatever you want**: jQuic delegates congestion control to the application level leaving space for streamId based packet prioritization or any other strategies.
*   **Linux-Specific Optimizations**:
    *   **eBPF Routing**: Native eBPF-based socket routing for efficient multi-socket packet distribution.
    *   **Native ECN (Explicit Congestion Notification)**: Direct support for ECN bits via native C integration for L4S compatibility.
    *   **SO_REUSEPORT Support**: Efficient load balancing across multiple listener sockets.
*   **Secure by Design**:
    *   Built-in TLS 1.3 support.
    *   Integrated Keystore management for easy certificate handling.
*   **Bootstrap Server**: Includes a lightweight HTTP/1.1 bootstrap server for service discovery and QUIC/HTTP3 upgrade signaling.

### Project Structure

*   `jquic/`: Core QUIC transport protocol implementation.
*   `http3/`: HTTP/3 protocol implementation.
*   `quic-application/`: Example application and bootstrapping logic.

### Getting Started

The project uses Gradle for builds. To compile the project:

```bash
gradle classes
```

For Linux environments, native components (eBPF and ECN) are pre-compiled and located in `jquic/src/main/resources/`.

