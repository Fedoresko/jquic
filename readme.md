<img src="jquic.svg" width="200" alt="jQuic" style="float: left; margin: 20px; margin-right: 60px">

# jQuic: High-Performance Java QUIC & HTTP/3 Server

**jQuic** is a high-performance Java library for serving incoming QUIC connections and shaping traffic. It is designed for front-facing application servers that require low latency and high throughput.

### Compliance Status

*   **QUIC**: Fully compliant with the [QUIC standard](https://datatracker.ietf.org/doc/html/rfc9000) (RFC 9000).
*   **HTTP/3**: Core functionality implementation including [QPACK](https://datatracker.ietf.org/doc/html/rfc9204) (RFC 9204).

### Key Features

*   **High-Performance Architecture**:
    *   **Multi-threaded Engine**: Decoupled selector and worker threads for maximum throughput.
    *   **Virtual Threads**: Leverages Java's virtual threads for scalable request handling.
    *   **Consistent Hashing**: Connection IDs are mapped to specific worker threads using consistent hashing, minimizing synchronization overhead.
    *   **Zero-Copy Handover**: Efficient data transfer between network threads and application workers using SPSC queues.
    *   **Batch I/O**: Optimized datagram handling using system-level batch I/O operations.
*   **Advanced Congestion Control**:
    *   **BBRv3**: Google's latest model-based congestion control algorithms.
    *   **TCP Prague**: Designed for L4S (Low Latency, Low Loss, Scalable throughput) using ECN.
    *   **Copa**: Delay-based congestion control for practical internet use.
    *   **TCP Cubic**: RFC 8312 compliant standard congestion control.
    *   **Customizable**: jQuic delegates congestion control to the application level, allowing for stream-based packet prioritization or custom strategies.
*   **Linux-Specific Optimizations**:
    *   **eBPF Routing**: Native eBPF-based socket routing for efficient multi-socket packet distribution.
    *   **Native ECN (Explicit Congestion Notification)**: Direct support for ECN bits via native C integration for L4S compatibility.
    *   **SO_REUSEPORT Support**: Efficient load balancing across multiple listener sockets.
*   **Secure & Robust**:
    *   **TLS 1.3**: Built-in support via BoringSSL, including ChaCha20 cipher suites.
    *   **Session Resumption & 0-RTT**: Support for faster connection establishment.
    *   **Anti-Amplification & DOS Protection**: Implementation of amplification limits and a specialized "Defence Mode" with Retry packets.
    *   **Path Validation**: Active path validation using PATH_CHALLENGE/PATH_RESPONSE.
    *   **Version Negotiation**: Full support for compatible version negotiation.
    *   **Integrated Keystore**: Easy certificate management.
*   **Bootstrap Server**: Includes a lightweight HTTP/1.1 bootstrap server for service discovery and QUIC/HTTP3 upgrade signaling.

### Project Structure

The repository is organized into four modules:

*   `jquic`: The main module containing the core QUIC transport protocol implementation.
*   `http3`: HTTP/3 protocol implementation (depends on `jquic`).
*   `hq-interop`: Implementation of the `hq` (HTTP/0.9) protocol used for interoperability testing and examples.
*   `quic-application`: A full-service example that also serves as a `quic-interop-runner` image.

### Usage and Examples

#### Maven Dependencies

To use jQuic in your project, add the following dependencies to your `pom.xml`:

```xml
<dependency>
    <groupId>org.jquic</groupId>
    <artifactId>jquic</artifactId>
    <version>1.1.0</version>
</dependency>
<dependency>
    <groupId>org.jquic</groupId>
    <artifactId>http3</artifactId>
    <version>1.1.0</version>
</dependency>
```

#### Stream API Example

You can implement custom application protocols by implementing `QuicApplicationProtocol` and `QuicApplicationProtocolConnectionHandler`.

```java
public class MyProtocol implements QuicApplicationProtocol {
    @Override
    public String getProtocolName() {
        return "my-protocol/1.0";
    }

    @Override
    public Function<Long, QuicApplicationProtocolConnectionHandler> getConnectionHandler() {
        return connectionId -> new MyHandler();
    }
    
    // ... other methods ...
}

public class MyHandler implements QuicApplicationProtocolConnectionHandler {
    @Override
    public void onStreamDataReceived(long streamId, QuicConnectionControl control, 
                                   byte[] data, boolean isLastData, 
                                   Long errorCode, boolean isEarlyData) {
        System.out.println("Received " + data.length + " bytes on stream " + streamId);
        // Echo data back
        try (DataOutputStream out = control.openStream(streamId)) {
            out.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

#### Starting the Engine

```java
// Initialize the QUIC engine
QuicEngine.init();

// Register your protocol
QuicEngine.getStreamEngine().registerProtocol(new MyProtocol());
```

### Getting Started

The project uses Gradle for builds. To compile the project:

```bash
gradle build
```

For Linux environments, native components (eBPF and ECN) are pre-compiled and located in `jquic/src/main/resources/`.

### Licensing

This project is licensed under the Apache License 2.0. See the `jquic/LICENSE` file for details.

#### Third-Party Licenses

This project includes BoringSSL binaries (libcrypto.dll, libcrypto.so), which are subject to the ISC, OpenSSL, and SSLeay licenses. See `jquic/LICENSE-BORINGSSL` and `jquic/NOTICE` for more information.

