#define _GNU_SOURCE

#include <jni.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

JNIEXPORT jobject JNICALL Java_org_fmalyshev_quic_LinuxEcnSocket_nativeReceive(
    JNIEnv *env, jclass clazz, jint fd, jobject dst, jint position, jint limit, jintArray out_metrics) {

    void *buf_address = NULL;
    jbyteArray heap_array = NULL;
    jbyte *native_heap_ptr = NULL;
    int max_len = limit - position;

    // 1. Resolve buffer type (Direct vs Heap ByteBuffer alignment)
    buf_address = (*env)->GetDirectBufferAddress(env, dst);
    if (buf_address != NULL) {
        // Direct ByteBuffer (Zero-copy optimization pathway)
        buf_address = (char *)buf_address + position;
    } else {
        // Heap ByteBuffer fallback path: fetch underlying byte[] array matching object reference
        jclass buf_class = (*env)->GetObjectClass(env, dst);
        jmethodID array_method = (*env)->GetMethodID(env, buf_class, "array", "()[B");
        if (!array_method) return NULL;

        heap_array = (jbyteArray)(*env)->CallObjectMethod(env, dst, array_method);
        if (!heap_array) return NULL;

        native_heap_ptr = (*env)->GetByteArrayElements(env, heap_array, NULL);
        buf_address = native_heap_ptr + position;
    }

    // 2. Set up native scatter/gather network elements
    struct iovec iov = { .iov_base = buf_address, .iov_len = max_len };
    char cmsg_buf[CMSG_SPACE(sizeof(int))];

    // Address storage structures to hold peer socket parameters
    struct sockaddr_storage peer_addr;

    struct msghdr msg = {
        .msg_name = &peer_addr,
        .msg_namelen = sizeof(peer_addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf)
    };

    // 3. Perform the explicit native system read operation
    ssize_t bytes_read = recvmsg(fd, &msg, 0);

    // Clean up heap array locks right after syscall completion if active
    if (native_heap_ptr) {
        (*env)->ReleaseByteArrayElements(env, heap_array, native_heap_ptr, 0);
    }

    // Handle non-blocking socket checks (EAGAIN / EWOULDBLOCK)
    if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return NULL;
        }
        // Throw an explicit Java IOException back to the application layer runtime
        jclass io_exception_clazz = (*env)->FindClass(env, "java/io/IOException");
        (*env)->ThrowNew(env, io_exception_clazz, strerror(errno));
        return NULL;
    }

    // 4. Isolate Explicit Congestion Notification data parameters
    int ecn_flags = 0;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) {
            unsigned char tos = *(unsigned char *)CMSG_DATA(cmsg);
            unsigned char ecn_bits = tos & 0x03; // Isolate lower 2 bits

            if (ecn_bits == 3) {       // Binary 11
                ecn_flags |= (1 << 0); // Set Bit 0 for CE
            } else if (ecn_bits == 1) { // Binary 01
                ecn_flags |= (1 << 1); // Set Bit 1 for ECT(1)
            } else if (ecn_bits == 2) { // Binary 10
                ecn_flags |= (1 << 2); // Set Bit 2 for ECT(0)
            }
            break;
        }
    }

    // 5. Pack: Shift bytes_read left by 6 bits, then merge the 3 ecn_flags bits
    jint packed_metric = ((jint)bytes_read << 6) | (ecn_flags & 0x3F);
    (*env)->SetIntArrayRegion(env, out_metrics, 0, 1, &packed_metric);

    // 6. Build the matching Java InetSocketAddress object mapping natively
    jobject ip_address_obj = NULL;
    int port = 0;

    if (peer_addr.ss_family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&peer_addr;
        port = ntohs(addr4->sin_port);

        jbyteArray ip_bytes = (*env)->NewByteArray(env, 4);
        (*env)->SetByteArrayRegion(env, ip_bytes, 0, 4, (jbyte *)&addr4->sin_addr.s_addr);

        jclass inet_address_clazz = (*env)->FindClass(env, "java/net/InetAddress");
        jmethodID get_by_address = (*env)->GetStaticMethodID(env, inet_address_clazz, "getByAddress", "([B)Ljava/net/InetAddress;");
        ip_address_obj = (*env)->CallStaticObjectMethod(env, inet_address_clazz, get_by_address, ip_bytes);
    }
    else if (peer_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&peer_addr;
        port = ntohs(addr6->sin6_port);

        jbyteArray ip_bytes = (*env)->NewByteArray(env, 16);
        (*env)->SetByteArrayRegion(env, ip_bytes, 0, 16, (jbyte *)&addr6->sin6_addr.s6_addr);

        jclass inet_address_clazz = (*env)->FindClass(env, "java/net/InetAddress");
        jmethodID get_by_address = (*env)->GetStaticMethodID(env, inet_address_clazz, "getByAddress", "([B)Ljava/net/InetAddress;");
        ip_address_obj = (*env)->CallStaticObjectMethod(env, inet_address_clazz, get_by_address, ip_bytes);
    }

    // Instantiate and return the matching Java InetSocketAddress instance
    jclass inet_sock_addr_clazz = (*env)->FindClass(env, "java/net/InetSocketAddress");
        jmethodID isa_constructor = (*env)->GetMethodID(env, inet_sock_addr_clazz, "<init>", "(Ljava/net/InetAddress;I)V");

    return (*env)->NewObject(env, inet_sock_addr_clazz, isa_constructor, ip_address_obj, port);
}