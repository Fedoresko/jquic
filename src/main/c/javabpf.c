#define _GNU_SOURCE

#include <jni.h>
#include <errno.h>
#include <sched.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

static int my_libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static int getMapFd(JNIEnv *env, jstring map_path) {
    const char *path = (*env)->GetStringUTFChars(env, map_path, NULL);

    // 1. Open the pinned map via its global path string
    int map_fd = bpf_obj_get(path);

    fflush(stdout);

    (*env)->ReleaseStringUTFChars(env, map_path, path);

    return map_fd;
}

JNIEXPORT jint JNICALL Java_org_fmalyshev_quic_BpfRouting_setAffinity(JNIEnv* env, jclass cls, jint pid, jlongArray mask) {
    cpu_set_t set;
    CPU_ZERO(&set);

    jsize mask_len = (*env)->GetArrayLength(env, mask);
    if (mask_len > sizeof(set) / sizeof(jlong)) {
        mask_len = sizeof(set) / sizeof(jlong);
    }

    (*env)->GetLongArrayRegion(env, mask, 0, mask_len, (jlong*)&set);

    return sched_setaffinity((pid_t)pid, sizeof(set), &set) == 0 ? 0 : errno;
}

JNIEXPORT jint JNICALL Java_org_fmalyshev_quic_BpfRouting_attachEBpfToSocket(
    JNIEnv *env, jclass clazz, jstring prog_path, jint socket_fd) {

    libbpf_set_print(my_libbpf_print_fn);

    int prog_fd = getMapFd(env, prog_path);

    // Pass the eBPF program descriptor straight to the Linux kernel socket level
    int result = setsockopt(socket_fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd));

    fflush(stdout);

    return (jint)result; // Returns 0 on success, or -1 on failure
}

JNIEXPORT jint JNICALL Java_org_fmalyshev_quic_BpfRouting_nativeUpdateBpfMapI(
    JNIEnv *env, jclass clazz, jstring map_path, jint key, jint socket_fd) {

    int map_fd = getMapFd(env, map_path);
    // 2. Execute the update directly from the Java process thread context
    // The kernel reads socket_fd relative to Java's private FD table!
    __u32 bpf_key = (__u32)key;
    int err = bpf_map_update_elem(map_fd, &bpf_key, &socket_fd, BPF_ANY);

    fflush(stdout);

    return err;
}

JNIEXPORT jint JNICALL Java_org_fmalyshev_quic_BpfRouting_nativeUpdateBpfMapL(
    JNIEnv *env, jclass clazz, jstring map_path, jlong key, jint socket_fd) {

    int map_fd = getMapFd(env, map_path);
    // 2. Execute the update directly from the Java process thread context
    // The kernel reads socket_fd relative to Java's private FD table!
    __u64 bpf_key = (__u64)key;
    int err = bpf_map_update_elem(map_fd, &bpf_key, &socket_fd, BPF_ANY);

    fflush(stdout);

    return err;
}

JNIEXPORT jint JNICALL Java_org_fmalyshev_quic_BpfRouting_nativeDeleteFromBpfMapL(
    JNIEnv *env, jclass clazz, jstring map_path, jlong key) {

    int map_fd = getMapFd(env, map_path);
    __u64 bpf_key = (__u64)key;
    int err = bpf_map_delete_elem(map_fd, &bpf_key);

    fflush(stdout);

    return err;
}

JNIEXPORT jint JNICALL Java_org_fmalyshev_quic_BpfRouting_nativeDeleteFromBpfMapI(
    JNIEnv *env, jclass clazz, jstring map_path, jint key) {

    int map_fd = getMapFd(env, map_path);
    __u32 bpf_key = (__u32)key;
    int err = bpf_map_delete_elem(map_fd, &bpf_key);

    return err;
}

JNIEXPORT jint JNICALL Java_org_fmalyshev_quic_BpfRouting_checkBpfMap(
    JNIEnv *env, jclass clazz, jstring map_path) {

    int map_fd = getMapFd(env, map_path);

    fflush(stdout);

    if (map_fd >= 0) {
        return 0;
    }
    return -1;
}

