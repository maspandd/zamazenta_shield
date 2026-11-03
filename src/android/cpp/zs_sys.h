// Direct system calls. Root hiders and anti-detection scripts usually hook libc (open, access,
// read, strstr, ...). On arm64 and x86_64, which cover every Play-eligible device, these wrappers
// trap into the kernel themselves, so a libc hook never sees them. 32-bit ABIs fall back to libc
// syscall(). Every wrapper returns -errno on failure, never sets errno.
#pragma once

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#if defined(__aarch64__)
#define ZS_RAW_SYSCALLS 1
static inline long zs_syscall6(long n, long a, long b, long c, long d, long e, long f) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
}
#elif defined(__x86_64__)
#define ZS_RAW_SYSCALLS 1
static inline long zs_syscall6(long n, long a, long b, long c, long d, long e, long f) {
    long ret;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "0"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory", "cc");
    return ret;
}
#else
#define ZS_RAW_SYSCALLS 0
static inline long zs_syscall6(long n, long a, long b, long c, long d, long e, long f) {
    long r = syscall(n, a, b, c, d, e, f);
    return r == -1 ? -errno : r;
}
#endif

static inline int zs_openat(int dirfd, const char *path, int flags) {
    return (int) zs_syscall6(__NR_openat, dirfd, (long) path, flags, 0, 0, 0);
}

static inline ssize_t zs_read(int fd, void *buf, size_t count) {
    return (ssize_t) zs_syscall6(__NR_read, fd, (long) buf, (long) count, 0, 0, 0);
}

static inline int zs_close(int fd) {
    return (int) zs_syscall6(__NR_close, fd, 0, 0, 0, 0, 0);
}

static inline off_t zs_lseek(int fd, off_t offset, int whence) {
    return (off_t) zs_syscall6(__NR_lseek, fd, (long) offset, whence, 0, 0, 0);
}

static inline int zs_faccessat(int dirfd, const char *path, int mode) {
    return (int) zs_syscall6(__NR_faccessat, dirfd, (long) path, mode, 0, 0, 0);
}

static inline ssize_t zs_readlinkat(int dirfd, const char *path, char *buf, size_t size) {
    return (ssize_t) zs_syscall6(__NR_readlinkat, dirfd, (long) path, (long) buf, (long) size, 0, 0);
}

static inline long zs_getdents64(int fd, void *buf, size_t size) {
    return zs_syscall6(__NR_getdents64, fd, (long) buf, (long) size, 0, 0, 0);
}

static inline int zs_inotify_init1(int flags) {
    return (int) zs_syscall6(__NR_inotify_init1, flags, 0, 0, 0, 0, 0);
}

static inline int zs_inotify_add_watch(int fd, const char *path, uint32_t mask) {
    return (int) zs_syscall6(__NR_inotify_add_watch, fd, (long) path, (long) mask, 0, 0, 0);
}

static inline int zs_prctl(int option, unsigned long arg2) {
    return (int) zs_syscall6(__NR_prctl, option, (long) arg2, 0, 0, 0, 0);
}

static inline pid_t zs_getpid(void) {
    return (pid_t) zs_syscall6(__NR_getpid, 0, 0, 0, 0, 0, 0);
}

static inline ssize_t zs_process_vm_readv(pid_t pid, const struct iovec *local, unsigned long local_count,
                                          const struct iovec *remote, unsigned long remote_count) {
    return (ssize_t) zs_syscall6(__NR_process_vm_readv, pid, (long) local, (long) local_count,
                                 (long) remote, (long) remote_count, 0);
}

__attribute__((noreturn)) static inline void zs_exit_group(int status) {
    for (;;) zs_syscall6(__NR_exit_group, status, 0, 0, 0, 0, 0);
}
