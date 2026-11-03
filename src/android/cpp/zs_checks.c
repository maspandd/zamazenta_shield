#include "zs_checks.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>

#include "zs_sys.h"

#define ZS_PROLOGUE_BYTES 16
#define ZS_SCAN_CHUNK 65536
#define ZS_SCAN_BUDGET (64u << 20)

struct zs_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

typedef void (*zs_dir_visitor)(int dirfd, const char *name, void *ctx);

static void for_each_dirent(const char *path, zs_dir_visitor visit, void *ctx) {
    int dirfd = zs_openat(AT_FDCWD, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) return;
    char buf[4096] __attribute__((aligned(8)));
    for (;;) {
        long n = zs_getdents64(dirfd, buf, sizeof(buf));
        if (n <= 0) break;
        for (long pos = 0; pos < n;) {
            struct zs_dirent64 *entry = (struct zs_dirent64 *) (buf + pos);
            if (entry->d_reclen == 0) break;
            if (entry->d_name[0] != '.') visit(dirfd, entry->d_name, ctx);
            pos += entry->d_reclen;
        }
    }
    zs_close(dirfd);
}

static int contains_any(const char *value, const char *const *markers, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (zs_contains(value, markers[i])) return 1;
    }
    return 0;
}

#define ZS_COUNT(a) (sizeof(a) / sizeof((a)[0]))

void zs_report_add(zs_report *report, int code, const char *prefix, const char *detail) {
    char text[ZS_ITEM_TEXT];
    size_t used = zs_copy(text, sizeof(text), prefix);
    zs_copy(text + used, sizeof(text) - used, detail);
    for (size_t i = 0; i < report->count; i++) {
        if (report->items[i].code == code && zs_mem_equal(report->items[i].text, text, zs_strlen(text) + 1)) return;
    }
    if (report->count >= ZS_MAX_ITEMS) return;
    report->items[report->count].code = code;
    zs_copy(report->items[report->count].text, ZS_ITEM_TEXT, text);
    report->count++;
}

// ---- Tracer ----

void zs_check_tracer(zs_report *report) {
    zs_buf status;
    if (zs_read_file("/proc/self/status", &status, 64 * 1024) != 0) return;
    const char *field = zs_find(status.data, "TracerPid:");
    if (field) {
        field += zs_strlen("TracerPid:");
        while (*field == ' ' || *field == '\t') field++;
        char pid[16];
        size_t i = 0;
        while (i + 1 < sizeof(pid) && field[i] >= '0' && field[i] <= '9') {
            pid[i] = field[i];
            i++;
        }
        pid[i] = '\0';
        if (i > 0 && !(i == 1 && pid[0] == '0')) zs_report_add(report, ZS_CODE_NATIVE_DEBUGGER, "native-TracerPid:", pid);
    }
    zs_buf_free(&status);
}

// ---- Root ----

static const char *const ZS_ROOT_PATHS[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/system/sd/xbin/su",
    "/system/bin/failsafe/su", "/system/bin/.ext/.su", "/data/local/su", "/data/local/bin/su",
    "/data/local/xbin/su", "/cache/su", "/data/su", "/dev/su", "/system/xbin/daemonsu",
    "/system/bin/magisk", "/sbin/magisk", "/sbin/.magisk", "/debug_ramdisk/magisk", "/debug_ramdisk/su",
    "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap", "/data/adb/modules", "/system/app/Superuser.apk",
};

static const char *const ZS_ROOT_MOUNT_MARKERS[] = {
    "magisk", "kernelsu", " /debug_ramdisk ", "zygisk", "apatch",
};

void zs_check_root(zs_report *report) {
    for (size_t i = 0; i < ZS_COUNT(ZS_ROOT_PATHS); i++) {
        if (zs_faccessat(AT_FDCWD, ZS_ROOT_PATHS[i], F_OK) == 0) {
            zs_report_add(report, ZS_CODE_ROOTED, "native-file:", ZS_ROOT_PATHS[i]);
        }
    }

    zs_buf mounts;
    if (zs_read_file("/proc/self/mountinfo", &mounts, 4u << 20) == 0) {
        char *line = mounts.data;
        while (line && *line) {
            char *next = line;
            while (*next && *next != '\n') next++;
            if (*next) *next++ = '\0';
            else next = NULL;
            if (contains_any(line, ZS_ROOT_MOUNT_MARKERS, ZS_COUNT(ZS_ROOT_MOUNT_MARKERS))) {
                zs_report_add(report, ZS_CODE_ROOTED, "native-mount:", line);
            }
            line = next;
        }
        zs_buf_free(&mounts);
    }

    zs_buf context;
    if (zs_read_file("/proc/self/attr/current", &context, 4096) == 0) {
        if (zs_contains(context.data, "magisk") || zs_contains(context.data, "su:s0")) {
            zs_report_add(report, ZS_CODE_ROOTED, "native-selinux:", context.data);
        }
        zs_buf_free(&context);
    }
}

// ---- Frida ----

static const char *const ZS_FRIDA_MAP_MARKERS[] = {"frida", "gadget", "linjector", "gum-js"};
static const char *const ZS_FRIDA_THREAD_MARKERS[] = {"gum-js-loop", "gmain", "gdbus", "pool-frida", "linjector", "pool-spawner"};
static const char *const ZS_FRIDA_FD_MARKERS[] = {"linjector", "frida"};
static const char *const ZS_FRIDA_MEMORY_NEEDLES[] = {"frida:rpc", "LIBFRIDA", "frida-agent"};

static void visit_thread(int dirfd, const char *tid, void *ctx) {
    char path[64];
    size_t used = zs_copy(path, sizeof(path), tid);
    zs_copy(path + used, sizeof(path) - used, "/comm");
    int fd = zs_openat(dirfd, path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    char name[32];
    ssize_t n = zs_read(fd, name, sizeof(name) - 1);
    zs_close(fd);
    if (n <= 0) return;
    name[n] = '\0';
    if (name[n - 1] == '\n') name[n - 1] = '\0';
    if (contains_any(name, ZS_FRIDA_THREAD_MARKERS, ZS_COUNT(ZS_FRIDA_THREAD_MARKERS))) {
        zs_report_add((zs_report *) ctx, ZS_CODE_HOOKING_FRAMEWORK, "native-thread:", name);
    }
}

static void visit_fd(int dirfd, const char *fd_name, void *ctx) {
    char target[PATH_MAX];
    ssize_t n = zs_readlinkat(dirfd, fd_name, target, sizeof(target) - 1);
    if (n <= 0) return;
    target[n] = '\0';
    if (contains_any(target, ZS_FRIDA_FD_MARKERS, ZS_COUNT(ZS_FRIDA_FD_MARKERS))) {
        zs_report_add((zs_report *) ctx, ZS_CODE_HOOKING_FRAMEWORK, "native-fd:", target);
    }
}

// Renamed Frida builds hide the agent's file name but still carry its strings. Only memfd-backed or
// deleted-file mappings are scanned: that is where injected agents live, and it keeps the cost low.
static void scan_injected_memory(const zs_maps *maps, zs_report *report) {
    const zs_region *self = zs_maps_find(maps, (uintptr_t) &scan_injected_memory);
    uint8_t *chunk = malloc(ZS_SCAN_CHUNK);
    if (!chunk) return;
    size_t budget = ZS_SCAN_BUDGET;
    const size_t overlap = 32;

    for (size_t i = 0; i < maps->count && budget > 0; i++) {
        const zs_region *r = &maps->items[i];
        if (r->perms[0] != 'r') continue;
        if (!zs_starts_with(r->path, "/memfd:") && !zs_contains(r->path, "(deleted)")) continue;
        if (zs_contains(r->path, "jit-cache") || zs_contains(r->path, "jit-zygote-cache")) continue;
        if (zs_contains(r->path, "/data/app/")) continue;
        if (self && zs_mem_equal(r->path, self->path, zs_strlen(self->path) + 1)) continue;

        for (uintptr_t addr = r->start; addr < r->end && budget > 0;) {
            size_t len = (size_t) (r->end - addr);
            if (len > ZS_SCAN_CHUNK) len = ZS_SCAN_CHUNK;
            if (len > budget) len = budget;
            if (zs_read_memory(addr, chunk, len) != 0) break;
            budget -= len;
            for (size_t k = 0; k < ZS_COUNT(ZS_FRIDA_MEMORY_NEEDLES); k++) {
                if (zs_mem_contains(chunk, len, ZS_FRIDA_MEMORY_NEEDLES[k])) {
                    zs_report_add(report, ZS_CODE_HOOKING_FRAMEWORK, "native-memory:", r->path);
                }
            }
            if (addr + len >= r->end) break;
            addr += len > overlap ? len - overlap : len;
        }
    }
    free(chunk);
}

void zs_check_frida(const zs_maps *maps, zs_report *report) {
    for (size_t i = 0; i < maps->count; i++) {
        const char *path = maps->items[i].path;
        if (path[0] && contains_any(path, ZS_FRIDA_MAP_MARKERS, ZS_COUNT(ZS_FRIDA_MAP_MARKERS))) {
            zs_report_add(report, ZS_CODE_HOOKING_FRAMEWORK, "native-maps:", path);
        }
    }
    for_each_dirent("/proc/self/task", visit_thread, report);
    for_each_dirent("/proc/self/fd", visit_fd, report);
    scan_injected_memory(maps, report);
}

// ---- Inline hooks ----

typedef struct {
    const char *library;
    const char *symbol;
} zs_hook_target;

// Functions anti-detection scripts patch to blind root/Frida checks, plus ptrace/kill/exit paths.
static const zs_hook_target ZS_HOOK_TARGETS[] = {
    {"libc.so", "open"}, {"libc.so", "openat"}, {"libc.so", "__openat"}, {"libc.so", "read"},
    {"libc.so", "fopen"}, {"libc.so", "fgets"}, {"libc.so", "strstr"}, {"libc.so", "strcmp"},
    {"libc.so", "access"}, {"libc.so", "faccessat"}, {"libc.so", "stat"}, {"libc.so", "fstatat"},
    {"libc.so", "readlink"}, {"libc.so", "readlinkat"}, {"libc.so", "opendir"}, {"libc.so", "readdir"},
    {"libc.so", "ptrace"}, {"libc.so", "kill"}, {"libc.so", "exit"}, {"libc.so", "_exit"},
    {"libc.so", "syscall"}, {"libc.so", "pthread_create"}, {"libc.so", "inotify_add_watch"},
    {"libc.so", "process_vm_readv"}, {"libc.so", "__system_property_get"},
    {"libdl.so", "dlopen"}, {"libdl.so", "dlsym"},
};

static void compare_prologue(const zs_maps *maps, const void *function, const char *name, zs_report *report) {
    uintptr_t addr = (uintptr_t) function;
#if defined(__arm__)
    addr &= ~(uintptr_t) 1;  // strip the Thumb bit
#endif
    const zs_region *region = zs_maps_find(maps, addr);
    if (!region) return;
    if (region->path[0] != '/') {
        // A libc symbol that resolves into anonymous memory has been redirected wholesale.
        zs_report_add(report, ZS_CODE_NATIVE_HOOKS, "native-anon-symbol:", name);
        return;
    }
    if (zs_contains(region->path, "(deleted)") || addr + ZS_PROLOGUE_BYTES > region->end) return;

    uint8_t in_memory[ZS_PROLOGUE_BYTES];
    uint8_t on_disk[ZS_PROLOGUE_BYTES];
    if (zs_read_memory(addr, in_memory, sizeof(in_memory)) != 0) return;  // execute-only page
    int fd = zs_openat(AT_FDCWD, region->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    long file_offset = (long) (addr - region->start + region->offset);
    int read_ok = zs_read_at(fd, file_offset, on_disk, sizeof(on_disk)) == 0;
    zs_close(fd);
    if (read_ok && !zs_mem_equal(in_memory, on_disk, sizeof(in_memory))) {
        zs_report_add(report, ZS_CODE_NATIVE_HOOKS, "native-prologue:", name);
    }
}

void zs_check_inline_hooks(const zs_maps *maps, zs_report *report) {
    for (size_t i = 0; i < ZS_COUNT(ZS_HOOK_TARGETS); i++) {
        void *handle = dlopen(ZS_HOOK_TARGETS[i].library, RTLD_NOW | RTLD_NOLOAD);
        if (!handle) continue;
        void *symbol = dlsym(handle, ZS_HOOK_TARGETS[i].symbol);
        if (symbol) compare_prologue(maps, symbol, ZS_HOOK_TARGETS[i].symbol, report);
        dlclose(handle);
    }

    // Our own entry points: patching these is the cheapest way to disable the shield.
    compare_prologue(maps, (const void *) &zs_check_tracer, "zs_check_tracer", report);
    compare_prologue(maps, (const void *) &zs_check_root, "zs_check_root", report);
    compare_prologue(maps, (const void *) &zs_check_frida, "zs_check_frida", report);
    compare_prologue(maps, (const void *) &zs_check_inline_hooks, "zs_check_inline_hooks", report);
    compare_prologue(maps, (const void *) &zs_check_injection, "zs_check_injection", report);
    compare_prologue(maps, (const void *) &zs_report_add, "zs_report_add", report);
}

// ---- Injection ----

static int is_foreign_app_path(const char *path, const char *package_name) {
    const char *rest = NULL;
    if (zs_starts_with(path, "/data/data/")) {
        rest = path + zs_strlen("/data/data/");
    } else if (zs_starts_with(path, "/data/user/")) {
        rest = path + zs_strlen("/data/user/");
        while (*rest >= '0' && *rest <= '9') rest++;
        if (*rest != '/') return 0;
        rest++;
    }
    if (!rest) return 0;
    size_t n = zs_strlen(package_name);
    return !(zs_mem_equal(rest, package_name, n) && rest[n] == '/');
}

void zs_check_injection(const zs_maps *maps, const char *package_name, zs_report *report) {
    for (size_t i = 0; i < maps->count; i++) {
        const char *path = maps->items[i].path;
        if (!zs_contains(path, ".so")) continue;
        if (zs_starts_with(path, "/data/local/tmp") || zs_starts_with(path, "/sdcard") ||
            zs_starts_with(path, "/storage") || is_foreign_app_path(path, package_name)) {
            zs_report_add(report, ZS_CODE_CODE_INJECTION, "native-maps:", path);
        }
    }
}

// ---- Memory scanning ----

int zs_memwatch_open(void) {
    int fd = zs_inotify_init1(IN_CLOEXEC);
    if (fd < 0) return fd;
    int wd = zs_inotify_add_watch(fd, "/proc/self/mem", IN_OPEN | IN_ACCESS);
    if (wd < 0) {
        zs_close(fd);
        return wd;
    }
    return fd;
}

int zs_memwatch_wait(int fd, char *detail, size_t detail_len) {
    char buf[sizeof(struct inotify_event) + NAME_MAX + 1] __attribute__((aligned(__alignof__(struct inotify_event))));
    for (;;) {
        ssize_t n = zs_read(fd, buf, sizeof(buf));
        if (n == -EINTR) continue;
        if (n < (ssize_t) sizeof(struct inotify_event)) return -1;
        const struct inotify_event *event = (const struct inotify_event *) buf;
        zs_copy(detail, detail_len, (event->mask & IN_OPEN) ? "/proc/self/mem opened" : "/proc/self/mem read");
        return 1;
    }
}
