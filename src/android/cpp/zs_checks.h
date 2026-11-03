#pragma once

#include <stddef.h>

#include "zs_util.h"

// Must match com.zamazenta.shield.Threat codes.
#define ZS_CODE_ROOTED 0
#define ZS_CODE_REPACKAGED 1
#define ZS_CODE_NATIVE_HOOKS 6
#define ZS_CODE_NATIVE_DEBUGGER 9
#define ZS_CODE_HOOKING_FRAMEWORK 22
#define ZS_CODE_CODE_INJECTION 35
#define ZS_CODE_MEMORY_SCAN 42

#define ZS_MAX_ITEMS 48
#define ZS_ITEM_TEXT 176

typedef struct {
    int code;
    char text[ZS_ITEM_TEXT];
} zs_item;

typedef struct {
    zs_item items[ZS_MAX_ITEMS];
    size_t count;
} zs_report;

// Adds "prefix + detail" under code, skipping exact duplicates.
void zs_report_add(zs_report *report, int code, const char *prefix, const char *detail);

// TracerPid != 0: gdb/lldb, strace, ltrace or any other ptrace-based tracer.
void zs_check_tracer(zs_report *report);

// su binaries and root managers (via raw faccessat), Magisk/KernelSU mounts, SELinux context.
void zs_check_root(zs_report *report);

// Frida: mapped agent/gadget, glib/frida thread names, injector fds, agent strings in memfd memory.
void zs_check_frida(const zs_maps *maps, zs_report *report);

// Inline hooks and software breakpoints: compares the first bytes of sensitive libc functions and
// of this library's own checks against the bytes in the file they were mapped from.
void zs_check_inline_hooks(const zs_maps *maps, zs_report *report);

// Native code mapped from locations an APK install never produces.
void zs_check_injection(const zs_maps *maps, const char *package_name, zs_report *report);

// Memory-scanner detection: an inotify watch on /proc/self/mem. Nothing in a normal app process
// opens that file; GameGuardian-style scanners and memory dumpers do. Returns the fd or -errno.
int zs_memwatch_open(void);
// Blocks until /proc/self/mem is opened or read. Returns 1 on an event, negative on error.
int zs_memwatch_wait(int fd, char *detail, size_t detail_len);
