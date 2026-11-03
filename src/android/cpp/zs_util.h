// File, /proc/self/maps and string helpers built on zs_sys.h. String routines are implemented
// here rather than taken from libc, because anti-detection scripts commonly hook strstr/strcmp to
// hide "frida" or "magisk".
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char *data;
    size_t len;
} zs_buf;

typedef struct {
    uintptr_t start;
    uintptr_t end;
    unsigned long offset;
    char perms[5];
    const char *path;  // points into zs_maps.raw; "" for anonymous mappings
} zs_region;

typedef struct {
    zs_region *items;
    size_t count;
    zs_buf raw;
} zs_maps;

// Reads a whole file (procfs files included) through raw syscalls. Returns 0 or -errno.
int zs_read_file(const char *path, zs_buf *out, size_t max_bytes);
void zs_buf_free(zs_buf *buf);

int zs_maps_load(zs_maps *maps);
void zs_maps_free(zs_maps *maps);
const zs_region *zs_maps_find(const zs_maps *maps, uintptr_t addr);

// Copies our own memory without faulting if it is unmapped or unreadable. Returns 0 on success.
int zs_read_memory(uintptr_t addr, void *out, size_t len);

// Reads exactly len bytes at offset. Returns 0 on success.
int zs_read_at(int fd, long offset, void *out, size_t len);

size_t zs_strlen(const char *s);
// Case-insensitive (ASCII) substring test.
int zs_contains(const char *haystack, const char *needle);
const char *zs_find(const char *haystack, const char *needle);
int zs_starts_with(const char *s, const char *prefix);
int zs_ends_with(const char *s, const char *suffix);
int zs_mem_equal(const void *a, const void *b, size_t len);
// Case-sensitive search for needle in a raw byte range.
int zs_mem_contains(const uint8_t *haystack, size_t len, const char *needle);
// Bounded copy that always NUL-terminates. Returns bytes copied.
size_t zs_copy(char *dst, size_t cap, const char *src);
