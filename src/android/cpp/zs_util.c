#include "zs_util.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "zs_sys.h"

#define ZS_INITIAL_CAPACITY 16384

int zs_read_file(const char *path, zs_buf *out, size_t max_bytes) {
    out->data = NULL;
    out->len = 0;
    int fd = zs_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return fd;

    char *data = NULL;
    size_t cap = 0;
    size_t len = 0;
    for (;;) {
        if (cap - len < 2) {
            if (cap >= max_bytes + 1) break;
            size_t next = cap ? cap * 2 : ZS_INITIAL_CAPACITY;
            if (next > max_bytes + 1) next = max_bytes + 1;
            char *grown = realloc(data, next);
            if (!grown) break;
            data = grown;
            cap = next;
        }
        ssize_t got = zs_read(fd, data + len, cap - len - 1);
        if (got == -EINTR) continue;
        if (got <= 0) break;
        len += (size_t) got;
    }
    zs_close(fd);

    if (!data) {
        data = malloc(1);
        if (!data) return -ENOMEM;
    }
    data[len] = '\0';
    out->data = data;
    out->len = len;
    return 0;
}

void zs_buf_free(zs_buf *buf) {
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
}

static int parse_hex(const char **cursor, uintptr_t *out) {
    uintptr_t value = 0;
    int digits = 0;
    for (const char *p = *cursor;; p++) {
        int d;
        if (*p >= '0' && *p <= '9') d = *p - '0';
        else if (*p >= 'a' && *p <= 'f') d = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') d = *p - 'A' + 10;
        else {
            *cursor = p;
            break;
        }
        value = (value << 4) | (uintptr_t) d;
        digits++;
    }
    *out = value;
    return digits > 0;
}

static const char *skip_token(const char *p) {
    while (*p && *p != ' ') p++;
    while (*p == ' ') p++;
    return p;
}

int zs_maps_load(zs_maps *maps) {
    memset(maps, 0, sizeof(*maps));
    int rc = zs_read_file("/proc/self/maps", &maps->raw, 32u << 20);
    if (rc != 0) return rc;

    size_t lines = 1;
    for (size_t i = 0; i < maps->raw.len; i++) {
        if (maps->raw.data[i] == '\n') lines++;
    }
    maps->items = calloc(lines, sizeof(zs_region));
    if (!maps->items) {
        zs_buf_free(&maps->raw);
        return -ENOMEM;
    }

    char *line = maps->raw.data;
    while (line && *line) {
        char *next = line;
        while (*next && *next != '\n') next++;
        if (*next == '\n') *next++ = '\0';
        else next = NULL;

        // "start-end perms offset dev inode   path"
        zs_region region;
        const char *p = line;
        uintptr_t offset = 0;
        if (parse_hex(&p, &region.start) && *p++ == '-' && parse_hex(&p, &region.end) && *p++ == ' ') {
            for (int i = 0; i < 4; i++) region.perms[i] = p[i] ? p[i] : '-';
            region.perms[4] = '\0';
            p = skip_token(p);
            if (parse_hex(&p, &offset)) {
                region.offset = (unsigned long) offset;
                p = skip_token(p);  // offset
                p = skip_token(p);  // dev
                p = skip_token(p);  // inode
                region.path = p;
                maps->items[maps->count++] = region;
            }
        }
        line = next;
    }
    return 0;
}

void zs_maps_free(zs_maps *maps) {
    free(maps->items);
    maps->items = NULL;
    maps->count = 0;
    zs_buf_free(&maps->raw);
}

const zs_region *zs_maps_find(const zs_maps *maps, uintptr_t addr) {
    for (size_t i = 0; i < maps->count; i++) {
        if (addr >= maps->items[i].start && addr < maps->items[i].end) return &maps->items[i];
    }
    return NULL;
}

int zs_read_memory(uintptr_t addr, void *out, size_t len) {
    struct iovec local = {out, len};
    struct iovec remote = {(void *) addr, len};
    return zs_process_vm_readv(zs_getpid(), &local, 1, &remote, 1) == (ssize_t) len ? 0 : -1;
}

int zs_read_at(int fd, long offset, void *out, size_t len) {
    if (zs_lseek(fd, (off_t) offset, SEEK_SET) != (off_t) offset) return -1;
    size_t done = 0;
    while (done < len) {
        ssize_t got = zs_read(fd, (char *) out + done, len - done);
        if (got == -EINTR) continue;
        if (got <= 0) return -1;
        done += (size_t) got;
    }
    return 0;
}

size_t zs_strlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static char lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char) (c - 'A' + 'a') : c;
}

const char *zs_find(const char *haystack, const char *needle) {
    if (!*needle) return haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n && lower(*h) == lower(*n)) {
            h++;
            n++;
        }
        if (!*n) return haystack;
    }
    return NULL;
}

int zs_contains(const char *haystack, const char *needle) {
    return zs_find(haystack, needle) != NULL;
}

int zs_starts_with(const char *s, const char *prefix) {
    while (*prefix) {
        if (*s++ != *prefix++) return 0;
    }
    return 1;
}

int zs_ends_with(const char *s, const char *suffix) {
    size_t a = zs_strlen(s);
    size_t b = zs_strlen(suffix);
    return a >= b && zs_mem_equal(s + a - b, suffix, b);
}

int zs_mem_equal(const void *a, const void *b, size_t len) {
    const volatile uint8_t *x = a;
    const volatile uint8_t *y = b;
    for (size_t i = 0; i < len; i++) {
        if (x[i] != y[i]) return 0;
    }
    return 1;
}

int zs_mem_contains(const uint8_t *haystack, size_t len, const char *needle) {
    size_t n = zs_strlen(needle);
    if (n == 0 || len < n) return 0;
    for (size_t i = 0; i + n <= len; i++) {
        if (haystack[i] == (uint8_t) needle[0] && zs_mem_equal(haystack + i, needle, n)) return 1;
    }
    return 0;
}

size_t zs_copy(char *dst, size_t cap, const char *src) {
    if (cap == 0) return 0;
    size_t i = 0;
    for (; i + 1 < cap && src[i]; i++) dst[i] = src[i];
    dst[i] = '\0';
    return i;
}
