// APK Signature Scheme v2/v3 parsing, per https://source.android.com/docs/security/features/apksigning/v2
//
//   [zip entries][APK Signing Block][central directory][end of central directory]
//   APK Signing Block = u64 size, (u64 len, u32 id, value)*, u64 size, "APK Sig Block 42"
#include "zs_apksig.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>

#include "zs_sys.h"
#include "zs_util.h"

#define EOCD_MAGIC 0x06054b50u
#define EOCD_MIN_SIZE 22
#define EOCD_MAX_COMMENT 0xffff
#define BLOCK_FOOTER_SIZE 24
#define MAX_BLOCK_SIZE (64u << 20)

#define ID_V2 0x7109871au
#define ID_V3 0xf05368c0u
#define ID_V31 0x1b93ad61u

typedef struct {
    const uint8_t *p;
    size_t n;
} slice;

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t) (p[0] | (p[1] << 8));
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static uint64_t rd64(const uint8_t *p) {
    return (uint64_t) rd32(p) | ((uint64_t) rd32(p + 4) << 32);
}

// Splits off a u32-length-prefixed field.
static int take_prefixed(slice *s, slice *out) {
    if (s->n < 4) return -1;
    uint32_t len = rd32(s->p);
    if (len > s->n - 4) return -1;
    out->p = s->p + 4;
    out->n = len;
    s->p += 4 + (size_t) len;
    s->n -= 4 + (size_t) len;
    return 0;
}

static int find_central_directory(int fd, long file_size, uint32_t *cd_offset) {
    long tail_len = file_size < EOCD_MIN_SIZE + EOCD_MAX_COMMENT ? file_size : EOCD_MIN_SIZE + EOCD_MAX_COMMENT;
    uint8_t *tail = malloc((size_t) tail_len);
    if (!tail) return ZS_APK_IO_ERROR;
    int rc = ZS_APK_MALFORMED;
    if (zs_read_at(fd, file_size - tail_len, tail, (size_t) tail_len) != 0) {
        rc = ZS_APK_IO_ERROR;
    } else {
        for (long i = tail_len - EOCD_MIN_SIZE; i >= 0; i--) {
            if (rd32(tail + i) == EOCD_MAGIC && i + EOCD_MIN_SIZE + rd16(tail + i + 20) == tail_len) {
                *cd_offset = rd32(tail + i + 16);
                rc = ZS_APK_OK;
                break;
            }
        }
    }
    free(tail);
    return rc;
}

static int collect_signers(slice value, char out[ZS_APK_MAX_SIGNERS][ZS_SHA256_HEX_LEN + 1], size_t *count) {
    slice signers;
    if (take_prefixed(&value, &signers) != 0) return ZS_APK_MALFORMED;
    while (signers.n > 0 && *count < ZS_APK_MAX_SIGNERS) {
        slice signer, signed_data, digests, certificates, certificate;
        if (take_prefixed(&signers, &signer) != 0 ||
            take_prefixed(&signer, &signed_data) != 0 ||
            take_prefixed(&signed_data, &digests) != 0 ||
            take_prefixed(&signed_data, &certificates) != 0 ||
            take_prefixed(&certificates, &certificate) != 0 ||
            certificate.n == 0) {
            return ZS_APK_MALFORMED;
        }
        zs_sha256_hex(certificate.p, certificate.n, out[*count]);
        (*count)++;
    }
    return *count > 0 ? ZS_APK_OK : ZS_APK_MALFORMED;
}

int zs_apk_signer_fingerprints(const char *apk_path, int sdk_int,
                               char out[ZS_APK_MAX_SIGNERS][ZS_SHA256_HEX_LEN + 1], size_t *count) {
    *count = 0;
    int fd = zs_openat(AT_FDCWD, apk_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return ZS_APK_IO_ERROR;

    int rc;
    uint8_t *block = NULL;
    long file_size = (long) zs_lseek(fd, 0, SEEK_END);
    uint32_t cd_offset = 0;
    uint8_t footer[BLOCK_FOOTER_SIZE];

    if (file_size < EOCD_MIN_SIZE) {
        rc = ZS_APK_MALFORMED;
        goto done;
    }
    rc = find_central_directory(fd, file_size, &cd_offset);
    if (rc != ZS_APK_OK) goto done;
    if (cd_offset < BLOCK_FOOTER_SIZE || (long) cd_offset > file_size ||
        zs_read_at(fd, (long) cd_offset - BLOCK_FOOTER_SIZE, footer, sizeof(footer)) != 0 ||
        !zs_mem_equal(footer + 8, "APK Sig Block 42", 16)) {
        rc = ZS_APK_NO_SIGNING_BLOCK;
        goto done;
    }

    uint64_t block_size = rd64(footer);
    if (block_size < BLOCK_FOOTER_SIZE || block_size > MAX_BLOCK_SIZE || block_size + 8 > cd_offset) {
        rc = ZS_APK_MALFORMED;
        goto done;
    }
    size_t total = (size_t) block_size + 8;
    block = malloc(total);
    if (!block || zs_read_at(fd, (long) cd_offset - (long) total, block, total) != 0) {
        rc = ZS_APK_IO_ERROR;
        goto done;
    }
    if (rd64(block) != block_size) {
        rc = ZS_APK_MALFORMED;
        goto done;
    }

    slice pairs = {block + 8, total - 8 - BLOCK_FOOTER_SIZE};
    slice v2 = {0}, v3 = {0}, v31 = {0};
    while (pairs.n >= 12) {
        uint64_t len = rd64(pairs.p);
        if (len < 4 || len > pairs.n - 8) {
            rc = ZS_APK_MALFORMED;
            goto done;
        }
        uint32_t id = rd32(pairs.p + 8);
        slice value = {pairs.p + 12, (size_t) len - 4};
        if (id == ID_V2) v2 = value;
        else if (id == ID_V3) v3 = value;
        else if (id == ID_V31) v31 = value;
        pairs.p += 8 + (size_t) len;
        pairs.n -= 8 + (size_t) len;
    }

    slice chosen = {0};
    if (sdk_int >= 33 && v31.p) chosen = v31;
    else if (sdk_int >= 28 && v3.p) chosen = v3;
    else if (v2.p) chosen = v2;
    rc = chosen.p ? collect_signers(chosen, out, count) : ZS_APK_NO_SIGNING_BLOCK;

done:
    free(block);
    zs_close(fd);
    return rc;
}
