#pragma once

#include <stddef.h>

#include "zs_sha256.h"

#define ZS_APK_OK 0
#define ZS_APK_IO_ERROR (-1)
#define ZS_APK_NO_SIGNING_BLOCK (-2)
#define ZS_APK_MALFORMED (-3)

#define ZS_APK_MAX_SIGNERS 8

// Reads the APK Signing Block straight from the installed APK (raw syscalls, no PackageManager)
// and returns the SHA-256 of each signer's leaf certificate, from the scheme the platform
// verifies on this device: v3.1 on API 33+, v3 on API 28+, otherwise v2. Picking by API level
// matters: a lower-priority block is not verified when a higher one exists, so an attacker could
// splice the original block into an APK re-signed with their own key.
int zs_apk_signer_fingerprints(const char *apk_path, int sdk_int,
                               char out[ZS_APK_MAX_SIGNERS][ZS_SHA256_HEX_LEN + 1], size_t *count);
