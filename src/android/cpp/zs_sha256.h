#pragma once

#include <stddef.h>
#include <stdint.h>

#define ZS_SHA256_HEX_LEN 64

// SHA-256 of data, written as 64 lower-case hex characters plus NUL into hex_out[65].
void zs_sha256_hex(const uint8_t *data, size_t len, char hex_out[ZS_SHA256_HEX_LEN + 1]);
