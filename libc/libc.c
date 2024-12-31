// SPDX-FileCopyrightText: 2005-2020 Rich Felker, et al.
// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

#if __clang__

#   include <stdint.h>
#   include "types.h"

#   define NOEXPORT __attribute__((visibility("hidden")))

NOEXPORT
void xmss_sponge_absorb(uint64_t *A, uint_fast8_t offset, const uint8_t *bytes, uint_fast8_t byte_count);

NOEXPORT
void xmss_sponge_absorb_native(uint64_t *A, const uint32_t *words, uint_fast8_t word_count);

NOEXPORT
void xmss_sponge_squeeze(XmssValue256 *digest, const uint64_t *A);

NOEXPORT
void xmss_sponge_squeeze_native(XmssNativeValue256 *native_digest, const uint64_t *A);

NOEXPORT
void xmss_keccak_p_1600_24(uint64_t *A);

#else  // !__clang__

#   define NOEXPORT

#endif

#include "../xmss-library/src/shake256_256_internal_default.c"  // NOLINT

#if _WINDLL || __clang__

// Implementation based on https://musl.libc.org/

#include <string.h>

NOEXPORT
int memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *left = s1;
    const unsigned char *right = s2;
    for (; n; n--) {
        int diff = (int)*left++ - (int)*right++;
        if (diff != 0) {
            return diff;
        }
    }
    return 0;
}

NOEXPORT
void *memcpy(void * restrict s1, const void * restrict s2, size_t n) {  // DevSkim: ignore DS121708
    unsigned char *dst = s1;
    const unsigned char *src = s2;
    for (; n; n--) {
        *dst++ = *src++;
    }
    return s1;
}

NOEXPORT
void *memset(void *s, int c, size_t n) {
    unsigned char *dest = s;
    for (; n; n--) {
        *dest++ = (unsigned char)c;
    }
    return s;
}

#endif  // _WINDLL || __clang__
