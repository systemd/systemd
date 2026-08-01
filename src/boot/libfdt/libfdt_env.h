/* SPDX-License-Identifier: BSD-2-Clause */
#pragma once

/*
 * Custom libfdt environment header for systemd-boot's freestanding EFI environment.
 * This replaces the upstream libfdt_env.h which requires hosted C library headers.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "efi-string.h"
#include "util.h"



static inline size_t strlen(const char *s) {
        return strlen8(s);
}

static inline char *strchr(const char *s, int c) {
        return strchr8(s, c);
}

static inline int strcmp(const char *s1, const char *s2) {
        return strcmp8(s1, s2);
}

static inline int strncmp(const char *s1, const char *s2, size_t n) {
        return strncmp8(s1, s2, n);
}

static inline size_t strnlen(const char *s, size_t maxlen) {
        return strnlen8(s, maxlen);
}

static inline char *strrchr(const char *s, int c) {
        return strrchr8(s, c);
}

static inline unsigned long strtoul(const char *nptr, char **endptr, int base) {
        return strtoul8(nptr, endptr, base);
}

#ifdef __CHECKER__
#define FDT_FORCE __attribute__((force))
#define FDT_BITWISE __attribute__((bitwise))
#else
#define FDT_FORCE
#define FDT_BITWISE
#endif

typedef uint16_t FDT_BITWISE fdt16_t;
typedef uint32_t FDT_BITWISE fdt32_t;
typedef uint64_t FDT_BITWISE fdt64_t;

static inline uint16_t fdt16_to_cpu(fdt16_t x) {
        return (FDT_FORCE uint16_t)be16toh((FDT_FORCE uint16_t)x);
}
static inline fdt16_t cpu_to_fdt16(uint16_t x) {
        return (FDT_FORCE fdt16_t)htobe16(x);
}

static inline uint32_t fdt32_to_cpu(fdt32_t x) {
        return (FDT_FORCE uint32_t)be32toh((FDT_FORCE uint32_t)x);
}
static inline fdt32_t cpu_to_fdt32(uint32_t x) {
        return (FDT_FORCE fdt32_t)htobe32(x);
}

static inline uint64_t fdt64_to_cpu(fdt64_t x) {
        return (FDT_FORCE uint64_t)be64toh((FDT_FORCE uint64_t)x);
}
static inline fdt64_t cpu_to_fdt64(uint64_t x) {
        return (FDT_FORCE fdt64_t)htobe64(x);
}
