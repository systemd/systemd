/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "macro.h"

typedef unsigned long loadavg_t;

int parse_boolean(const char *v) _pure_;
int parse_pid(const char *s, pid_t* ret_pid);
int parse_mode(const char *s, mode_t *ret);
int parse_ifindex(const char *s);
int parse_mtu(int family, const char *s, uint32_t *ret);

int parse_size(const char *t, uint64_t base, uint64_t *size);
int parse_range(const char *t, unsigned *lower, unsigned *upper);
int parse_errno(const char *t);

#define SAFE_ATO_REFUSE_PLUS_MINUS (1U << 30)
#define SAFE_ATO_REFUSE_LEADING_ZERO (1U << 29)
#define SAFE_ATO_REFUSE_LEADING_WHITESPACE (1U << 28)
#define SAFE_ATO_ALL_FLAGS (SAFE_ATO_REFUSE_PLUS_MINUS|SAFE_ATO_REFUSE_LEADING_ZERO|SAFE_ATO_REFUSE_LEADING_WHITESPACE)
#define SAFE_ATO_MASK_FLAGS(base) ((base) & ~SAFE_ATO_ALL_FLAGS)

int safe_atou_full(const char *s, unsigned base, unsigned *ret_u);

static inline int safe_atou(const char *s, unsigned *ret_u) {
        return safe_atou_full(s, 0, ret_u);
}

int safe_atoi(const char *s, int *ret_i);
int safe_atolli(const char *s, long long int *ret_i);

int safe_atou8_full(const char *s, unsigned base, uint8_t *ret);

static inline int safe_atou8(const char *s, uint8_t *ret) {
        return safe_atou8_full(s, 0, ret);
}

int safe_atou16_full(const char *s, unsigned base, uint16_t *ret);

static inline int safe_atou16(const char *s, uint16_t *ret) {
        return safe_atou16_full(s, 0, ret);
}

static inline int safe_atoux16(const char *s, uint16_t *ret) {
        return safe_atou16_full(s, 16, ret);
}

int safe_atoi16(const char *s, int16_t *ret);

static inline int safe_atou32_full(const char *s, unsigned base, uint32_t *ret_u) {
        assert_cc(sizeof(uint32_t) == sizeof(unsigned));
        return safe_atou_full(s, base, (unsigned*) ret_u);
}

static inline int safe_atou32(const char *s, uint32_t *ret_u) {
        return safe_atou32_full(s, 0, (unsigned*) ret_u);
}

static inline int safe_atoi32(const char *s, int32_t *ret_i) {
        assert_cc(sizeof(int32_t) == sizeof(int));
        return safe_atoi(s, (int*) ret_i);
}

int safe_atollu_full(const char *s, unsigned base, unsigned long long *ret_llu);

static inline int safe_atollu(const char *s, unsigned long long *ret_llu) {
        return safe_atollu_full(s, 0, ret_llu);
}

static inline int safe_atou64(const char *s, uint64_t *ret_u) {
        assert_cc(sizeof(uint64_t) == sizeof(unsigned long long));
        return safe_atollu(s, (unsigned long long*) ret_u);
}

static inline int safe_atoi64(const char *s, int64_t *ret_i) {
        assert_cc(sizeof(int64_t) == sizeof(long long int));
        return safe_atolli(s, (long long int*) ret_i);
}

static inline int safe_atoux64(const char *s, uint64_t *ret) {
        assert_cc(sizeof(int64_t) == sizeof(unsigned long long));
        return safe_atollu_full(s, 16, (unsigned long long*) ret);
}

#if LONG_MAX == INT_MAX
static inline int safe_atolu_full(const char *s, unsigned base, unsigned long *ret_u) {
        assert_cc(sizeof(unsigned long) == sizeof(unsigned));
        return safe_atou_full(s, base, (unsigned*) ret_u);
}
static inline int safe_atoli(const char *s, long int *ret_u) {
        assert_cc(sizeof(long int) == sizeof(int));
        return safe_atoi(s, (int*) ret_u);
}
#else
static inline int safe_atolu_full(const char *s, unsigned base, unsigned long *ret_u) {
        assert_cc(sizeof(unsigned long) == sizeof(unsigned long long));
        return safe_atollu_full(s, base, (unsigned long long*) ret_u);
}
static inline int safe_atoli(const char *s, long int *ret_u) {
        assert_cc(sizeof(long int) == sizeof(long long int));
        return safe_atolli(s, (long long int*) ret_u);
}
#endif

static inline int safe_atolu(const char *s, unsigned long *ret_u) {
        return safe_atolu_full(s, 0, ret_u);
}

#if SIZE_MAX == UINT_MAX
static inline int safe_atozu(const char *s, size_t *ret_u) {
        assert_cc(sizeof(size_t) == sizeof(unsigned));
        return safe_atou(s, (unsigned *) ret_u);
}
#else
static inline int safe_atozu(const char *s, size_t *ret_u) {
        assert_cc(sizeof(size_t) == sizeof(unsigned long));
        return safe_atolu(s, ret_u);
}
#endif

int safe_atod(const char *s, double *ret_d);

int parse_fractional_part_u(const char **s, size_t digits, unsigned *res);

int parse_nice(const char *p, int *ret);

int parse_ip_port(const char *s, uint16_t *ret);
int parse_ip_port_range(const char *s, uint16_t *low, uint16_t *high);

int parse_ip_prefix_length(const char *s, int *ret);

int parse_oom_score_adjust(const char *s, int *ret);

/* Implement floating point using fixed integers, to improve performance when
 * calculating load averages. These macros can be used to extract the integer
 * and decimal parts of a value. */
#define LOADAVG_PRECISION_BITS  11
#define LOADAVG_FIXED_POINT_1_0 (1 << LOADAVG_PRECISION_BITS)
#define LOADAVG_INT_SIDE(x)     ((x) >> LOADAVG_PRECISION_BITS)
#define LOADAVG_DECIMAL_SIDE(x) LOADAVG_INT_SIDE(((x) & (LOADAVG_FIXED_POINT_1_0 - 1)) * 100)

/* Given a Linux load average (e.g. decimal number 34.89 where 34 is passed as i and 89 is passed as f), convert it
 * to a loadavg_t. */
int store_loadavg_fixed_point(unsigned long i, unsigned long f, loadavg_t *ret);
int parse_loadavg_fixed_point(const char *s, loadavg_t *ret);
