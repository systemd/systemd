/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "macro.h"

int parse_boolean(const char *v) _pure_;
int parse_dev(const char *s, dev_t *ret);
int parse_pid(const char *s, pid_t* ret_pid);
int parse_mode(const char *s, mode_t *ret);
int parse_ifindex(const char *s, int *ret);
int parse_ifindex_or_ifname(const char *s, int *ret);
int parse_mtu(int family, const char *s, uint32_t *ret);

int parse_size(const char *t, uint64_t base, uint64_t *size);
int parse_range(const char *t, unsigned *lower, unsigned *upper);
int parse_errno(const char *t);
int parse_syscall_and_errno(const char *in, char **name, int *error);

int safe_atou_full(const char *s, unsigned base, unsigned *ret_u);

static inline int safe_atou(const char *s, unsigned *ret_u) {
        return safe_atou_full(s, 0, ret_u);
}

int safe_atoi(const char *s, int *ret_i);
int safe_atollu(const char *s, unsigned long long *ret_u);
int safe_atolli(const char *s, long long int *ret_i);

int safe_atou8(const char *s, uint8_t *ret);

int safe_atou16_full(const char *s, unsigned base, uint16_t *ret);

static inline int safe_atou16(const char *s, uint16_t *ret) {
        return safe_atou16_full(s, 0, ret);
}

static inline int safe_atoux16(const char *s, uint16_t *ret) {
        return safe_atou16_full(s, 16, ret);
}

int safe_atoi16(const char *s, int16_t *ret);

static inline int safe_atou32(const char *s, uint32_t *ret_u) {
        assert_cc(sizeof(uint32_t) == sizeof(unsigned));
        return safe_atou(s, (unsigned*) ret_u);
}

static inline int safe_atoi32(const char *s, int32_t *ret_i) {
        assert_cc(sizeof(int32_t) == sizeof(int));
        return safe_atoi(s, (int*) ret_i);
}

static inline int safe_atou64(const char *s, uint64_t *ret_u) {
        assert_cc(sizeof(uint64_t) == sizeof(unsigned long long));
        return safe_atollu(s, (unsigned long long*) ret_u);
}

static inline int safe_atoi64(const char *s, int64_t *ret_i) {
        assert_cc(sizeof(int64_t) == sizeof(long long int));
        return safe_atolli(s, (long long int*) ret_i);
}

#if LONG_MAX == INT_MAX
static inline int safe_atolu(const char *s, unsigned long *ret_u) {
        assert_cc(sizeof(unsigned long) == sizeof(unsigned));
        return safe_atou(s, (unsigned*) ret_u);
}
static inline int safe_atoli(const char *s, long int *ret_u) {
        assert_cc(sizeof(long int) == sizeof(int));
        return safe_atoi(s, (int*) ret_u);
}
#else
static inline int safe_atolu(const char *s, unsigned long *ret_u) {
        assert_cc(sizeof(unsigned long) == sizeof(unsigned long long));
        return safe_atollu(s, (unsigned long long*) ret_u);
}
static inline int safe_atoli(const char *s, long int *ret_u) {
        assert_cc(sizeof(long int) == sizeof(long long int));
        return safe_atolli(s, (long long int*) ret_u);
}
#endif

#if SIZE_MAX == UINT_MAX
static inline int safe_atozu(const char *s, size_t *ret_u) {
        assert_cc(sizeof(size_t) == sizeof(unsigned));
        return safe_atou(s, (unsigned *) ret_u);
}
#else
static inline int safe_atozu(const char *s, size_t *ret_u) {
        assert_cc(sizeof(size_t) == sizeof(long unsigned));
        return safe_atolu(s, ret_u);
}
#endif

int safe_atod(const char *s, double *ret_d);

int parse_fractional_part_u(const char **s, size_t digits, unsigned *res);

int parse_percent_unbounded(const char *p);
int parse_percent(const char *p);

int parse_permille_unbounded(const char *p);
int parse_permille(const char *p);

int parse_nice(const char *p, int *ret);

int parse_ip_port(const char *s, uint16_t *ret);
int parse_ip_port_range(const char *s, uint16_t *low, uint16_t *high);

int parse_oom_score_adjust(const char *s, int *ret);
