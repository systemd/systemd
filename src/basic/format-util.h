/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>
#include <net/if.h>
#include <stdbool.h>

#include "cgroup-util.h"
#include "macro.h"

assert_cc(sizeof(pid_t) == sizeof(int32_t));
#define PID_PRI PRIi32
#define PID_FMT "%" PID_PRI

assert_cc(sizeof(uid_t) == sizeof(uint32_t));
#define UID_FMT "%" PRIu32

assert_cc(sizeof(gid_t) == sizeof(uint32_t));
#define GID_FMT "%" PRIu32

#if SIZEOF_TIME_T == 8
#  define PRI_TIME PRIi64
#elif SIZEOF_TIME_T == 4
#  define PRI_TIME "li"
#else
#  error Unknown time_t size
#endif

#if defined __x86_64__ && defined __ILP32__
#  define PRI_TIMEX PRIi64
#else
#  define PRI_TIMEX "li"
#endif

#if SIZEOF_RLIM_T == 8
#  define RLIM_FMT "%" PRIu64
#elif SIZEOF_RLIM_T == 4
#  define RLIM_FMT "%" PRIu32
#else
#  error Unknown rlim_t size
#endif

#if SIZEOF_DEV_T == 8
#  define DEV_FMT "%" PRIu64
#elif SIZEOF_DEV_T == 4
#  define DEV_FMT "%" PRIu32
#else
#  error Unknown dev_t size
#endif

#if SIZEOF_INO_T == 8
#  define INO_FMT "%" PRIu64
#elif SIZEOF_INO_T == 4
#  define INO_FMT "%" PRIu32
#else
#  error Unknown ino_t size
#endif

typedef enum {
        FORMAT_IFNAME_IFINDEX              = 1 << 0,
        FORMAT_IFNAME_IFINDEX_WITH_PERCENT = (1 << 1) | FORMAT_IFNAME_IFINDEX,
} FormatIfnameFlag;

char *format_ifname_full(int ifindex, char buf[static IF_NAMESIZE + 1], FormatIfnameFlag flag);
static inline char *format_ifname(int ifindex, char buf[static IF_NAMESIZE + 1]) {
        return format_ifname_full(ifindex, buf, 0);
}

typedef enum {
        FORMAT_BYTES_USE_IEC     = 1 << 0,
        FORMAT_BYTES_BELOW_POINT = 1 << 1,
        FORMAT_BYTES_TRAILING_B  = 1 << 2,
} FormatBytesFlag;

#define FORMAT_BYTES_MAX 16
char *format_bytes_full(char *buf, size_t l, uint64_t t, FormatBytesFlag flag);
static inline char *format_bytes(char *buf, size_t l, uint64_t t) {
        return format_bytes_full(buf, l, t, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B);
}
static inline char *format_bytes_cgroup_protection(char *buf, size_t l, uint64_t t) {
        if (t == CGROUP_LIMIT_MAX) {
                (void) snprintf(buf, l, "%s", "infinity");
                return buf;
        }
        return format_bytes(buf, l, t);
}
