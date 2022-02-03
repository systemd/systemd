/* SPDX-License-Identifier: LGPL-2.1-or-later */
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

#if SIZEOF_TIMEX_MEMBER == 8
#  define PRI_TIMEX PRIi64
#elif SIZEOF_TIMEX_MEMBER == 4
#  define PRI_TIMEX "li"
#else
#  error Unknown timex member size
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

int format_ifname_full(int ifindex, FormatIfnameFlag flag, char buf[static IF_NAMESIZE]);
int format_ifname_full_alloc(int ifindex, FormatIfnameFlag flag, char **ret);

static inline int format_ifname(int ifindex, char buf[static IF_NAMESIZE]) {
        return format_ifname_full(ifindex, 0, buf);
}
static inline int format_ifname_alloc(int ifindex, char **ret) {
        return format_ifname_full_alloc(ifindex, 0, ret);
}

static inline char *_format_ifname_full(int ifindex, FormatIfnameFlag flag, char buf[static IF_NAMESIZE]) {
        (void) format_ifname_full(ifindex, flag, buf);
        return buf;
}

#define FORMAT_IFNAME_FULL(index, flag) _format_ifname_full(index, flag, (char[IF_NAMESIZE]){})
#define FORMAT_IFNAME(index) _format_ifname_full(index, 0, (char[IF_NAMESIZE]){})

typedef enum {
        FORMAT_BYTES_USE_IEC     = 1 << 0,
        FORMAT_BYTES_BELOW_POINT = 1 << 1,
        FORMAT_BYTES_TRAILING_B  = 1 << 2,
} FormatBytesFlag;

#define FORMAT_BYTES_MAX 16U

char *format_bytes_full(char *buf, size_t l, uint64_t t, FormatBytesFlag flag) _warn_unused_result_;

_warn_unused_result_
static inline char *format_bytes(char *buf, size_t l, uint64_t t) {
        return format_bytes_full(buf, l, t, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B);
}

/* Note: the lifetime of the compound literal is the immediately surrounding block,
 * see C11 §6.5.2.5, and
 * https://stackoverflow.com/questions/34880638/compound-literal-lifetime-and-if-blocks */
#define FORMAT_BYTES(t) format_bytes((char[FORMAT_BYTES_MAX]){}, FORMAT_BYTES_MAX, t)
#define FORMAT_BYTES_FULL(t, flag) format_bytes_full((char[FORMAT_BYTES_MAX]){}, FORMAT_BYTES_MAX, t, flag)

#define FORMAT_BYTES_CGROUP_PROTECTION(t) (t == CGROUP_LIMIT_MAX ? "infinity" : FORMAT_BYTES(t))
