/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* IWYU pragma: always_keep */

#include <errno.h>                      /* IWYU pragma: export */
#include <inttypes.h>                   /* IWYU pragma: export */
#include <limits.h>                     /* IWYU pragma: export */
#include <paths.h>                      /* IWYU pragma: export */
#include <stdarg.h>                     /* IWYU pragma: export */
#include <stdbool.h>                    /* IWYU pragma: export */
#include <stddef.h>                     /* IWYU pragma: export */
#include <stdint.h>                     /* IWYU pragma: export */
#include <sys/types.h>                  /* IWYU pragma: export */
#include <uchar.h>                      /* IWYU pragma: export */

#include "assert-util.h"                /* IWYU pragma: export */
#include "cleanup-util.h"               /* IWYU pragma: export */
#include "macro.h"                      /* IWYU pragma: export */
#include "string-table-fundamental.h"   /* IWYU pragma: export */

/* Generic types */

typedef uint64_t usec_t;
typedef uint64_t nsec_t;

/* Libc/Linux forward declarations */

struct dirent;
struct ether_addr;
struct fiemap;
struct file_handle;
struct glob_t;
struct group;
struct icmp6_hdr;
struct in_addr;
struct in6_addr;
struct inotify_event;
struct iovec;
struct mount_attr;
struct msghdr;
struct passwd;
struct pollfd;
struct rlimit;
struct sgrp;
struct shadow;
struct signalfd_siginfo;
struct siphash;
struct sockaddr;
struct spwd;
struct stat;
struct statfs;
struct statx_timestamp;
struct statx;
struct termios;
struct tm;
struct ucred;

/* To forward declare FILE and DIR, we have to declare the internal struct names for them. Since these are
 * used for C++ symbol name mangling, they're effectively part of the ABI and won't actually change. */
typedef struct _IO_FILE FILE;
typedef struct __dirstream DIR;

/* 3rd-party library forward declarations */

enum bpf_map_type;

struct fdisk_context;
struct fdisk_table;
struct crypt_device;

/* basic/ forward declarations */

typedef void (*hash_func_t)(const void *p, struct siphash *state);
typedef int (*compare_func_t)(const void *a, const void *b);
typedef compare_func_t comparison_fn_t;
typedef int (*comparison_userdata_fn_t)(const void *, const void *, void *);

struct hash_ops;
struct hw_addr_data;
struct in_addr_data;
struct iovec_wrapper;
union in_addr_union;
union sockaddr_union;

typedef enum Architecture Architecture;
typedef enum CGroupFlags CGroupFlags;
typedef enum CGroupMask CGroupMask;
typedef enum ChaseFlags ChaseFlags;
typedef enum ConfFilesFlags ConfFilesFlags;
typedef enum ExtractFlags ExtractFlags;
typedef enum ForkFlags ForkFlags;
typedef enum Glyph Glyph;
typedef enum ImageClass ImageClass;
typedef enum JobMode JobMode;
typedef enum RuntimeScope RuntimeScope;
typedef enum TimestampStyle TimestampStyle;
typedef enum UnitActiveState UnitActiveState;
typedef enum UnitDependency UnitDependency;
typedef enum UnitNameMangle UnitNameMangle;
typedef enum UnitType UnitType;
typedef enum WaitFlags WaitFlags;

typedef struct Hashmap Hashmap;
typedef struct HashmapBase HashmapBase;
typedef struct IteratedCache IteratedCache;
typedef struct Iterator Iterator;
typedef struct OrderedHashmap OrderedHashmap;
typedef struct OrderedSet OrderedSet;
typedef struct Set Set;

typedef struct dual_timestamp dual_timestamp;
typedef struct triple_timestamp triple_timestamp;
typedef struct ConfFile ConfFile;
typedef struct LockFile LockFile;
typedef struct PidRef PidRef;
typedef struct Prioq Prioq;
typedef struct RateLimit RateLimit;
typedef struct SocketAddress SocketAddress;

/* Constants */

/* We duplicate various commonly used constants here so we can keep most static inline functions without
 * having to include the full header that provides these constants. */

/* glibc defines AT_FDCWD as -100, but musl defines it as (-100). */
#ifdef __GLIBC__
#define AT_FDCWD                -100
#else
#define AT_FDCWD                (-100)
#endif
#define AT_EMPTY_PATH           0x1000
#define AT_SYMLINK_FOLLOW       0x400
#define AT_SYMLINK_NOFOLLOW     0x100

#define MODE_INVALID            ((mode_t) -1)

#define UID_INVALID             ((uid_t) -1)
#define GID_INVALID             ((gid_t) -1)

#define USEC_INFINITY           ((usec_t) UINT64_MAX)
#define NSEC_INFINITY           ((nsec_t) UINT64_MAX)

/* MAX_ERRNO is defined as 4095 in linux/err.h. We use the same value here. */
#define ERRNO_MAX               4095
