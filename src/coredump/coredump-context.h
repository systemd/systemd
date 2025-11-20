/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "coredump-forward.h"
#include "iovec-wrapper.h"
#include "pidref.h"

typedef enum MetadataField {
        /* We use these as array indexes for our process metadata cache.
         *
         * The first indices of the cache stores the same metadata as the ones passed by the kernel via
         * argv[], i.e. the strings specified in our pattern defined in /proc/sys/kernel/core_pattern,
         * see core(5). */

        META_ARGV_PID,          /* %P: as seen in the initial pid namespace */
        META_ARGV_UID,          /* %u: as seen in the initial user namespace */
        META_ARGV_GID,          /* %g: as seen in the initial user namespace */
        META_ARGV_SIGNAL,       /* %s: number of signal causing dump */
        META_ARGV_TIMESTAMP,    /* %t: time of dump, expressed as seconds since the Epoch (we expand this to μs granularity) */
        META_ARGV_RLIMIT,       /* %c: core file size soft resource limit */
        _META_ARGV_REQUIRED,
        /* The fields below were added to kernel/core_pattern at later points, so they might be missing. */
        META_ARGV_HOSTNAME = _META_ARGV_REQUIRED,  /* %h: hostname */
        META_ARGV_DUMPABLE,     /* %d: as set by the kernel */
        META_ARGV_PIDFD,        /* %F: pidfd of the process, since v6.16 */
        /* If new fields are added, they should be added here, to maintain compatibility
         * with callers which don't know about the new fields. */
        _META_ARGV_MAX,

        /* The following indexes are cached for a couple of special fields we use (and
         * thereby need to be retrieved quickly) for naming coredump files, and attaching
         * xattrs. Unlike the previous ones they are retrieved from the runtime
         * environment. */

        META_COMM = _META_ARGV_MAX,

        /* The rest are similar to the previous ones except that we won't fail if one of
         * them is missing in a message sent over the socket. */

        META_EXE,
        META_UNIT,
        META_PROC_AUXV,
        _META_MAX,
        _META_INVALID = -EINVAL,
} MetadataField;

struct CoredumpContext {
        PidRef pidref;     /* META_ARGV_PID and META_ARGV_PIDFD */
        uid_t uid;         /* META_ARGV_UID */
        gid_t gid;         /* META_ARGV_GID */
        int signo;         /* META_ARGV_SIGNAL */
        usec_t timestamp;  /* META_ARGV_TIMESTAMP */
        uint64_t rlimit;   /* META_ARGV_RLIMIT */
        char *hostname;    /* META_ARGV_HOSTNAME */
        unsigned dumpable; /* META_ARGV_DUMPABLE */
        char *comm;        /* META_COMM */
        char *exe;         /* META_EXE */
        char *unit;        /* META_UNIT */
        char *auxv;        /* META_PROC_AUXV */
        size_t auxv_size;  /* META_PROC_AUXV */
        bool got_pidfd;    /* META_ARGV_PIDFD */
        bool same_pidns;
        bool forwarded;
        int input_fd;
        int mount_tree_fd;
        struct iovec_wrapper iovw;
};

#define COREDUMP_CONTEXT_NULL                   \
        (CoredumpContext) {                     \
                .pidref = PIDREF_NULL,          \
                .uid = UID_INVALID,             \
                .gid = GID_INVALID,             \
                .mount_tree_fd = -EBADF,        \
                .input_fd = -EBADF,             \
        }

void coredump_context_done(CoredumpContext *context);
bool coredump_context_is_pid1(CoredumpContext *context);
bool coredump_context_is_journald(CoredumpContext *context);
int coredump_context_build_iovw(CoredumpContext *context);
int coredump_context_parse_iovw(CoredumpContext *context);
int coredump_context_parse_from_argv(CoredumpContext *context, int argc, char **argv);
