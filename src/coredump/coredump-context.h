/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "coredump-forward.h"
#include "pidref.h"

typedef enum {
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
        _META_MAX
} meta_argv_t;

extern const char * const meta_field_names[_META_MAX];

struct Context {
        PidRef pidref;
        uid_t uid;
        gid_t gid;
        unsigned dumpable;
        int signo;
        uint64_t rlimit;
        bool is_pid1;
        bool is_journald;
        bool got_pidfd;
        int mount_tree_fd;

        /* These point into external memory, are not owned by this object */
        const char *meta[_META_MAX];
        size_t meta_size[_META_MAX];
};

#define CONTEXT_NULL                            \
        (Context) {                             \
                .pidref = PIDREF_NULL,          \
                .uid = UID_INVALID,             \
                .gid = GID_INVALID,             \
                .mount_tree_fd = -EBADF,        \
        }

void context_done(Context *c);
int context_parse_iovw(Context *context, struct iovec_wrapper *iovw);
int gather_pid_metadata_from_argv(struct iovec_wrapper *iovw, Context *context, int argc, char **argv);
int gather_pid_metadata_from_procfs(struct iovec_wrapper *iovw, Context *context);
