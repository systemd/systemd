/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "io-util.h"

enum {
        /* The following fields are mandatory and are passed by the kernel when running in handler
         * mode. */

        META_PID,                /* %P: as seen in the initial pid namespace */
        META_SIGNAL,             /* %s: number of signal causing dump */
        META_TIMESTAMP,          /* %t: time of dump, expressed as seconds since the Epoch */
        META_RLIMIT,             /* %c: core file size soft resource limit */

        /* The following fields are cached since they're used for naming coredump files, and
         * attaching xattrs. Unlike the previous ones they are retrieved from /proc. */

        META_COMM,
        META_UID,
        META_GID,

        _META_MANDATORY_MAX,

        /* The rest are similar to the previous ones except that we won't fail if one of them is
         * missing. */

        META_EXE = _META_MANDATORY_MAX,
        META_UNIT,
        META_NS_PID,             /* %p: as seen in tne pid namespace of the crashing process */
        META_HOSTNAME,           /* %h: hostname */

        _META_MAX
};

typedef struct Context {
        const char *meta[_META_MAX];
        pid_t pid, ns_pid;
        uid_t uid;
        gid_t gid;
        bool is_pid1;
        bool is_journald;
        bool is_coredumpd;
        bool exec_in_namespace;
} Context;

int coredump_submit(Context *context, struct iovec_wrapper *iovw, int input_fd);
int coredump_save_context(Context *context, const struct iovec_wrapper *iovw);
