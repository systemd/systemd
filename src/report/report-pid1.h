/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#define METRIC_IO_SYSTEMD_PID1_PREFIX "io.systemd.PID1."

/* Snapshot of PID1 data read from /proc/1 at startup.
 *
 * Each *_result field is:
 *   0  = source not yet collected (matches new0() zero-init),
 *   1  = collected successfully,
 *   <0 = collection failed with this -errno.
 *
 * Callbacks emit only when the field is 1. This leaves zero-init meaning
 * "uncollected", so skipping the collect calls cannot silently produce
 * zero-valued metrics. */
typedef struct Pid1Context {
        uint64_t utime_jiffies;
        uint64_t stime_jiffies;
        uint64_t memory_bytes;
        uint64_t fd_count;
        uint64_t threads;
        int stat_result;
        int memory_result;
        int fd_result;
        int threads_result;
} Pid1Context;

/* Collection is split into two phases so the privilege drop can happen between them:
 *
 *  1. pid1_context_collect_privileged() runs as root and handles the pieces
 *     that require privilege — counting /proc/1/fd (mode 0500, root-owned)
 *     and opening /proc/1/stat and /proc/1/status past the ProtectProc=
 *     hidepid check. The two fds are returned to the caller.
 *
 *  2. pid1_context_collect_unprivileged() parses those fds and can therefore
 *     run after drop_privileges(). It takes ownership of both fds and closes
 *     them before returning. Reads from the already-open file descriptions
 *     succeed regardless of current credentials because the kernel's access
 *     check ran at open() time. */
void pid1_context_collect_privileged(Pid1Context *ctx, int *ret_stat_fd, int *ret_status_fd);
void pid1_context_collect_unprivileged(Pid1Context *ctx, int stat_fd, int status_fd);

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
