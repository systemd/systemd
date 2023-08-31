/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "execute.h"

/* These functions serialize/deserialize for invocation purposes (i.e.: serialized object is passed to a
 * child process) rather than to save state across reload/reexec.
 * Note that the Unit object is only minimally serialized, to allow for logging with log_unit* in the
 * deserializer. Only type, id, cgroup_id and invocation_id are serialized and deserialized. */

int exec_serialize_invocation(FILE *f,
        FDSet *fds,
        const ExecContext *ctx,
        const ExecCommand *cmd,
        const ExecParameters *p,
        const ExecRuntime *rt,
        const CGroupContext *cg);

int exec_deserialize_invocation(FILE *f,
        FDSet *fds,
        ExecContext *ctx,
        ExecCommand *cmd,
        ExecParameters *p,
        ExecRuntime *rt,
        CGroupContext *cg);
