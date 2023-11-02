/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "execute.h"

/* These functions serialize/deserialize for invocation purposes (i.e.: serialized object is passed to a
 * child process) rather than to save state across reload/reexec. These functions can also serialize FDs by
 * value or index. The former is useful when serializing to a child process that is directly forked, and the
 * latter is useful when serializing and sending data over via a socket (SCM_RIGHTS). */

int exec_serialize_invocation(FILE *f,
        FDSet *fds,
        bool indexed,
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
