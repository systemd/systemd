/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "execute.h"

/* These functions serialize/deserialize for invocation purposes (i.e.: serialized object is passed to a
 * child process) rather than to save state across reload/reexec. */

int exec_serialize_invocation(FILE *f,
        FDSet *fds,
        const ExecContext *ctx,
        const ExecCommand *cmd,
        const ExecParameters *p);

int exec_deserialize_invocation(FILE *f,
        FDSet *fds,
        ExecContext *ctx,
        ExecCommand *cmd,
        ExecParameters *p);
