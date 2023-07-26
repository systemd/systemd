/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "execute.h"

/* These functions take both a fdset and a fd array. If the fdset is non-NULL it will be used, otherwise the
 * fd arra will be used instead. The fdset is useful when serializing to a child process that is directly
 * forked, and the fd array is useful when serializing and sending data over via a socket (SCM_RIGHTS).
 * In the former case the serialized key=value strings will mention the fd numbers, as they will match
 * between the parent (serializer) and the child (deserializer). In the latter case the serialized key=value
 * strings will mention the index in the fd array where the corresponding file descriptor will be found, as
 * the fd numbers will not match between sender and receiver.
 *
 * Note that the Unit object is only minimally serialized, to allow for logging with log_unit* in the
 * deserializer. Only type, id, cgroup_id and invocation_id are serialized and deserialized. */

int exec_serialize(FILE *f,
        FDSet *fds,
        int **fds_array,
        size_t *n_fds_array,
        const Unit *u,
        const ExecContext *ctx,
        const ExecCommand *cmd,
        const ExecParameters *p,
        const ExecRuntime *rt,
        const CGroupContext *cg);

int exec_deserialize(FILE *f,
        FDSet *fds,
        int *fds_array,
        size_t n_fds_array,
        Unit **ret_unit,
        ExecCommand *c,
        ExecParameters *p,
        ExecRuntime *rt);
