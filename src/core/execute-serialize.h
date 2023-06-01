/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "execute.h"

int exec_serialize(FILE *f,
                FDSet *fds,
                const Unit *u,
                const ExecContext *ctx,
                const ExecCommand *cmd,
                const ExecParameters *p,
                const ExecRuntime *rt,
                const CGroupContext *cg);

int exec_deserialize(FILE *f,
                FDSet *fds,
                Unit **ret_unit,
                ExecCommand *c,
                ExecParameters *p,
                ExecRuntime *rt);
