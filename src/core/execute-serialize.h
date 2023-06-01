/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "execute.h"

int exec_context_serialize(const ExecContext *c, FILE *f, FDSet *fds);
int exec_context_deserialize(ExecContext *c, FILE *f, FDSet *fds);
int exec_command_serialize(const ExecCommand *c, FILE *f);
int exec_command_deserialize(ExecCommand *c, FILE *f);
int exec_parameters_serialize(const ExecParameters *p, FILE *f, FDSet *fds);
int exec_parameters_deserialize(ExecParameters *p, FILE *f, FDSet *fds);
int exec_runtime_serialize(const ExecRuntime *r, FILE *f, FDSet *fds);
int exec_runtime_deserialize(ExecRuntime *r, FILE *f, FDSet *fds);
int exec_cgroup_context_serialize(const CGroupContext *c, FILE *f);
int exec_cgroup_context_deserialize(CGroupContext *c, FILE *f);
