/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int unit_exec_context_build_json(sd_json_variant **ret, const char *name, void *userdata);

typedef struct TransientExecContextParameters TransientExecContextParameters;
TransientExecContextParameters* transient_exec_context_parameters_free(TransientExecContextParameters *p);
int transient_exec_context_dispatch(sd_json_variant *variant, TransientExecContextParameters **ret, char **reterr_bad_field);
int transient_exec_context_apply_properties(Unit *u, ExecContext *c, TransientExecContextParameters *p, char **reterr_bad_field);
