/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int unit_kill_context_build_json(sd_json_variant **ret, const char *name, void *userdata);

typedef struct TransientKillContextParameters TransientKillContextParameters;
TransientKillContextParameters* transient_kill_context_parameters_free(TransientKillContextParameters *p);
int transient_kill_context_dispatch(sd_json_variant *variant, TransientKillContextParameters **ret, const char **reterr_field);
int transient_kill_context_apply_properties(Unit *u, KillContext *k, TransientKillContextParameters *p);
