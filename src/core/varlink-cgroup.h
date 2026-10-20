/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int unit_cgroup_context_build_json(sd_json_variant **ret, const char *name, void *userdata);
int unit_cgroup_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata);

typedef struct TransientCGroupContextParameters TransientCGroupContextParameters;
TransientCGroupContextParameters* transient_cgroup_context_parameters_free(TransientCGroupContextParameters *p);
int transient_cgroup_context_dispatch(sd_json_variant *variant, TransientCGroupContextParameters **ret, char **reterr_bad_field);
int transient_cgroup_context_apply_properties(Unit *u, CGroupContext *c, TransientCGroupContextParameters *p, char **reterr_bad_field);
