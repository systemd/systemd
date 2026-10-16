/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int scope_context_build_json(sd_json_variant **ret, const char *name, void *userdata);
int scope_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata);

typedef struct TransientScopeParameters TransientScopeParameters;
TransientScopeParameters* transient_scope_parameters_free(TransientScopeParameters *p);
int transient_scope_dispatch(sd_json_variant *variant, TransientScopeParameters **ret, const char **reterr_field);
int transient_scope_apply_properties(Scope *s, TransientScopeParameters *sp, sd_varlink *link, const char **reterr_field, sd_bus_error *reterr_bus_error);
