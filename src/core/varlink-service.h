/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int service_context_build_json(sd_json_variant **ret, const char *name, void *userdata);
int service_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata);

typedef struct TransientServiceParameters TransientServiceParameters;
TransientServiceParameters* transient_service_parameters_free(TransientServiceParameters *p);
int transient_service_dispatch(sd_json_variant *variant, TransientServiceParameters **ret, const char **reterr_field);
int transient_service_resolve_stdio_fds(sd_varlink *link, TransientServiceParameters *sp, const char **reterr_field);
int transient_service_apply_properties(Service *s, TransientServiceParameters *sp, const char **reterr_field);
