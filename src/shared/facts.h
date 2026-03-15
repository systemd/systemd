/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef struct FactFamily FactFamily;

typedef struct FactFamilyContext {
        const FactFamily *fact_family;
        sd_varlink *link;
} FactFamilyContext;

typedef int (*fact_family_generate_func_t)(FactFamilyContext *ffc, void *userdata);

typedef struct FactFamily {
        const char *name;
        const char *description;
        fact_family_generate_func_t generate;
} FactFamily;

/* Add io.systemd.Facts interface + methods to an existing varlink server */
int facts_add_to_varlink_server(
                sd_varlink_server *server,
                sd_varlink_method_t vl_method_list_cb,
                sd_varlink_method_t vl_method_describe_cb);

int facts_method_describe(const FactFamily fact_family_table[], sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int facts_method_list(const FactFamily fact_family_table[], sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

int fact_build_send_string(FactFamilyContext *context, const char *object, const char *value);
int fact_build_send_unsigned(FactFamilyContext *context, const char *object, uint64_t value);
