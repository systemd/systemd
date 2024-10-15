/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-varlink.h"

#include "machine.h"

#define VARLINK_DISPATCH_MACHINE_LOOKUP_FIELDS(t) {                     \
                .name = "name",                                         \
                .type = SD_JSON_VARIANT_STRING,                         \
                .callback = sd_json_dispatch_const_string,              \
                .offset = offsetof(t, name)                             \
        }, {                                                            \
                .name = "pid",                                          \
                .type = _SD_JSON_VARIANT_TYPE_INVALID,                  \
                .callback = json_dispatch_pidref,                       \
                .offset = offsetof(t, pidref),                          \
                .flags = SD_JSON_RELAX /* allows PID_AUTOMATIC */       \
        }

int lookup_machine_by_name_or_pidref(sd_varlink *link, Manager *manager, const char *machine_name, const PidRef *pidref, Machine **ret_machine);

int vl_method_register(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_unregister_internal(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_terminate_internal(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_kill(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
