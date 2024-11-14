/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

#include "manager.h"

int vl_method_describe_manager(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

int rlimit_build_json(sd_json_variant **ret, const char *name, void *userdata);
int manager_environment_build_json(sd_json_variant **ret, const char *name, void *userdata);
