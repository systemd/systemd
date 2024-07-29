/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "homed-manager.h"

int vl_method_get_user_record(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_get_group_record(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_get_memberships(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
