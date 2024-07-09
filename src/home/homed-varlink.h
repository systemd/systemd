/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "homed-manager.h"

int vl_method_get_user_record(Varlink *link, sd_json_variant *parameters, VarlinkMethodFlags flags, void *userdata);
int vl_method_get_group_record(Varlink *link, sd_json_variant *parameters, VarlinkMethodFlags flags, void *userdata);
int vl_method_get_memberships(Varlink *link, sd_json_variant *parameters, VarlinkMethodFlags flags, void *userdata);
