/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "machine-forward.h"

int vl_method_query_filter(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_resolve_record(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);

int manager_notify_hook_filters(Manager *m);
