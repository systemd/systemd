/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int unit_cgroup_context_build_json(sd_json_variant **ret, const char *name, void *userdata);
int unit_cgroup_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata);
