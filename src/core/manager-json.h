/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

#include "manager.h"

int rlimit_build_json(sd_json_variant **ret, const char *name, void *userdata);
int environment_build_json(sd_json_variant **ret, const char *name, void *userdata);
int manager_build_json(Manager *manager, sd_json_variant **ret);
