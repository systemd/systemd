/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"
#include "sd-varlink.h"

int rlimit_build_json(sd_json_variant **ret, const char *name, void *userdata);
int activation_details_build_json(sd_json_variant **ret, const char *name, void *userdata);
