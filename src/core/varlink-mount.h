/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int mount_context_build_json(sd_json_variant **ret, const char *name, void *userdata);
int mount_runtime_build_json(sd_json_variant **ret, const char *name, void *userdata);
