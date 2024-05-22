/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

typedef struct Link Link;
typedef struct Manager Manager;

int link_build_json(Link *link, sd_json_variant **ret);
int manager_build_json(Manager *manager, sd_json_variant **ret);
