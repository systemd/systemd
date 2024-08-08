/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

#include "manager.h"

int manager_build_json(Manager *manager, sd_json_variant **ret);
