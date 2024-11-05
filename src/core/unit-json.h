/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

#include "unit.h"

int unit_build_json(Unit *unit, sd_json_variant **ret);
