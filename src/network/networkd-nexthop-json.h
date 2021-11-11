/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"
#include "set.h"

int nexthops_build_json(Set *nexthops, JsonVariant **ret);
