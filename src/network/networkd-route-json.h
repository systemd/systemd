/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"
#include "set.h"

int routes_build_json(Set *routes, JsonVariant **ret);
