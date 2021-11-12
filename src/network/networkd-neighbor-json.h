/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"
#include "set.h"

int neighbors_build_json(Set *neighbors, JsonVariant **ret);
