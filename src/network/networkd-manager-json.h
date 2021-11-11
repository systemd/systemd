/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"

typedef struct Manager Manager;

int manager_build_json(Manager *manager, JsonVariant **ret);
