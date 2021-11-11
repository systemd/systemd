/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"

typedef struct Network Network;

int network_build_json(Network *network, JsonVariant **ret);
