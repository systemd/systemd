/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"

typedef struct Link Link;

int link_addresses_build_json(Link *link, JsonVariant **ret);
