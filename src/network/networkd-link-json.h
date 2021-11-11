/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"

typedef struct Link Link;
typedef struct Manager Manager;

int link_build_json(Link *link, JsonVariant **ret);
int links_build_json(Manager *manager, JsonVariant **ret);
