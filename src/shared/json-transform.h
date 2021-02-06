/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "bus-message.h"
#include "json.h"

int json_transform_message(sd_bus_message *m, JsonVariant **ret);
int json_transform_variant(sd_bus_message *m, const char *contents, JsonVariant **ret);
