/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "user-record.h"
#include "json.h"

int bus_message_read_secret(sd_bus_message *m, UserRecord **ret, sd_bus_error *error);
int bus_message_read_home_record(sd_bus_message *m, UserRecordLoadFlags flags, UserRecord **ret, sd_bus_error *error);
