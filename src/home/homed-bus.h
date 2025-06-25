/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int bus_message_read_secret(sd_bus_message *m, UserRecord **ret, sd_bus_error *error);
int bus_message_read_home_record(sd_bus_message *m, UserRecordLoadFlags flags, UserRecord **ret, sd_bus_error *error);
int bus_message_read_blobs(sd_bus_message *m, Hashmap **ret, sd_bus_error *error);
