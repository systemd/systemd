/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"
#include "user-record.h"

int quality_check_password(UserRecord *hr, UserRecord *secret, sd_bus_error *error);

int suggest_passwords(void);
