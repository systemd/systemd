/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "user-record.h"

int user_record_quality_check_password(UserRecord *hr, UserRecord *secret, sd_bus_error *error);
