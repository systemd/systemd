/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"
#include "user-record.h"

int user_record_check_password_quality(UserRecord *hr, UserRecord *secret, sd_bus_error *error);
