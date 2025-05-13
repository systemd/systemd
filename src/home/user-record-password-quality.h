/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int user_record_check_password_quality(UserRecord *hr, UserRecord *secret, sd_bus_error *error);
