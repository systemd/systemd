/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "user-record.h"

const char *user_record_state_color(const char *state);

void user_record_show(UserRecord *hr, bool show_full_group_info);
