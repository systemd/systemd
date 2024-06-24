/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "user-record.h"
#include "group-record.h"

const char* user_record_state_color(const char *state);

void user_record_show(UserRecord *hr, bool show_full_group_info);
void group_record_show(GroupRecord *gr, bool show_full_user_info);
