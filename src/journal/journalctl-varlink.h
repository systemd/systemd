/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-varlink.h"

int varlink_connect_journal(sd_varlink **ret);

int action_flush_to_var(void);
int action_relinquish_var(void);
int action_rotate(void);
int action_vacuum(void);
int action_rotate_and_vacuum(void);
int action_sync(void);
