/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int dm_deferred_remove_cancel(const char *name);
int dm_table_status(dev_t devnum, char **ret_target_type, char **ret_params);
int dm_verity_table_signed(const char *params, const char *root_hash);
