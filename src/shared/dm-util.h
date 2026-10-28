/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int dm_table_status(dev_t devnum, char **ret_target_type, char **ret_params);
int dm_verity_table_signed(const char *params, const char *root_hash, dev_t *ret_data_devnum);
int dm_get_devnum(const char *name, dev_t *ret);
int dm_open(const char *name, int flags, char **ret_devname);
