/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int dm_get_devnum(const char *name, dev_t *ret);
int dm_open(const char *name, int flags, char **ret_devname);
