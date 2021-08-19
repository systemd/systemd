/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "devlink-util.h"
#include "string-table.h"

static const char * const devlink_cmd_table[__DEVLINK_CMD_MAX] = {
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(devlink_cmd, int);
