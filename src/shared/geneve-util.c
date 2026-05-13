/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "geneve-util.h"
#include "string-table.h"

static const char* const geneve_df_table[_NETDEV_GENEVE_DF_MAX] = {
        [NETDEV_GENEVE_DF_UNSET]   = "unset",
        [NETDEV_GENEVE_DF_SET]     = "set",
        [NETDEV_GENEVE_DF_INHERIT] = "inherit",
};

DEFINE_STRING_TABLE_LOOKUP(geneve_df, GeneveDF);
