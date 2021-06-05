/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/if_link.h>

#include "conf-parser.h"

typedef enum GeneveDF {
        NETDEV_GENEVE_DF_UNSET    = GENEVE_DF_UNSET,
        NETDEV_GENEVE_DF_SET      = GENEVE_DF_SET,
        NETDEV_GENEVE_DF_INHERIT  = GENEVE_DF_INHERIT,
        _NETDEV_GENEVE_DF_MAX,
        _NETDEV_GENEVE_DF_INVALID = -EINVAL,
} GeneveDF;

const char *geneve_df_to_string(GeneveDF d) _const_;
GeneveDF geneve_df_from_string(const char *d) _pure_;
