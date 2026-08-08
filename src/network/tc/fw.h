/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "tfilter.h"

typedef struct FirewallFilter {
        TFilter meta;
} FirewallFilter;

DEFINE_TFILTER_CAST(FW, FirewallFilter);
extern const TFilterVTable fw_tfilter_vtable;
