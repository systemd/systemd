/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "rdtd-group.h"

typedef struct ResctrlAllocSchemata ResctrlAllocSchemata;

struct ResctrlAllocSchemata {
        uint64_t *bits_mask; /* cache bit mask array */
        unsigned int max_ids; /* max socket id */
};

int resctrl_lock(void);
int resctrl_unlock(int fd);
int resctrl_get_l3_info(RdtInfoL3 *l3_info, const char *type);
int resctrl_alloc_group_remove(const char *name);
int resctrl_update_schemata(RdtGroup *g);
