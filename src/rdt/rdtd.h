/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-event.h"

#include "conf-parser.h"
#include "hashmap.h"
#include "list.h"
#include "set.h"

typedef struct Manager Manager;

#include "rdtd-info.h"
#include "rdtd-group.h"

struct Manager {
        sd_event *event;

        RdtInfo *rdtinfo;
        Hashmap *groups;
};

int rdtd_parse_config(void);
int manager_get_rdtinfo(Manager *m);
int manager_enumerate_groups(Manager *m);

/* gperf lookup function */
const struct ConfigPerfItem* rdtd_gperf_lookup(const char *key, GPERF_LEN_TYPE length);
