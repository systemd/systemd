/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct RdtGroup RdtGroup;

#include "rdtd.h"
#include "list.h"

#define GROUP_CONF_DIR          "/etc/systemd/rtd.d"
#define RDT_RUNTIME_DIR         "/run/systemd/rdt-groups"
#define RDT_STATIC_DIR          "/etc/systemd/rdtd.d"

#define RESCTRL_PATH            "/sys/fs/resctrl"
#define RESCTRL_PATH_INFO       RESCTRL_PATH"/info"
#define RESCTRL_TYPE_L3         "L3"

struct RdtGroup {
        Manager *manager;

        char *name; /* Group name */
        uint64_t l3_size; /* L3 cache size limit */
        char *l3_id; /* cache id */

        time_t mtime; /* Cached modification time */
        char *source; /* From where the config comes */
};

RdtGroup* group_new(Manager *m, const char *name);
void group_free(RdtGroup *d);

int rdt_scan_runtime_configs(Manager *m);
int rdt_scan_static_configs(Manager *m);
