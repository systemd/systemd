/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "oomd-util.h"
#include "sd-event.h"
#include "varlink.h"

/* Polling interval for monitoring stats */
#define INTERVAL_USEC (1 * USEC_PER_SEC)

/* Used to weight the averages */
#define AVERAGE_SIZE_DECAY 4

/* Take action if 10s of memory pressure > 60 for more than 30s. We use the "full" value from PSI so this is the
 * percentage of time all tasks were delayed (i.e. unproductive).
 * Generally 60 or higher might be acceptable for something like system.slice with no memory.high set; processes in
 * system.slice are assumed to be less latency sensitive. */
#define PRESSURE_DURATION_USEC (30 * USEC_PER_SEC)
#define DEFAULT_MEM_PRESSURE_LIMIT 60
#define DEFAULT_SWAP_USED_LIMIT 90

#define POST_ACTION_DELAY_USEC (15 * USEC_PER_SEC)

typedef struct Manager Manager;

struct Manager {
        sd_bus *bus;
        sd_event *event;

        Hashmap *polkit_registry;

        bool dry_run;
        unsigned swap_used_limit;
        loadavg_t default_mem_pressure_limit;

        /* k: cgroup paths -> v: OomdCGroupContext
         * Used to detect when to take action. */
        Hashmap *monitored_swap_cgroup_contexts;
        Hashmap *monitored_mem_pressure_cgroup_contexts;

        OomdSystemContext system_context;

        usec_t post_action_delay_start;

        sd_event_source *cgroup_context_event_source;

        Varlink *varlink;
};

void manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_new(Manager **ret);

int manager_start(Manager *m, bool dry_run, int swap_used_limit, int mem_pressure_limit);

int manager_get_dump_string(Manager *m, char **ret);

CONFIG_PARSER_PROTOTYPE(config_parse_oomd_default);
