/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdbool.h>

#include "list.h"
#include "time-util.h"

typedef struct CGroupContext CGroupContext;
typedef struct CGroupDeviceAllow CGroupDeviceAllow;
typedef struct CGroupBlockIODeviceWeight CGroupBlockIODeviceWeight;
typedef struct CGroupBlockIODeviceBandwidth CGroupBlockIODeviceBandwidth;

typedef enum CGroupDevicePolicy {

        /* When devices listed, will allow those, plus built-in ones,
        if none are listed will allow everything. */
        CGROUP_AUTO,

        /* Everything forbidden, except built-in ones and listed ones. */
        CGROUP_CLOSED,

        /* Everythings forbidden, except for the listed devices */
        CGROUP_STRICT,

        _CGROUP_DEVICE_POLICY_MAX,
        _CGROUP_DEVICE_POLICY_INVALID = -1
} CGroupDevicePolicy;

struct CGroupDeviceAllow {
        LIST_FIELDS(CGroupDeviceAllow, device_allow);
        char *path;
        bool r:1;
        bool w:1;
        bool m:1;
};

struct CGroupBlockIODeviceWeight {
        LIST_FIELDS(CGroupBlockIODeviceWeight, device_weights);
        char *path;
        unsigned long weight;
};

struct CGroupBlockIODeviceBandwidth {
        LIST_FIELDS(CGroupBlockIODeviceBandwidth, device_bandwidths);
        char *path;
        uint64_t bandwidth;
        bool read;
};

struct CGroupContext {
        bool cpu_accounting;
        bool blockio_accounting;
        bool memory_accounting;

        unsigned long cpu_shares;
        unsigned long startup_cpu_shares;
        usec_t cpu_quota_per_sec_usec;

        unsigned long blockio_weight;
        unsigned long startup_blockio_weight;
        LIST_HEAD(CGroupBlockIODeviceWeight, blockio_device_weights);
        LIST_HEAD(CGroupBlockIODeviceBandwidth, blockio_device_bandwidths);

        uint64_t memory_limit;

        CGroupDevicePolicy device_policy;
        LIST_HEAD(CGroupDeviceAllow, device_allow);

        bool delegate;
};

#include "unit.h"
#include "cgroup-util.h"

void cgroup_context_init(CGroupContext *c);
void cgroup_context_done(CGroupContext *c);
void cgroup_context_dump(CGroupContext *c, FILE* f, const char *prefix);
void cgroup_context_apply(CGroupContext *c, CGroupControllerMask mask, const char *path, ManagerState state);

CGroupControllerMask cgroup_context_get_mask(CGroupContext *c);

void cgroup_context_free_device_allow(CGroupContext *c, CGroupDeviceAllow *a);
void cgroup_context_free_blockio_device_weight(CGroupContext *c, CGroupBlockIODeviceWeight *w);
void cgroup_context_free_blockio_device_bandwidth(CGroupContext *c, CGroupBlockIODeviceBandwidth *b);

CGroupControllerMask unit_get_cgroup_mask(Unit *u);
CGroupControllerMask unit_get_siblings_mask(Unit *u);
CGroupControllerMask unit_get_members_mask(Unit *u);
CGroupControllerMask unit_get_target_mask(Unit *u);

void unit_update_cgroup_members_masks(Unit *u);
int unit_realize_cgroup(Unit *u);
void unit_destroy_cgroup_if_empty(Unit *u);
int unit_attach_pids_to_cgroup(Unit *u);

int manager_setup_cgroup(Manager *m);
void manager_shutdown_cgroup(Manager *m, bool delete);

unsigned manager_dispatch_cgroup_queue(Manager *m);

Unit *manager_get_unit_by_cgroup(Manager *m, const char *cgroup);
Unit* manager_get_unit_by_pid(Manager *m, pid_t pid);

pid_t unit_search_main_pid(Unit *u);

int manager_notify_cgroup_empty(Manager *m, const char *group);

int unit_get_memory_current(Unit *u, uint64_t *ret);
int unit_get_cpu_usage(Unit *u, nsec_t *ret);
int unit_reset_cpu_usage(Unit *u);

const char* cgroup_device_policy_to_string(CGroupDevicePolicy i) _const_;
CGroupDevicePolicy cgroup_device_policy_from_string(const char *s) _pure_;
