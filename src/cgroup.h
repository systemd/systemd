/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foocgrouphfoo
#define foocgrouphfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

typedef struct CGroupBonding CGroupBonding;

#include "unit.h"

/* Binds a cgroup to a name */
struct CGroupBonding {
        char *controller;
        char *path;

        Unit *unit;

        /* For the Unit::cgroup_bondings list */
        LIST_FIELDS(CGroupBonding, by_unit);

        /* For the Manager::cgroup_bondings hashmap */
        LIST_FIELDS(CGroupBonding, by_path);

        /* When shutting down, remove cgroup? */
        bool clean_up:1;

        /* When our tasks are the only ones in this group */
        bool only_us:1;

        /* This cgroup is realized */
        bool realized:1;
};

int cgroup_bonding_realize(CGroupBonding *b);
int cgroup_bonding_realize_list(CGroupBonding *first);

void cgroup_bonding_free(CGroupBonding *b);
void cgroup_bonding_free_list(CGroupBonding *first);

int cgroup_bonding_install(CGroupBonding *b, pid_t pid);
int cgroup_bonding_install_list(CGroupBonding *first, pid_t pid);

int cgroup_bonding_kill(CGroupBonding *b, int sig);
int cgroup_bonding_kill_list(CGroupBonding *first, int sig);

int cgroup_bonding_is_empty(CGroupBonding *b);
int cgroup_bonding_is_empty_list(CGroupBonding *first);

CGroupBonding *cgroup_bonding_find_list(CGroupBonding *first, const char *controller);

char *cgroup_bonding_to_string(CGroupBonding *b);

#include "manager.h"

int manager_setup_cgroup(Manager *m);
int manager_shutdown_cgroup(Manager *m);

int cgroup_notify_empty(Manager *m, const char *group);

Unit* cgroup_unit_by_pid(Manager *m, pid_t pid);

#endif
