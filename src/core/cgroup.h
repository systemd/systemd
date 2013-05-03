/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

        /* When shutting down, remove cgroup? Are our own tasks the
         * only ones in this group?*/
        bool ours:1;

        /* If we cannot create this group, or add a process to it, is this fatal? */
        bool essential:1;

        /* This cgroup is realized */
        bool realized:1;
};

int cgroup_bonding_realize(CGroupBonding *b);
int cgroup_bonding_realize_list(CGroupBonding *first);

void cgroup_bonding_free(CGroupBonding *b, bool trim);
void cgroup_bonding_free_list(CGroupBonding *first, bool trim);

int cgroup_bonding_install(CGroupBonding *b, pid_t pid, const char *suffix);
int cgroup_bonding_install_list(CGroupBonding *first, pid_t pid, const char *suffix);

int cgroup_bonding_migrate(CGroupBonding *b, CGroupBonding *list);
int cgroup_bonding_migrate_to(CGroupBonding *b, const char *target, bool rem);

int cgroup_bonding_set_group_access(CGroupBonding *b, mode_t mode, uid_t uid, gid_t gid);
int cgroup_bonding_set_group_access_list(CGroupBonding *b, mode_t mode, uid_t uid, gid_t gid);

int cgroup_bonding_set_task_access(CGroupBonding *b, mode_t mode, uid_t uid, gid_t gid, int sticky);
int cgroup_bonding_set_task_access_list(CGroupBonding *b, mode_t mode, uid_t uid, gid_t gid, int sticky);

int cgroup_bonding_kill(CGroupBonding *b, int sig, bool sigcont, bool rem, Set *s, const char *suffix);
int cgroup_bonding_kill_list(CGroupBonding *first, int sig, bool sigcont, bool rem, Set *s, const char *suffix);

void cgroup_bonding_trim(CGroupBonding *first, bool delete_root);
void cgroup_bonding_trim_list(CGroupBonding *first, bool delete_root);

int cgroup_bonding_is_empty(CGroupBonding *b);
int cgroup_bonding_is_empty_list(CGroupBonding *first);

CGroupBonding *cgroup_bonding_find_list(CGroupBonding *first, const char *controller) _pure_;

char *cgroup_bonding_to_string(CGroupBonding *b);

pid_t cgroup_bonding_search_main_pid(CGroupBonding *b);
pid_t cgroup_bonding_search_main_pid_list(CGroupBonding *b);

#include "manager.h"

int manager_setup_cgroup(Manager *m);
void manager_shutdown_cgroup(Manager *m, bool delete);

int cgroup_bonding_get(Manager *m, const char *cgroup, CGroupBonding **bonding);
int cgroup_notify_empty(Manager *m, const char *group);

Unit* cgroup_unit_by_pid(Manager *m, pid_t pid);
