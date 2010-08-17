/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foocgrouputilhfoo
#define foocgrouputilhfoo

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

#include <sys/types.h>
#include <stdio.h>
#include <dirent.h>

#include "set.h"

#define SYSTEMD_CGROUP_CONTROLLER "name=systemd"

int cg_enumerate_processes(const char *controller, const char *path, FILE **_f);
int cg_enumerate_tasks(const char *controller, const char *path, FILE **_f);
int cg_read_pid(FILE *f, pid_t *_pid);

int cg_enumerate_subgroups(const char *controller, const char *path, DIR **_d);
int cg_read_subgroup(DIR *d, char **fn);

int cg_kill(const char *controller, const char *path, int sig, bool ignore_self);
int cg_kill_recursive(const char *controller, const char *path, int sig, bool ignore_self, bool remove);
int cg_kill_recursive_and_wait(const char *controller, const char *path, bool remove);

int cg_migrate(const char *controller, const char *from, const char *to, bool ignore_self);
int cg_migrate_recursive(const char *controller, const char *from, const char *to, bool ignore_self, bool remove);

int cg_split_spec(const char *spec, char **controller, char **path);
int cg_join_spec(const char *controller, const char *path, char **spec);
int cg_fix_path(const char *path, char **result);

int cg_get_path(const char *controller, const char *path, const char *suffix, char **fs);
int cg_get_by_pid(const char *controller, pid_t pid, char **path);

int cg_trim(const char *controller, const char *path, bool delete_root);

int cg_rmdir(const char *controller, const char *path);
int cg_delete(const char *controller, const char *path);

int cg_create(const char *controller, const char *path);
int cg_attach(const char *controller, const char *path, pid_t pid);
int cg_create_and_attach(const char *controller, const char *path, pid_t pid);

int cg_set_group_access(const char *controller, const char *path, mode_t mode, uid_t uid, gid_t gid);
int cg_set_task_access(const char *controller, const char *path, mode_t mode, uid_t uid, gid_t gid);

int cg_install_release_agent(const char *controller, const char *agent);

int cg_is_empty(const char *controller, const char *path, bool ignore_self);
int cg_is_empty_recursive(const char *controller, const char *path, bool ignore_self);

#endif
