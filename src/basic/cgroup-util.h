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

#include <sys/types.h>
#include <stdio.h>
#include <dirent.h>

#include "set.h"
#include "def.h"

/* An enum of well known cgroup controllers */
typedef enum CGroupController {
        CGROUP_CONTROLLER_CPU,
        CGROUP_CONTROLLER_CPUACCT,
        CGROUP_CONTROLLER_BLKIO,
        CGROUP_CONTROLLER_MEMORY,
        CGROUP_CONTROLLER_DEVICES,
        CGROUP_CONTROLLER_PIDS,
        CGROUP_CONTROLLER_NET_CLS,
        _CGROUP_CONTROLLER_MAX,
        _CGROUP_CONTROLLER_INVALID = -1,
} CGroupController;

#define CGROUP_CONTROLLER_TO_MASK(c) (1 << (c))

/* A bit mask of well known cgroup controllers */
typedef enum CGroupMask {
        CGROUP_MASK_CPU = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_CPU),
        CGROUP_MASK_CPUACCT = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_CPUACCT),
        CGROUP_MASK_BLKIO = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_BLKIO),
        CGROUP_MASK_MEMORY = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_MEMORY),
        CGROUP_MASK_DEVICES = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_DEVICES),
        CGROUP_MASK_PIDS = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_PIDS),
        CGROUP_MASK_NET_CLS = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_NET_CLS),
        _CGROUP_MASK_ALL = CGROUP_CONTROLLER_TO_MASK(_CGROUP_CONTROLLER_MAX) - 1
} CGroupMask;

/* Special values for the cpu.shares attribute */
#define CGROUP_CPU_SHARES_INVALID ((uint64_t) -1)
#define CGROUP_CPU_SHARES_MIN UINT64_C(2)
#define CGROUP_CPU_SHARES_MAX UINT64_C(262144)
#define CGROUP_CPU_SHARES_DEFAULT UINT64_C(1024)

static inline bool CGROUP_CPU_SHARES_IS_OK(uint64_t x) {
        return
            x == CGROUP_CPU_SHARES_INVALID ||
            (x >= CGROUP_CPU_SHARES_MIN && x <= CGROUP_CPU_SHARES_MAX);
}

/* Special values for the blkio.weight attribute */
#define CGROUP_BLKIO_WEIGHT_INVALID ((uint64_t) -1)
#define CGROUP_BLKIO_WEIGHT_MIN UINT64_C(10)
#define CGROUP_BLKIO_WEIGHT_MAX UINT64_C(1000)
#define CGROUP_BLKIO_WEIGHT_DEFAULT UINT64_C(500)

static inline bool CGROUP_BLKIO_WEIGHT_IS_OK(uint64_t x) {
        return
            x == CGROUP_BLKIO_WEIGHT_INVALID ||
            (x >= CGROUP_BLKIO_WEIGHT_MIN && x <= CGROUP_BLKIO_WEIGHT_MAX);
}

/*
 * General rules:
 *
 * We accept named hierarchies in the syntax "foo" and "name=foo".
 *
 * We expect that named hierarchies do not conflict in name with a
 * kernel hierarchy, modulo the "name=" prefix.
 *
 * We always generate "normalized" controller names, i.e. without the
 * "name=" prefix.
 *
 * We require absolute cgroup paths. When returning, we will always
 * generate paths with multiple adjacent / removed.
 */

int cg_enumerate_processes(const char *controller, const char *path, FILE **_f);
int cg_read_pid(FILE *f, pid_t *_pid);

int cg_enumerate_subgroups(const char *controller, const char *path, DIR **_d);
int cg_read_subgroup(DIR *d, char **fn);

int cg_kill(const char *controller, const char *path, int sig, bool sigcont, bool ignore_self, Set *s);
int cg_kill_recursive(const char *controller, const char *path, int sig, bool sigcont, bool ignore_self, bool remove, Set *s);

int cg_migrate(const char *cfrom, const char *pfrom, const char *cto, const char *pto, bool ignore_self);
int cg_migrate_recursive(const char *cfrom, const char *pfrom, const char *cto, const char *pto, bool ignore_self, bool remove);
int cg_migrate_recursive_fallback(const char *cfrom, const char *pfrom, const char *cto, const char *pto, bool ignore_self, bool rem);

int cg_split_spec(const char *spec, char **controller, char **path);
int cg_mangle_path(const char *path, char **result);

int cg_get_path(const char *controller, const char *path, const char *suffix, char **fs);
int cg_get_path_and_check(const char *controller, const char *path, const char *suffix, char **fs);

int cg_pid_get_path(const char *controller, pid_t pid, char **path);

int cg_trim(const char *controller, const char *path, bool delete_root);

int cg_rmdir(const char *controller, const char *path);

int cg_create(const char *controller, const char *path);
int cg_attach(const char *controller, const char *path, pid_t pid);
int cg_attach_fallback(const char *controller, const char *path, pid_t pid);
int cg_create_and_attach(const char *controller, const char *path, pid_t pid);

int cg_set_attribute(const char *controller, const char *path, const char *attribute, const char *value);
int cg_get_attribute(const char *controller, const char *path, const char *attribute, char **ret);

int cg_set_group_access(const char *controller, const char *path, mode_t mode, uid_t uid, gid_t gid);
int cg_set_task_access(const char *controller, const char *path, mode_t mode, uid_t uid, gid_t gid);

int cg_install_release_agent(const char *controller, const char *agent);
int cg_uninstall_release_agent(const char *controller);

int cg_is_empty(const char *controller, const char *path);
int cg_is_empty_recursive(const char *controller, const char *path);

int cg_get_root_path(char **path);

int cg_path_get_session(const char *path, char **session);
int cg_path_get_owner_uid(const char *path, uid_t *uid);
int cg_path_get_unit(const char *path, char **unit);
int cg_path_get_user_unit(const char *path, char **unit);
int cg_path_get_machine_name(const char *path, char **machine);
int cg_path_get_slice(const char *path, char **slice);
int cg_path_get_user_slice(const char *path, char **slice);

int cg_shift_path(const char *cgroup, const char *cached_root, const char **shifted);
int cg_pid_get_path_shifted(pid_t pid, const char *cached_root, char **cgroup);

int cg_pid_get_session(pid_t pid, char **session);
int cg_pid_get_owner_uid(pid_t pid, uid_t *uid);
int cg_pid_get_unit(pid_t pid, char **unit);
int cg_pid_get_user_unit(pid_t pid, char **unit);
int cg_pid_get_machine_name(pid_t pid, char **machine);
int cg_pid_get_slice(pid_t pid, char **slice);
int cg_pid_get_user_slice(pid_t pid, char **slice);

int cg_path_decode_unit(const char *cgroup, char **unit);

char *cg_escape(const char *p);
char *cg_unescape(const char *p) _pure_;

bool cg_controller_is_valid(const char *p);

int cg_slice_to_path(const char *unit, char **ret);

typedef const char* (*cg_migrate_callback_t)(CGroupMask mask, void *userdata);

int cg_create_everywhere(CGroupMask supported, CGroupMask mask, const char *path);
int cg_attach_everywhere(CGroupMask supported, const char *path, pid_t pid, cg_migrate_callback_t callback, void *userdata);
int cg_attach_many_everywhere(CGroupMask supported, const char *path, Set* pids, cg_migrate_callback_t callback, void *userdata);
int cg_migrate_everywhere(CGroupMask supported, const char *from, const char *to, cg_migrate_callback_t callback, void *userdata);
int cg_trim_everywhere(CGroupMask supported, const char *path, bool delete_root);
int cg_enable_everywhere(CGroupMask supported, CGroupMask mask, const char *p);

int cg_mask_supported(CGroupMask *ret);

int cg_kernel_controllers(Set *controllers);

int cg_unified(void);
void cg_unified_flush(void);

bool cg_is_unified_wanted(void);
bool cg_is_legacy_wanted(void);

const char* cgroup_controller_to_string(CGroupController c) _const_;
CGroupController cgroup_controller_from_string(const char *s) _pure_;

int cg_cpu_shares_parse(const char *s, uint64_t *ret);
int cg_blkio_weight_parse(const char *s, uint64_t *ret);
