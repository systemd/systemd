/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "cgroup-util.h"

bool cg_is_unified_wanted(void);
bool cg_is_legacy_wanted(void);
bool cg_is_hybrid_wanted(void);
bool cg_is_legacy_enabled(void);
bool cg_is_legacy_force_enabled(void);

int cg_weight_parse(const char *s, uint64_t *ret);
int cg_cpu_weight_parse(const char *s, uint64_t *ret);
int cg_cpu_shares_parse(const char *s, uint64_t *ret);
int cg_blkio_weight_parse(const char *s, uint64_t *ret);

int cg_trim(const char *controller, const char *path, bool delete_root);

int cg_create(const char *controller, const char *path);
int cg_attach(const char *controller, const char *path, pid_t pid);
int cg_fd_attach(int fd, pid_t pid);
int cg_attach_fallback(const char *controller, const char *path, pid_t pid);
int cg_create_and_attach(const char *controller, const char *path, pid_t pid);

int cg_set_access(const char *controller, const char *path, uid_t uid, gid_t gid);
int cg_set_access_recursive(const char *controller, const char *path, uid_t uid, gid_t gid);

int cg_create_everywhere(CGroupMask supported, CGroupMask mask, const char *path);
int cg_attach_everywhere(CGroupMask supported, const char *path, pid_t pid);
int cg_trim_everywhere(CGroupMask supported, const char *path, bool delete_root);
int cg_enable_everywhere(CGroupMask supported, CGroupMask mask, const char *p, CGroupMask *ret_result_mask);

int cg_migrate(const char *cfrom, const char *pfrom, const char *cto, const char *pto, CGroupFlags flags);

typedef const char* (*cg_migrate_callback_t)(CGroupMask mask, void *userdata);

/* CGroup V1 specific */
int cg_migrate_recursive(const char *cfrom, const char *pfrom, const char *cto, const char *pto, CGroupFlags flags);
int cg_migrate_recursive_fallback(const char *cfrom, const char *pfrom, const char *cto, const char *pto, CGroupFlags flags);
int cg_migrate_v1_controllers(CGroupMask supported, CGroupMask mask, const char *from, cg_migrate_callback_t to_callback, void *userdata);
int cg_trim_v1_controllers(CGroupMask supported, CGroupMask mask, const char *path, bool delete_root);

int cg_install_release_agent(const char *controller, const char *agent);
int cg_uninstall_release_agent(const char *controller);
