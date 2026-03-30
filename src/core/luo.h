/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int manager_luo_restore_fd_stores(Manager *m);
int manager_luo_process_held_fds(Manager *m);
int manager_luo_try_restore_held_fds_for_unit(Unit *u);
int manager_luo_serialize_held_fds(Manager *m, FILE *f, FDSet *fds);
int manager_luo_deserialize_held_fd(Manager *m, const char *value, FDSet *fds);
int manager_luo_serialize_fd_stores(Manager *m, FILE **ret_f, FDSet **ret_fds);
