/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int manager_luo_restore_fd_stores(Manager *m);
int manager_luo_serialize_fd_stores(Manager *m, FILE **ret_f, FDSet **ret_fds);
