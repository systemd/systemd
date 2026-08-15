/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

int manager_notify_hook_filters(Manager *m);
int manager_varlink_init_resolve_hook(Manager *m, int fd);
