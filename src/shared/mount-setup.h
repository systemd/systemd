/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

int mount_setup_early(void);
int mount_setup(bool loaded_policy, bool leave_propagation);

int mount_cgroup_controllers(void);

bool mount_point_is_api(const char *path);
bool mount_point_ignore(const char *path);
