/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

int mount_setup_early(void);
int mount_setup(bool loaded_policy);

int mount_cgroup_controllers(char ***join_controllers);
int mount_resctrl(char *resctrl_options);

bool mount_point_is_api(const char *path);
bool mount_point_ignore(const char *path);
