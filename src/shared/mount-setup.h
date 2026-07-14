/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

bool mount_point_is_api(const char *path) _pure_;
bool mount_point_ignore(const char *path) _pure_;

int mount_setup_early(void);
int mount_setup(bool loaded_policy, bool leave_propagation);

int mount_cgroupfs(const char *path);
