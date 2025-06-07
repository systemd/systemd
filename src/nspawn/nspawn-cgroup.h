/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "nspawn-settings.h"

int create_subcgroup(
                const PidRef *pid,
                bool keep_unit,
                uid_t uid_shift,
                int userns_fd,
                UserNamespaceMode userns_mode);

int mount_cgroups(const char *dest, bool accept_existing);
int bind_mount_cgroup_hierarchy(void);
