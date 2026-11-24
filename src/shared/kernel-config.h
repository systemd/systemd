/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int load_kernel_install_conf_at(
                const char *root,
                int root_fd,
                const char *conf_root,
                char **ret_machine_id,
                char **ret_boot_root,
                char **ret_layout,
                char **ret_initrd_generator,
                char **ret_uki_generator,
                char **ret_entry_name_format);
