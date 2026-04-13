/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "fd-util.h"
#include "shared-forward.h"

int load_kernel_install_conf_at(
                const char *root,
                int root_fd,
                const char *conf_root,
                char **ret_machine_id,
                char **ret_boot_root,
                char **ret_layout,
                char **ret_initrd_generator,
                char **ret_uki_generator);

static inline int load_kernel_install_conf(
                const char *root,
                const char *conf_root,
                char **ret_machine_id,
                char **ret_boot_root,
                char **ret_layout,
                char **ret_initrd_generator,
                char **ret_uki_generator) {

        return load_kernel_install_conf_at(root, XAT_FDROOT, conf_root, ret_machine_id, ret_boot_root, ret_layout, ret_initrd_generator, ret_uki_generator);
}
