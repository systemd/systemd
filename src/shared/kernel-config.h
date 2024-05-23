/* SPDX-License-Identifier: LGPL-2.1-or-later */

int load_kernel_install_conf(
                const char *root,
                const char *conf_root,
                char **ret_machine_id,
                char **ret_boot_root,
                char **ret_layout,
                char **ret_initrd_generator,
                char **ret_uki_generator);
