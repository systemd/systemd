/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "conf-parser.h"
#include "kernel-config.h"
#include "macro.h"
#include "path-util.h"
#include "strv.h"

int load_kernel_install_conf(
                const char *root,
                const char *conf_root,
                char **ret_machine_id,
                char **ret_boot_root,
                char **ret_layout,
                char **ret_initrd_generator,
                char **ret_uki_generator) {

        _cleanup_free_ char *machine_id = NULL, *boot_root = NULL, *layout = NULL,
                            *initrd_generator = NULL, *uki_generator = NULL;
        const ConfigTableItem items[] = {
                { NULL, "MACHINE_ID",       config_parse_string, 0, &machine_id       },
                { NULL, "BOOT_ROOT",        config_parse_string, 0, &boot_root        },
                { NULL, "layout",           config_parse_string, 0, &layout           },
                { NULL, "initrd_generator", config_parse_string, 0, &initrd_generator },
                { NULL, "uki_generator",    config_parse_string, 0, &uki_generator    },
                {}
        };
        int r;

        if (conf_root) {
                _cleanup_free_ char *conf = path_join(conf_root, "install.conf");
                if (!conf)
                        return log_oom();

                r = config_parse_many(
                                STRV_MAKE_CONST(conf),
                                STRV_MAKE_CONST(conf_root),
                                "install.conf.d",
                                /* root= */ NULL, /* $KERNEL_INSTALL_CONF_ROOT and --root are independent */
                                /* sections= */ NULL,
                                config_item_table_lookup, items,
                                CONFIG_PARSE_WARN,
                                /* userdata= */ NULL,
                                /* ret_stats_by_path= */ NULL,
                                /* ret_dropin_files= */ NULL);
        } else
                r = config_parse_standard_file_with_dropins_full(
                                root,
                                "kernel/install.conf",
                                /* sections= */ NULL,
                                config_item_table_lookup, items,
                                CONFIG_PARSE_WARN,
                                /* userdata= */ NULL,
                                /* ret_stats_by_path= */ NULL,
                                /* ret_dropin_files= */ NULL);
        if (r < 0 && r != -ENOENT)
                return r;

        if (ret_machine_id)
                *ret_machine_id = TAKE_PTR(machine_id);
        if (ret_boot_root)
                *ret_boot_root = TAKE_PTR(boot_root);
        if (ret_layout)
                *ret_layout = TAKE_PTR(layout);
        if (ret_initrd_generator)
                *ret_initrd_generator = TAKE_PTR(initrd_generator);
        if (ret_uki_generator)
                *ret_uki_generator = TAKE_PTR(uki_generator);
        return r >= 0;  /* Return 0 if we got -ENOENT above, 1 otherwise. */
}
