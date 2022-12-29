/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int sync_everything(void);

const char *get_efi_arch(void);

int get_file_version(int fd, char **ret);

int settle_entry_token(void);

static inline const char* get_conf_root(void)
{
        const char* conf_root = getenv("KERNEL_INSTALL_CONF_ROOT");
        if (conf_root)
                return conf_root;
        return "/etc/kernel/";
}
