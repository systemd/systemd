/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Kay Sievers

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <locale.h>
#include <string.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <sys/timex.h>

#include "boot.h"
#include "boot-loader.h"
#include "build.h"
#include "util.h"
#include "strv.h"
#include "efivars.h"
#include "conf-files.h"

static char *tilt_slashes(char *s) {
        char *p;

        if (!s)
                return NULL;

        for (p = s; *p; p++)
                if (*p == '\\')
                        *p = '/';
        return s;
}

static int get_boot_entries(struct boot_info *info) {
        uint16_t *list = NULL;
        int i, n;
        int err = 0;

        n = efi_get_boot_options(&list);
        if (n < 0)
                return n;

        for (i = 0; i < n; i++) {
                struct boot_info_entry *e;

                e = realloc(info->fw_entries, (info->fw_entries_count+1) * sizeof(struct boot_info_entry));
                if (!e) {
                        err = -ENOMEM;
                                break;
                }
                info->fw_entries = e;

                e = &info->fw_entries[info->fw_entries_count];
                memzero(e, sizeof(struct boot_info_entry));
                e->order = -1;

                err = efi_get_boot_option(list[i], &e->title, &e->part_uuid, &e->path);
                if (err < 0)
                        continue;

                if (isempty(e->title)) {
                        free(e->title);
                        e->title = NULL;
                }
                tilt_slashes(e->path);

                e->id = list[i];
                info->fw_entries_count++;
        }

        free(list);
        return err;
}

static int find_active_entry(struct boot_info *info) {
        uint16_t boot_cur;
        void *buf;
        size_t l;
        size_t i;
        int err;

        err = efi_get_variable(EFI_VENDOR_GLOBAL, "BootCurrent", NULL, &buf, &l);
        if (err < 0)
                return err;

        memcpy(&boot_cur, buf, sizeof(uint16_t));
        for (i = 0; i < info->fw_entries_count; i++) {
                if (info->fw_entries[i].id != boot_cur)
                        continue;
                info->fw_entry_active = i;
                err = 0;
                break;
        }
        free(buf);
        return err;
}

static int get_boot_order(struct boot_info *info) {
        size_t i, k;
        int r;

        r = efi_get_boot_order(&info->fw_entries_order);
        if (r < 0)
                return r;

        info->fw_entries_order_count = r;

        for (i = 0; i < info->fw_entries_order_count; i++) {
                for (k = 0; k < info->fw_entries_count; k++) {
                        if (info->fw_entries[k].id != info->fw_entries_order[i])
                                continue;
                        info->fw_entries[k].order = i;
                        break;
                }
        }

        return 0;
}

static int entry_cmp(const void *a, const void *b) {
        const struct boot_info_entry *e1 = a;
        const struct boot_info_entry *e2 = b;

        /* boot order of active entries */
        if (e1->order > 0 && e2->order > 0)
                return e1->order - e2->order;

        /* sort active entries before inactive ones */
        if (e1->order > 0)
                return 1;
        if (e2->order > 0)
                return -1;

        /* order of inactive entries */
        return e1->id - e2->id;
}

int boot_info_query(struct boot_info *info) {
        char str[64];
        char buf[64];
        char *loader_active = NULL;

        info->fw_secure_boot = is_efi_secure_boot();
        info->fw_secure_boot_setup_mode = is_efi_secure_boot_setup_mode();

        efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderInfo", &info->loader);

        get_boot_entries(info);
        if (info->fw_entries_count > 0) {
                get_boot_order(info);
                qsort(info->fw_entries, info->fw_entries_count, sizeof(struct boot_info_entry), entry_cmp);
                find_active_entry(info);
        }

        efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderFirmwareType", &info->fw_type);
        efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderFirmwareInfo", &info->fw_info);
        efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderImageIdentifier", &info->loader_image_path);
        tilt_slashes(info->loader_image_path);
        efi_loader_get_device_part_uuid(&info->loader_part_uuid);

        boot_loader_read_entries(info);
        efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderEntrySelected", &loader_active);
        if (loader_active) {
                boot_loader_find_active_entry(info, loader_active);
                free(loader_active);
        }

        snprintf(str, sizeof(str), "LoaderEntryOptions-%s", sd_id128_to_string(info->machine_id, buf));
        efi_get_variable_string(EFI_VENDOR_LOADER, str, &info->loader_options_added);

        return 0;
}
