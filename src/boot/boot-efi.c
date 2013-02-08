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

static int get_boot_entries(struct boot_info *info) {
        DIR *d = NULL;
        struct dirent *dent;
        int err = 0;

        d = opendir("/sys/firmware/efi/efivars");
        if (!d)
                return -errno;

        for (dent = readdir(d); dent != NULL; dent = readdir(d)) {
                unsigned int id;
                struct boot_info_entry *e;

                if (dent->d_name[0] == '.')
                        continue;
                if (sscanf(dent->d_name, "Boot%04X-8be4df61-93ca-11d2-aa0d-00e098032b8c", &id) != 1)
                        continue;

                e = realloc(info->fw_entries, (info->fw_entries_count+1) * sizeof(struct boot_info_entry));
                if (!e) {
                        err = -ENOMEM;
                        break;
                }
                info->fw_entries = e;

                e = &info->fw_entries[info->fw_entries_count];
                memset(e, 0, sizeof(struct boot_info_entry));
                e->order = -1;

                err = efi_get_boot_option(id, NULL, &e->title, &e->part_uuid, &e->path, &e->data, &e->data_size);
                if (err < 0)
                        break;
                e->id = id;

                info->fw_entries_count++;
        }
        closedir(d);

        return err;
}

static int find_active_entry(struct boot_info *info) {
        uint16_t boot_cur;
        void *buf;
        size_t l;
        size_t i;
        int err = -ENOENT;

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
        int err;

        err = efi_get_boot_order(&info->fw_entries_order, &info->fw_entries_order_count);
        if (err < 0)
                return err;

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
        char *loader_active;

        info->loader = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderInfo");

        get_boot_entries(info);
        if (info->fw_entries_count > 0) {
                get_boot_order(info);
                qsort(info->fw_entries, info->fw_entries_count, sizeof(struct boot_info_entry), entry_cmp);
                find_active_entry(info);
        }

        info->fw_type = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderFirmwareType");
        info->fw_info = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderFirmwareInfo");
        info->loader_image_path = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderImageIdentifier");
        efi_get_loader_device_part_uuid(&info->loader_part_uuid);

        boot_loader_read_entries(info);
        loader_active = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderEntrySelected");
        if (loader_active) {
                boot_loader_find_active_entry(info, loader_active);
                free(loader_active);
        }

        snprintf(str, sizeof(str), "LoaderEntryOptions-%s", sd_id128_to_string(info->machine_id, buf));
        info->loader_options_added = efi_get_variable_string(EFI_VENDOR_LOADER, str);
        return 0;
}
