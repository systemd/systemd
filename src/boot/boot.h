/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include "sd-id128.h"

/*
 * Firmware and boot manager information to be filled in
 * by the platform.
 *
 * This is partly EFI specific, if you add things, keep this
 * as generic as possible to be able to re-use it on other
 * platforms.
 */

struct boot_info_entry {
        uint16_t id;
        uint16_t order;
        char *title;
        sd_id128_t part_uuid;
        char *path;
};

struct boot_info {
        sd_id128_t machine_id;
        sd_id128_t boot_id;
        char *fw_type;
        char *fw_info;
        int fw_secure_boot;
        int fw_secure_boot_setup_mode;
        struct boot_info_entry *fw_entries;
        size_t fw_entries_count;
        uint16_t *fw_entries_order;
        size_t fw_entries_order_count;
        ssize_t fw_entry_active;
        char *loader;
        char *loader_image_path;
        sd_id128_t loader_part_uuid;
        struct boot_info_entry *loader_entries;
        size_t loader_entries_count;
        ssize_t loader_entry_active;
        char *loader_options_added;
};

int boot_info_query(struct boot_info *info);
