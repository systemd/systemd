/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2010 - Maxim Levitsky
 *
 * mtd_probe is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * mtd_probe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with mtd_probe; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301  USA
 */

#include <errno.h>
#include <fcntl.h>
#include <mtd/mtd-user.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "mtd_probe.h"

static const uint8_t cis_signature[] = {
        0x01, 0x03, 0xD9, 0x01, 0xFF, 0x18, 0x02, 0xDF, 0x01, 0x20
};

int probe_smart_media(int mtd_fd, mtd_info_t* info) {
        int sector_size;
        int block_size;
        int size_in_megs;
        int spare_count;
        _cleanup_free_ uint8_t *cis_buffer = NULL;
        int offset;
        int cis_found = 0;

        cis_buffer = malloc(SM_SECTOR_SIZE);
        if (!cis_buffer)
                return log_oom();

        if (info->type != MTD_NANDFLASH)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Not marked MTD_NANDFLASH.");

        sector_size = info->writesize;
        block_size = info->erasesize;
        size_in_megs = info->size / (1024 * 1024);

        if (!IN_SET(sector_size, SM_SECTOR_SIZE, SM_SMALL_PAGE))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Unexpected sector size: %i", sector_size);

        switch (size_in_megs) {
        case 1:
        case 2:
                spare_count = 6;
                break;
        case 4:
                spare_count = 12;
                break;
        default:
                spare_count = 24;
                break;
        }

        for (offset = 0; offset < block_size * spare_count; offset += sector_size) {
                (void) lseek(mtd_fd, SEEK_SET, offset);

                if (read(mtd_fd, cis_buffer, SM_SECTOR_SIZE) == SM_SECTOR_SIZE) {
                        cis_found = 1;
                        break;
                }
        }

        if (!cis_found)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "CIS not found");

        if (memcmp(cis_buffer, cis_signature, sizeof(cis_signature)) != 0 &&
            memcmp(cis_buffer + SM_SMALL_PAGE, cis_signature, sizeof(cis_signature)) != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "CIS signature didn't match");

        printf("MTD_FTL=smartmedia\n");
        return 0;
}
