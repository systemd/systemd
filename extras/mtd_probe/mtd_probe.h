/*
 * Copyright (C) 2010 - Maxim Levitsky
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

#include <mtd/mtd-user.h>

/* Full oob structure as written on the flash */
struct sm_oob {
	uint32_t reserved;
	uint8_t data_status;
	uint8_t block_status;
	uint8_t lba_copy1[2];
	uint8_t ecc2[3];
	uint8_t lba_copy2[2];
	uint8_t ecc1[3];
} __attribute__((packed));


/* one sector is always 512 bytes, but it can consist of two nand pages */
#define SM_SECTOR_SIZE		512

/* oob area is also 16 bytes, but might be from two pages */
#define SM_OOB_SIZE		16

/* This is maximum zone size, and all devices that have more that one zone
   have this size */
#define SM_MAX_ZONE_SIZE 	1024

/* support for small page nand */
#define SM_SMALL_PAGE 		256
#define SM_SMALL_OOB_SIZE	8


void probe_smart_media(int mtd_fd, mtd_info_t *info);
