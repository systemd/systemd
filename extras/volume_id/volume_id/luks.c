/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2005 W. Michael Petullo <mike@flyn.org>
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation; either
 *	version 2.1 of the License, or (at your option) any later version.
 *
 *	This library is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *	Lesser General Public License for more details.
 *
 *	You should have received a copy of the GNU Lesser General Public
 *	License along with this library; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <asm/types.h>

#include "volume_id.h"
#include "util.h"
#include "logging.h"
#include "luks.h"

#define SECTOR_SHIFT			9
#define SECTOR_SIZE			(1 << SECTOR_SHIFT)

#define LUKS_CIPHERNAME_L		32
#define LUKS_CIPHERMODE_L		32
#define LUKS_HASHSPEC_L			32
#define LUKS_DIGESTSIZE			20
#define LUKS_SALTSIZE			32
#define LUKS_NUMKEYS			8

const __u8 LUKS_MAGIC[] = {'L','U','K','S', 0xba, 0xbe};
#define LUKS_MAGIC_L 6
#define LUKS_PHDR_SIZE (sizeof(struct luks_phdr)/SECTOR_SIZE+1)
#define UUID_STRING_L 40

struct luks_phdr {
	__u8		magic[LUKS_MAGIC_L];
	__u16		version;
	__u8		cipherName[LUKS_CIPHERNAME_L];
	__u8		cipherMode[LUKS_CIPHERMODE_L];
	__u8		hashSpec[LUKS_HASHSPEC_L];
	__u32		payloadOffset;
	__u32		keyBytes;
	__u8		mkDigest[LUKS_DIGESTSIZE];
	__u8		mkDigestSalt[LUKS_SALTSIZE];
	__u32		mkDigestIterations;
	__u8		uuid[UUID_STRING_L];
	struct {
		__u32	active;
		__u32	passwordIterations;
		__u8		passwordSalt[LUKS_SALTSIZE];
		__u32	keyMaterialOffset;
		__u32	stripes;
	} keyblock[LUKS_NUMKEYS];
};

int volume_id_probe_luks(struct volume_id *id, __u64 off)
{
	struct luks_phdr *header;

	header = (struct luks_phdr*) volume_id_get_buffer(id, off, LUKS_PHDR_SIZE);
	if (header == NULL)
		return -1;

	if (memcmp(header->magic, LUKS_MAGIC, LUKS_MAGIC_L))
		return -1;

	volume_id_set_usage(id, VOLUME_ID_CRYPTO);
	volume_id_set_uuid(id, header->uuid, UUID_DCE_STRING);

	id->type = "crypto_LUKS";

	return 0;
}
