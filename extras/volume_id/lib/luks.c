/*
 * volume_id - reads filesystem label and uuid
 *
 * Copyright (C) 2005 W. Michael Petullo <mike@flyn.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
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

#include "libvolume_id.h"
#include "util.h"

#define SECTOR_SHIFT			9
#define SECTOR_SIZE			(1 << SECTOR_SHIFT)

#define LUKS_CIPHERNAME_L		32
#define LUKS_CIPHERMODE_L		32
#define LUKS_HASHSPEC_L			32
#define LUKS_DIGESTSIZE			20
#define LUKS_SALTSIZE			32
#define LUKS_NUMKEYS			8

static const uint8_t LUKS_MAGIC[] = {'L','U','K','S', 0xba, 0xbe};
#define LUKS_MAGIC_L 6
#define LUKS_PHDR_SIZE (sizeof(struct luks_phdr)/SECTOR_SIZE+1)
#define UUID_STRING_L 40

struct luks_phdr {
	uint8_t		magic[LUKS_MAGIC_L];
	uint16_t	version;
	uint8_t		cipherName[LUKS_CIPHERNAME_L];
	uint8_t		cipherMode[LUKS_CIPHERMODE_L];
	uint8_t		hashSpec[LUKS_HASHSPEC_L];
	uint32_t	payloadOffset;
	uint32_t	keyBytes;
	uint8_t		mkDigest[LUKS_DIGESTSIZE];
	uint8_t		mkDigestSalt[LUKS_SALTSIZE];
	uint32_t	mkDigestIterations;
	uint8_t		uuid[UUID_STRING_L];
	struct {
		uint32_t	active;
		uint32_t	passwordIterations;
		uint8_t		passwordSalt[LUKS_SALTSIZE];
		uint32_t	keyMaterialOffset;
		uint32_t	stripes;
	} keyblock[LUKS_NUMKEYS];
};

int volume_id_probe_luks(struct volume_id *id, uint64_t off, uint64_t size)
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
