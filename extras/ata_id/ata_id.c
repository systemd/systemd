/*
 * ata_id - reads product/serial number from ATA drives
 *
 * Copyright (C) 2005-2008 Kay Sievers <kay.sievers@vrfy.org>
 * Copyright (C) 2009 Lennart Poettering <lennart@poettering.net>
 * Copyright (C) 2009 David Zeuthen <zeuthen@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <scsi/scsi.h>
#include <scsi/sg.h>
#include <scsi/scsi_ioctl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/hdreg.h>
#include <linux/fs.h>
#include <linux/cdrom.h>
#include <arpa/inet.h>

#include "libudev.h"
#include "libudev-private.h"

#define COMMAND_TIMEOUT 2000

/* Sends a SCSI command block */
static int sg_io(int fd, int direction,
		 const void *cdb, size_t cdb_len,
		 void *data, size_t data_len,
		 void *sense, size_t sense_len)
{

	struct sg_io_hdr io_hdr;

	memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
	io_hdr.interface_id = 'S';
	io_hdr.cmdp = (unsigned char*) cdb;
	io_hdr.cmd_len = cdb_len;
	io_hdr.dxferp = data;
	io_hdr.dxfer_len = data_len;
	io_hdr.sbp = sense;
	io_hdr.mx_sb_len = sense_len;
	io_hdr.dxfer_direction = direction;
	io_hdr.timeout = COMMAND_TIMEOUT;
	return ioctl(fd, SG_IO, &io_hdr);
}

static int disk_command(int fd, int command, int direction, void *cmd_data,
			void *data, size_t *len)
{
	uint8_t *bytes = cmd_data;
	uint8_t cdb[12];
	uint8_t sense[32];
	uint8_t *desc = sense+8;
	int ret;

	/*
	 * ATA Pass-Through 12 byte command, as described in "T10 04-262r8
	 * ATA Command Pass-Through":
	 * http://www.t10.org/ftp/t10/document.04/04-262r8.pdf
	 */
	memset(cdb, 0, sizeof(cdb));
	cdb[0] = 0xa1; /* OPERATION CODE: 12 byte pass through */
	if (direction == SG_DXFER_NONE) {
		cdb[1] = 3 << 1;	/* PROTOCOL: Non-Data */
		cdb[2] = 0x20;		/* OFF_LINE=0, CK_COND=1, T_DIR=0, BYT_BLOK=0, T_LENGTH=0 */
	} else if (direction == SG_DXFER_FROM_DEV) {
		cdb[1] = 4 << 1;	/* PROTOCOL: PIO Data-in */
		cdb[2] = 0x2e;		/* OFF_LINE=0, CK_COND=1, T_DIR=1, BYT_BLOK=1, T_LENGTH=2 */
	} else if (direction == SG_DXFER_TO_DEV) {
		cdb[1] = 5 << 1;	/* PROTOCOL: PIO Data-Out */
		cdb[2] = 0x26;		/* OFF_LINE=0, CK_COND=1, T_DIR=0, BYT_BLOK=1, T_LENGTH=2 */
	}
	cdb[3] = bytes[1];		/* FEATURES */
	cdb[4] = bytes[3];		/* SECTORS */
	cdb[5] = bytes[9];		/* LBA LOW */
	cdb[6] = bytes[8];		/* LBA MID */
	cdb[7] = bytes[7];		/* LBA HIGH */
	cdb[8] = bytes[10] & 0x4F;	/* SELECT */
	cdb[9] = (uint8_t) command;
	memset(sense, 0, sizeof(sense));
	if ((ret = sg_io(fd, direction, cdb, sizeof(cdb), data, len ? *len : 0, sense, sizeof(sense))) < 0)
		return ret;
	if (sense[0] != 0x72 || desc[0] != 0x9 || desc[1] != 0x0c) {
		errno = EIO;
		return -1;
	}

	memset(bytes, 0, 12);
	bytes[1] = desc[3]; /* FEATURES */
	bytes[2] = desc[4]; /* STATUS */
	bytes[3] = desc[5]; /* SECTORS */
	bytes[9] = desc[7]; /* LBA LOW */
	bytes[8] = desc[9]; /* LBA MID */
	bytes[7] = desc[11]; /* LBA HIGH */
	bytes[10] = desc[12]; /* SELECT */
	bytes[11] = desc[13]; /* ERROR */
	return ret;
}

/**
 * disk_identify_get_string:
 * @identify: A block of IDENTIFY data
 * @offset_words: Offset of the string to get, in words.
 * @dest: Destination buffer for the string.
 * @dest_len: Length of destination buffer, in bytes.
 *
 * Copies the ATA string from @identify located at @offset_words into @dest.
 */
static void disk_identify_get_string (uint8_t identify[512],
				      unsigned int offset_words,
				      char *dest,
				      size_t dest_len)
{
	unsigned int c1;
	unsigned int c2;

	assert (identify != NULL);
	assert (dest != NULL);
	assert ((dest_len & 1) == 0);

	while (dest_len > 0) {
		c1 = ((uint16_t *) identify)[offset_words] >> 8;
		c2 = ((uint16_t *) identify)[offset_words] & 0xff;
		*dest = c1;
		dest++;
		*dest = c2;
		dest++;
		offset_words++;
		dest_len -= 2;
	}
}

static void disk_identify_fixup_string (uint8_t identify[512],
					unsigned int offset_words,
					size_t len)
{
	disk_identify_get_string(identify, offset_words,
				 (char *) identify + offset_words * 2, len);
}

static void disk_identify_fixup_uint16 (uint8_t identify[512], unsigned int offset_words)
{
	uint16_t *p;

	p = (uint16_t *) identify;
	p[offset_words] = le16toh (p[offset_words]);
}

/**
 * disk_identify:
 * @udev: The libudev context.
 * @fd: File descriptor for the block device.
 * @out_identify: Return location for IDENTIFY data.
 *
 * Sends the IDENTIFY DEVICE command to the device represented by
 * @fd. If successful, then the result will be copied into
 * @out_identify.
 *
 * This routine is based on code from libatasmart, Copyright 2008
 * Lennart Poettering, LGPL v2.1.
 *
 * Returns: 0 if the IDENTIFY data was successfully obtained,
 * otherwise non-zero with errno set.
 */
static int disk_identify (struct udev *udev,
			  int fd,
			  uint8_t out_identify[512])
{
	int ret;
	uint64_t size;
	struct stat st;
	uint16_t cmd[6];
	size_t len = 512;
	const uint8_t *p;

	assert (out_identify != NULL);

	/* init results */
	ret = -1;
	memset (out_identify, '\0', 512);

	if ((ret = fstat(fd, &st)) < 0)
		goto fail;

	if (!S_ISBLK(st.st_mode)) {
		errno = ENODEV;
		goto fail;
	}

	/*
	 * do not confuse optical drive firmware with ATA commands
	 * some drives are reported to blank CD-RWs
	 */
	if (ioctl(fd, CDROM_GET_CAPABILITY, NULL) >= 0) {
		errno = EIO;
		ret = -1;
		goto fail;
	}

	/* So, it's a block device. Let's make sure the ioctls work */
	if ((ret = ioctl(fd, BLKGETSIZE64, &size)) < 0)
		goto fail;

	if (size <= 0 || size == (uint64_t) -1) {
		errno = EIO;
		goto fail;
	}

	memset(cmd, 0, sizeof(cmd));
	cmd[1] = htons(1);
	ret = disk_command(fd,
			   0xEC, /* IDENTIFY DEVICE command */
			   SG_DXFER_FROM_DEV, cmd,
			   out_identify, &len);
	if (ret != 0)
		goto fail;

	if (len != 512) {
		errno = EIO;
		goto fail;
	}

	 /* Check if IDENTIFY data is all NULs */
	for (p = out_identify; p < (const uint8_t*) out_identify + len; p++) {
		if (*p) {
			p = NULL;
			break;
		}
	}

	if (p) {
		errno = EIO;
		goto fail;
	}

	ret = 0;
fail:
	return ret;
}

static void log_fn(struct udev *udev, int priority,
		   const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	vsyslog(priority, format, args);
}

int main(int argc, char *argv[])
{
	struct udev *udev;
	struct hd_driveid id;
	 uint8_t identify[512];
	char model[41];
	char model_enc[256];
	char serial[21];
	char revision[9];
	const char *node = NULL;
	int export = 0;
	int fd;
	 uint16_t word;
	int rc = 0;
	static const struct option options[] = {
		{ "export", no_argument, NULL, 'x' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};

	udev = udev_new();
	if (udev == NULL)
		goto exit;

	udev_log_init("ata_id");
	udev_set_log_fn(udev, log_fn);

	while (1) {
		int option;

		option = getopt_long(argc, argv, "xh", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'x':
			export = 1;
			break;
		case 'h':
			printf("Usage: ata_id [--export] [--help] <device>\n"
			       "  --export    print values as environment keys\n"
			       "  --help      print this help text\n\n");
		default:
			rc = 1;
			goto exit;
		}
	}

	node = argv[optind];
	if (node == NULL) {
		err(udev, "no node specified\n");
		rc = 1;
		goto exit;
	}

	fd = open(node, O_RDONLY|O_NONBLOCK);
	if (fd < 0) {
		err(udev, "unable to open '%s'\n", node);
		rc = 1;
		goto exit;
	}

	if (disk_identify(udev, fd, identify) == 0) {
		/*
		 * fix up only the fields from the IDENTIFY data that we are going to
		 * use and copy it into the hd_driveid struct for convenience
		 */
		disk_identify_fixup_string (identify,  10, 20);	/* serial */
		disk_identify_fixup_string (identify,  23,  6);	/* fwrev */
		disk_identify_fixup_string (identify,  27, 40);	/* model */
		disk_identify_fixup_uint16 (identify,   0);	/* configuration */
		disk_identify_fixup_uint16 (identify,  75);	/* queue depth */
		disk_identify_fixup_uint16 (identify,  75);	/* SATA capabilities */
		disk_identify_fixup_uint16 (identify,  82);	/* command set supported */
		disk_identify_fixup_uint16 (identify,  83);	/* command set supported */
		disk_identify_fixup_uint16 (identify,  84);	/* command set supported */
		disk_identify_fixup_uint16 (identify,  85);	/* command set supported */
		disk_identify_fixup_uint16 (identify,  86);	/* command set supported */
		disk_identify_fixup_uint16 (identify,  87);	/* command set supported */
		disk_identify_fixup_uint16 (identify,  89);	/* time required for SECURITY ERASE UNIT */
		disk_identify_fixup_uint16 (identify,  90);	/* time required for enhanced SECURITY ERASE UNIT */
		disk_identify_fixup_uint16 (identify,  91);	/* current APM values */
		disk_identify_fixup_uint16 (identify,  94);	/* current AAM value */
		disk_identify_fixup_uint16 (identify, 128);	/* device lock function */
		disk_identify_fixup_uint16 (identify, 217);	/* nominal media rotation rate */
		memcpy(&id, identify, sizeof id);
	} else {
		/* If this fails, then try HDIO_GET_IDENTITY */
		if (ioctl(fd, HDIO_GET_IDENTITY, &id) != 0) {
			if (errno == ENOTTY) {
				info(udev, "HDIO_GET_IDENTITY unsupported for '%s'\n", node);
				rc = 2;
			} else {
				err(udev, "HDIO_GET_IDENTITY failed for '%s'\n", node);
				rc = 3;
			}
			goto close;
		}
	}

	memcpy (model, id.model, 40);
	model[40] = '\0';
	udev_util_encode_string(model, model_enc, sizeof(model_enc));
	udev_util_replace_whitespace((char *) id.model, model, 40);
	udev_util_replace_chars(model, NULL);
	udev_util_replace_whitespace((char *) id.serial_no, serial, 20);
	udev_util_replace_chars(serial, NULL);
	udev_util_replace_whitespace((char *) id.fw_rev, revision, 8);
	udev_util_replace_chars(revision, NULL);

	if (export) {
		  /* Set this to convey the disk speaks the ATA protocol */
		  printf("ID_ATA=1\n");

		if ((id.config >> 8) & 0x80) {
			/* This is an ATAPI device */
			switch ((id.config >> 8) & 0x1f) {
			case 0:
				printf("ID_TYPE=cd\n");
				break;
			case 1:
				printf("ID_TYPE=tape\n");
				break;
			case 5:
				printf("ID_TYPE=cd\n");
				break;
			case 7:
				printf("ID_TYPE=optical\n");
				break;
			default:
				printf("ID_TYPE=generic\n");
				break;
			}
		} else {
			printf("ID_TYPE=disk\n");
		}
		printf("ID_BUS=ata\n");
		printf("ID_MODEL=%s\n", model);
		printf("ID_MODEL_ENC=%s\n", model_enc);
		printf("ID_REVISION=%s\n", revision);
		printf("ID_SERIAL=%s_%s\n", model, serial);
		printf("ID_SERIAL_SHORT=%s\n", serial);

		if (id.command_set_1 & (1<<5)) {
			printf ("ID_ATA_WRITE_CACHE=1\n");
			printf ("ID_ATA_WRITE_CACHE_ENABLED=%d\n", (id.cfs_enable_1 & (1<<5)) ? 1 : 0);
		}
		if (id.command_set_1 & (1<<10)) {
			printf("ID_ATA_FEATURE_SET_HPA=1\n");
			printf("ID_ATA_FEATURE_SET_HPA_ENABLED=%d\n", (id.cfs_enable_1 & (1<<10)) ? 1 : 0);

			/*
			 * TODO: use the READ NATIVE MAX ADDRESS command to get the native max address
			 * so it is easy to check whether the protected area is in use.
			 */
		}
		if (id.command_set_1 & (1<<3)) {
			printf("ID_ATA_FEATURE_SET_PM=1\n");
			printf("ID_ATA_FEATURE_SET_PM_ENABLED=%d\n", (id.cfs_enable_1 & (1<<3)) ? 1 : 0);
		}
		if (id.command_set_1 & (1<<1)) {
			printf("ID_ATA_FEATURE_SET_SECURITY=1\n");
			printf("ID_ATA_FEATURE_SET_SECURITY_ENABLED=%d\n", (id.cfs_enable_1 & (1<<1)) ? 1 : 0);
			printf("ID_ATA_FEATURE_SET_SECURITY_ERASE_UNIT_MIN=%d\n", id.trseuc * 2);
			if ((id.cfs_enable_1 & (1<<1))) /* enabled */ {
				if (id.dlf & (1<<8))
					printf("ID_ATA_FEATURE_SET_SECURITY_LEVEL=maximum\n");
				else
					printf("ID_ATA_FEATURE_SET_SECURITY_LEVEL=high\n");
			}
			if (id.dlf & (1<<5))
				printf("ID_ATA_FEATURE_SET_SECURITY_ENHANCED_ERASE_UNIT_MIN=%d\n", id.trsEuc * 2);
			if (id.dlf & (1<<4))
				printf("ID_ATA_FEATURE_SET_SECURITY_EXPIRE=1\n");
			if (id.dlf & (1<<3))
				printf("ID_ATA_FEATURE_SET_SECURITY_FROZEN=1\n");
			if (id.dlf & (1<<2))
				printf("ID_ATA_FEATURE_SET_SECURITY_LOCKED=1\n");
		}
		if (id.command_set_1 & (1<<0)) {
			printf("ID_ATA_FEATURE_SET_SMART=1\n");
			printf("ID_ATA_FEATURE_SET_SMART_ENABLED=%d\n", (id.cfs_enable_1 & (1<<0)) ? 1 : 0);
		}
		if (id.command_set_2 & (1<<9)) {
			printf("ID_ATA_FEATURE_SET_AAM=1\n");
			printf("ID_ATA_FEATURE_SET_AAM_ENABLED=%d\n", (id.cfs_enable_2 & (1<<9)) ? 1 : 0);
			printf("ID_ATA_FEATURE_SET_AAM_VENDOR_RECOMMENDED_VALUE=%d\n", id.acoustic >> 8);
			printf("ID_ATA_FEATURE_SET_AAM_CURRENT_VALUE=%d\n", id.acoustic & 0xff);
		}
		if (id.command_set_2 & (1<<5)) {
			printf("ID_ATA_FEATURE_SET_PUIS=1\n");
			printf("ID_ATA_FEATURE_SET_PUIS_ENABLED=%d\n", (id.cfs_enable_2 & (1<<5)) ? 1 : 0);
		}
		if (id.command_set_2 & (1<<3)) {
			printf("ID_ATA_FEATURE_SET_APM=1\n");
			printf("ID_ATA_FEATURE_SET_APM_ENABLED=%d\n", (id.cfs_enable_2 & (1<<3)) ? 1 : 0);
			if ((id.cfs_enable_2 & (1<<3)))
				printf("ID_ATA_FEATURE_SET_APM_CURRENT_VALUE=%d\n", id.CurAPMvalues & 0xff);
		}
		if (id.command_set_2 & (1<<0))
			printf("ID_ATA_DOWNLOAD_MICROCODE=1\n");

		/*
		 * Word 76 indicates the capabilities of a SATA device. A PATA device shall set
		 * word 76 to 0000h or FFFFh. If word 76 is set to 0000h or FFFFh, then
		 * the device does not claim compliance with the Serial ATA specification and words
		 * 76 through 79 are not valid and shall be ignored.
		 */
		word = *((uint16_t *) identify + 76);
		if (word != 0x0000 && word != 0xffff) {
			printf("ID_ATA_SATA=1\n");
			/*
			 * If bit 2 of word 76 is set to one, then the device supports the Gen2
			 * signaling rate of 3.0 Gb/s (see SATA 2.6).
			 *
			 * If bit 1 of word 76 is set to one, then the device supports the Gen1
			 * signaling rate of 1.5 Gb/s (see SATA 2.6).
			 */
			if (word & (1<<2))
				printf("ID_ATA_SATA_SIGNAL_RATE_GEN2=1\n");
			if (word & (1<<1))
				printf("ID_ATA_SATA_SIGNAL_RATE_GEN1=1\n");
		}

		/* Word 217 indicates the nominal media rotation rate of the device */
		word = *((uint16_t *) identify + 217);
		if (word != 0x0000) {
			if (word == 0x0001) {
				printf ("ID_ATA_ROTATION_RATE_RPM=0\n"); /* non-rotating e.g. SSD */
			} else if (word >= 0x0401 && word <= 0xfffe) {
				printf ("ID_ATA_ROTATION_RATE_RPM=%d\n", word);
			}
		}

		/*
		 * Words 108-111 contain a mandatory World Wide Name (WWN) in the NAA IEEE Registered identifier
		 * format. Word 108 bits (15:12) shall contain 5h, indicating that the naming authority is IEEE.
		 * All other values are reserved.
		 */
		word = *((uint16_t *) identify + 108);
		if ((word & 0xf000) == 0x5000) {
			uint64_t wwwn;

			wwwn   = *((uint16_t *) identify + 108);
			wwwn <<= 16;
			wwwn  |= *((uint16_t *) identify + 109);
			wwwn <<= 16;
			wwwn  |= *((uint16_t *) identify + 110);
			wwwn <<= 16;
			wwwn  |= *((uint16_t *) identify + 111);
			printf("ID_WWN=0x%llx\n", (unsigned long long int) wwwn);
			/* ATA devices have no vendor extension */
			printf("ID_WWN_WITH_EXTENSION=0x%llx\n", (unsigned long long int) wwwn);
		}
	} else {
		if (serial[0] != '\0')
			printf("%s_%s\n", model, serial);
		else
			printf("%s\n", model);
	}
close:
	close(fd);
exit:
	udev_unref(udev);
	udev_log_close();
	return rc;
}
