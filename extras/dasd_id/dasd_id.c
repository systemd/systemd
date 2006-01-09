/*
 * dasdlabel - read label from s390 block device
 *
 * Copyright (C) 2004 Arnd Bergmann <arnd@arndb.de>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "../../udev.h"

#ifdef USE_LOG
void log_message(int priority, const char *format, ...)
{
	va_list args;
	static int udev_log = -1;

	if (udev_log == -1) {
		const char *value;

		value = getenv("UDEV_LOG");
		if (value)
			udev_log = log_priority(value);
		else
			udev_log = LOG_ERR;
	}

	if (priority > udev_log)
		return;

	va_start(args, format);
	vsyslog(priority, format, args);
	va_end(args);
}
#endif

/*
 * Only compile this on S/390. Doesn't make any sense
 * for other architectures.
 */

static unsigned char EBCtoASC[256] =
{
/* 0x00  NUL   SOH   STX   ETX  *SEL    HT  *RNL   DEL */
	0x00, 0x01, 0x02, 0x03, 0x07, 0x09, 0x07, 0x7F,
/* 0x08  -GE  -SPS  -RPT    VT    FF    CR    SO    SI */
	0x07, 0x07, 0x07, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
/* 0x10  DLE   DC1   DC2   DC3  -RES   -NL    BS  -POC
                                -ENP  ->LF             */
	0x10, 0x11, 0x12, 0x13, 0x07, 0x0A, 0x08, 0x07,
/* 0x18  CAN    EM  -UBS  -CU1  -IFS  -IGS  -IRS  -ITB
                                                  -IUS */
	0x18, 0x19, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
/* 0x20  -DS  -SOS    FS  -WUS  -BYP    LF   ETB   ESC
                                -INP                   */
	0x07, 0x07, 0x1C, 0x07, 0x07, 0x0A, 0x17, 0x1B,
/* 0x28  -SA  -SFE   -SM  -CSP  -MFA   ENQ   ACK   BEL
                     -SW                               */
	0x07, 0x07, 0x07, 0x07, 0x07, 0x05, 0x06, 0x07,
/* 0x30 ----  ----   SYN   -IR   -PP  -TRN  -NBS   EOT */
	0x07, 0x07, 0x16, 0x07, 0x07, 0x07, 0x07, 0x04,
/* 0x38 -SBS   -IT  -RFF  -CU3   DC4   NAK  ----   SUB */
	0x07, 0x07, 0x07, 0x07, 0x14, 0x15, 0x07, 0x1A,
/* 0x40   SP   RSP           ä              ----       */
	0x20, 0xFF, 0x83, 0x84, 0x85, 0xA0, 0x07, 0x86,
/* 0x48                      .     <     (     +     | */
	0x87, 0xA4, 0x9B, 0x2E, 0x3C, 0x28, 0x2B, 0x7C,
/* 0x50    &                                      ---- */
	0x26, 0x82, 0x88, 0x89, 0x8A, 0xA1, 0x8C, 0x07,
/* 0x58          ß     !     $     *     )     ;       */
	0x8D, 0xE1, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0xAA,
/* 0x60    -     /  ----     Ä  ----  ----  ----       */
	0x2D, 0x2F, 0x07, 0x8E, 0x07, 0x07, 0x07, 0x8F,
/* 0x68             ----     ,     %     _     >     ? */
	0x80, 0xA5, 0x07, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,
/* 0x70  ---        ----  ----  ----  ----  ----  ---- */
	0x07, 0x90, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
/* 0x78    *     `     :     #     @     '     =     " */
	0x70, 0x60, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,
/* 0x80    *     a     b     c     d     e     f     g */
	0x07, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
/* 0x88    h     i              ----  ----  ----       */
	0x68, 0x69, 0xAE, 0xAF, 0x07, 0x07, 0x07, 0xF1,
/* 0x90    °     j     k     l     m     n     o     p */
	0xF8, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
/* 0x98    q     r                    ----        ---- */
	0x71, 0x72, 0xA6, 0xA7, 0x91, 0x07, 0x92, 0x07,
/* 0xA0          ~     s     t     u     v     w     x */
	0xE6, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
/* 0xA8    y     z              ----  ----  ----  ---- */
	0x79, 0x7A, 0xAD, 0xAB, 0x07, 0x07, 0x07, 0x07,
/* 0xB0    ^                    ----     §  ----       */
	0x5E, 0x9C, 0x9D, 0xFA, 0x07, 0x07, 0x07, 0xAC,
/* 0xB8       ----     [     ]  ----  ----  ----  ---- */
	0xAB, 0x07, 0x5B, 0x5D, 0x07, 0x07, 0x07, 0x07,
/* 0xC0    {     A     B     C     D     E     F     G */
	0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
/* 0xC8    H     I  ----           ö              ---- */
	0x48, 0x49, 0x07, 0x93, 0x94, 0x95, 0xA2, 0x07,
/* 0xD0    }     J     K     L     M     N     O     P */
	0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
/* 0xD8    Q     R  ----           ü                   */
	0x51, 0x52, 0x07, 0x96, 0x81, 0x97, 0xA3, 0x98,
/* 0xE0    \           S     T     U     V     W     X */
	0x5C, 0xF6, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
/* 0xE8    Y     Z        ----     Ö  ----  ----  ---- */
	0x59, 0x5A, 0xFD, 0x07, 0x99, 0x07, 0x07, 0x07,
/* 0xF0    0     1     2     3     4     5     6     7 */
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
/* 0xF8    8     9  ----  ----     Ü  ----  ----  ---- */
	0x38, 0x39, 0x07, 0x07, 0x9A, 0x07, 0x07, 0x07
};

static void vtoc_ebcdic_dec (const unsigned char *source, unsigned char *target, int l) 
{
	int i;

	for (i = 0; i < l; i++) 
		target[i]=(char)EBCtoASC[(unsigned char)(source[i])];
}

/*
 * struct dasd_information_t
 * represents any data about the data, which is visible to userspace
 */
typedef struct dasd_information_t {
	unsigned int devno;		/* S/390 devno */
	unsigned int real_devno;	/* for aliases */
	unsigned int schid;		/* S/390 subchannel identifier */
	unsigned int cu_type  : 16;	/* from SenseID */
	unsigned int cu_model :  8;	/* from SenseID */
	unsigned int dev_type : 16;	/* from SenseID */
	unsigned int dev_model : 8;	/* from SenseID */
	unsigned int open_count;
	unsigned int req_queue_len;
	unsigned int chanq_len;		/* length of chanq */
	char type[4];			/* from discipline.name, 'none' for unknown */
	unsigned int status;		/* current device level */
	unsigned int label_block;	/* where to find the VOLSER */
	unsigned int FBA_layout;	/* fixed block size (like AIXVOL) */
	unsigned int characteristics_size;
	unsigned int confdata_size;
	char characteristics[64];	/* from read_device_characteristics */
	char configuration_data[256];	/* from read_configuration_data */
} dasd_information_t;

#define DASD_IOCTL_LETTER	 'D'
#define BIODASDINFO _IOR(DASD_IOCTL_LETTER,1,dasd_information_t)
#define BLKSSZGET _IO(0x12,104)

unsigned char serial[8];

static int dasd_id(int fd)
{
	int blocksize;
	dasd_information_t info;
	unsigned char *data;
	unsigned char *label_raw;

	if (ioctl(fd, BIODASDINFO, &info) != 0) {
		dbg("not a dasd");
		return -1;
	}

		if (ioctl(fd, BLKSSZGET, &blocksize) != 0) {
			err("failed to get blocksize");
			return -1;
		}

		if (lseek(fd,info.label_block * blocksize, SEEK_SET) == -1) {
			err("seek failed on dasd");
			return -1;
		}

		data = malloc(blocksize);
		if (data == NULL)
			return -1;

		if (read(fd, data, blocksize) == -1) {
			err("read disklabel failed");
			free(data);
			return -1;
		}

		if ((!info.FBA_layout) && (!strcmp(info.type, "ECKD")))
			label_raw = &data[8];
		else
			label_raw = &data[4];
		serial[6] = '\0';

		vtoc_ebcdic_dec(label_raw, serial, 6);
		free(data);

		return 0;
	}

int main(int argc, char *argv[])
{
	const char *node = NULL;
	int i;
	int export = 0;
	int fd;
	int rc = 0;

	logging_init("dasd_id");

	for (i = 1; i < argc; i++) {
		char *arg = argv[i];

		if (strcmp(arg, "--export") == 0) {
			export = 1;
		} else
			node = arg;
	}
	if (!node) {
		err("no node specified");
		rc = 1;
		goto exit;
	}

	fd = open(node, O_RDONLY);
	if (fd < 0) {
		err("unable to open '%s'", node);
		rc = 1;
		goto exit;
	}

	if (dasd_id(fd) < 0) {
		err("dasd_id failed: %s", strerror(errno));
		rc = 1;
	}

	if (export) {
		printf("ID_TYPE=disk\n");
		printf("ID_SERIAL=%s\n",serial);
		printf("ID_BUS=ccw\n");
	} else
		printf("%s\n", serial);

	close(fd);
exit:
	logging_close();
	return rc;
}

