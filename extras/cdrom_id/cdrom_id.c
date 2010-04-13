/*
 * cdrom_id - optical drive and media information prober
 *
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <scsi/sg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <linux/cdrom.h>

#include "libudev.h"
#include "libudev-private.h"

static int debug;

static void log_fn(struct udev *udev, int priority,
		   const char *file, int line, const char *fn,
		   const char *format, va_list args)
{
	if (debug) {
		fprintf(stderr, "%s: ", fn);
		vfprintf(stderr, format, args);
	} else {
		vsyslog(priority, format, args);
	}
}

/* device info */
static unsigned int cd_cd_rom = 0;
static unsigned int cd_cd_r = 0;
static unsigned int cd_cd_rw = 0;
static unsigned int cd_dvd_rom = 0;
static unsigned int cd_dvd_r = 0;
static unsigned int cd_dvd_rw = 0;
static unsigned int cd_dvd_ram = 0;
static unsigned int cd_dvd_plus_r = 0;
static unsigned int cd_dvd_plus_rw = 0;
static unsigned int cd_dvd_plus_r_dl = 0;
static unsigned int cd_dvd_plus_rw_dl = 0;
static unsigned int cd_bd = 0;
static unsigned int cd_bd_r = 0;
static unsigned int cd_bd_re = 0;
static unsigned int cd_hddvd = 0;
static unsigned int cd_hddvd_r = 0;
static unsigned int cd_hddvd_rw = 0;
static unsigned int cd_mo = 0;
static unsigned int cd_mrw = 0;
static unsigned int cd_mrw_w = 0;

/* media info */
static unsigned int cd_media = 0;
static unsigned int cd_media_cd_rom = 0;
static unsigned int cd_media_cd_r = 0;
static unsigned int cd_media_cd_rw = 0;
static unsigned int cd_media_dvd_rom = 0;
static unsigned int cd_media_dvd_r = 0;
static unsigned int cd_media_dvd_rw = 0;
static unsigned int cd_media_dvd_ram = 0;
static unsigned int cd_media_dvd_plus_r = 0;
static unsigned int cd_media_dvd_plus_rw = 0;
static unsigned int cd_media_dvd_plus_r_dl = 0;
static unsigned int cd_media_dvd_plus_rw_dl = 0;
static unsigned int cd_media_bd = 0;
static unsigned int cd_media_bd_r = 0;
static unsigned int cd_media_bd_re = 0;
static unsigned int cd_media_hddvd = 0;
static unsigned int cd_media_hddvd_r = 0;
static unsigned int cd_media_hddvd_rw = 0;
static unsigned int cd_media_mo = 0;
static unsigned int cd_media_mrw = 0;
static unsigned int cd_media_mrw_w = 0;

static const char *cd_media_state = NULL;
static unsigned int cd_media_session_next = 0;
static unsigned int cd_media_session_count = 0;
static unsigned int cd_media_track_count = 0;
static unsigned int cd_media_track_count_data = 0;
static unsigned int cd_media_track_count_audio = 0;
static unsigned long long int cd_media_session_last_offset = 0;

#define ERRCODE(s)	((((s)[2] & 0x0F) << 16) | ((s)[12] << 8) | ((s)[13]))
#define SK(errcode)	(((errcode) >> 16) & 0xF)
#define ASC(errcode)	(((errcode) >> 8) & 0xFF)
#define ASCQ(errcode)	((errcode) & 0xFF)

static int is_mounted(const char *device)
{
	struct stat statbuf;
	FILE *fp;
	int maj, min;
	int mounted = 0;

	if (stat(device, &statbuf) < 0)
		return -ENODEV;

	fp = fopen("/proc/self/mountinfo", "r");
	if (fp == NULL)
		return -ENOSYS;
	while (fscanf(fp, "%*s %*s %i:%i %*[^\n]", &maj, &min) == 2) {
		if (makedev(maj, min) == statbuf.st_rdev) {
			mounted = 1;
			break;
		}
	}
	fclose(fp);
	return mounted;
}

static void info_scsi_cmd_err(struct udev *udev, char *cmd, int err)
{
	if (err == -1) {
		info(udev, "%s failed\n", cmd);
		return;
	}
	info(udev, "%s failed with SK=%Xh/ASC=%02Xh/ACQ=%02Xh\n", cmd, SK(err), ASC(err), ASCQ(err));
}

struct scsi_cmd {
	struct cdrom_generic_command cgc;
	union {
		struct request_sense s;
		unsigned char u[18];
	} _sense;
	struct sg_io_hdr sg_io;
};

static void scsi_cmd_set(struct udev *udev, struct scsi_cmd *cmd, size_t i, int arg)
{
	if (i == 0) {
		memset(cmd, 0x00, sizeof(struct scsi_cmd));
		cmd->cgc.quiet = 1;
		cmd->cgc.sense = &cmd->_sense.s;
		memset(&cmd->sg_io, 0, sizeof(cmd->sg_io));
		cmd->sg_io.interface_id = 'S';
		cmd->sg_io.mx_sb_len = sizeof(cmd->_sense);
		cmd->sg_io.cmdp = cmd->cgc.cmd;
		cmd->sg_io.sbp = cmd->_sense.u;
		cmd->sg_io.flags = SG_FLAG_LUN_INHIBIT | SG_FLAG_DIRECT_IO;
	}
	cmd->sg_io.cmd_len = i + 1;
	cmd->cgc.cmd[i] = arg;
}

#define CHECK_CONDITION 0x01

static int scsi_cmd_run(struct udev *udev, struct scsi_cmd *cmd, int fd, unsigned char *buf, size_t bufsize)
{
	int ret = 0;

	cmd->sg_io.dxferp = buf;
	cmd->sg_io.dxfer_len = bufsize;
	cmd->sg_io.dxfer_direction = SG_DXFER_FROM_DEV;
	if (ioctl(fd, SG_IO, &cmd->sg_io))
		return -1;

	if ((cmd->sg_io.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
		errno = EIO;
		ret = -1;
		if (cmd->sg_io.masked_status & CHECK_CONDITION) {
			ret = ERRCODE(cmd->_sense.u);
			if (ret == 0)
				ret = -1;
		}
	}
	return ret;
}

static int cd_capability_compat(struct udev *udev, int fd)
{
	int capability;

	capability = ioctl(fd, CDROM_GET_CAPABILITY, NULL);
	if (capability < 0) {
		info(udev, "CDROM_GET_CAPABILITY failed\n");
		return -1;
	}

	if (capability & CDC_CD_R)
		cd_cd_r = 1;
	if (capability & CDC_CD_RW)
		cd_cd_rw = 1;
	if (capability & CDC_DVD)
		cd_dvd_rom = 1;
	if (capability & CDC_DVD_R)
		cd_dvd_r = 1;
	if (capability & CDC_DVD_RAM)
		cd_dvd_ram = 1;
	if (capability & CDC_MRW)
		cd_mrw = 1;
	if (capability & CDC_MRW_W)
		cd_mrw_w = 1;
	return 0;
}

static int cd_media_compat(struct udev *udev, int fd)
{
	if (ioctl(fd, CDROM_DRIVE_STATUS, CDSL_CURRENT) != CDS_DISC_OK) {
		info(udev, "CDROM_DRIVE_STATUS != CDS_DISC_OK\n");
		return -1;
	}
	cd_media = 1;
	return 0;
}

static int cd_inquiry(struct udev *udev, int fd) {
	struct scsi_cmd sc;
	unsigned char inq[128];
	int err;

	memset (inq, 0, sizeof (inq));
	scsi_cmd_set(udev, &sc, 0, 0x12);
	scsi_cmd_set(udev, &sc, 4, 36);
	scsi_cmd_set(udev, &sc, 5, 0);
	err = scsi_cmd_run(udev, &sc, fd, inq, 36);
	if ((err < 0)) {
		info_scsi_cmd_err(udev, "INQUIRY", err);
		return -1;
	}

	if ((inq[0] & 0x1F) != 5) {
		info(udev, "not an MMC unit\n");
		return -1;
	}

	info(udev, "INQUIRY: [%.8s][%.16s][%.4s]\n", inq + 8, inq + 16, inq + 32);
	return 0;
}

static int cd_profiles(struct udev *udev, int fd)
{
	struct scsi_cmd sc;
	unsigned char header[8];
	unsigned char profiles[512];
	unsigned int cur_profile;
	unsigned int len;
	unsigned int i;
	int err;

	memset (header, 0, sizeof (header));
	scsi_cmd_set(udev, &sc, 0, 0x46);
	scsi_cmd_set(udev, &sc, 1, 0);
	scsi_cmd_set(udev, &sc, 8, sizeof(header));
	scsi_cmd_set(udev, &sc, 9, 0);
	err = scsi_cmd_run(udev, &sc, fd, header, sizeof(header));
	if ((err < 0)) {
		info_scsi_cmd_err(udev, "GET CONFIGURATION", err);
		return -1;
	}

	len = 4 + (header[0] << 24 | header[1] << 16 | header[2] << 8 | header[3]);
	info(udev, "GET CONFIGURATION: number of profiles %i\n", len);
	if (len > sizeof(profiles)) {
		info(udev, "invalid number of profiles\n");
		return -1;
	}

	memset (profiles, 0, sizeof (profiles));
	scsi_cmd_set(udev, &sc, 0, 0x46);
	scsi_cmd_set(udev, &sc, 1, 1);
	scsi_cmd_set(udev, &sc, 6, len >> 16);
	scsi_cmd_set(udev, &sc, 7, len >> 8);
	scsi_cmd_set(udev, &sc, 8, len);
	scsi_cmd_set(udev, &sc, 9, 0);
	err = scsi_cmd_run(udev, &sc, fd, profiles, len);
	if ((err < 0)) {
		info_scsi_cmd_err(udev, "GET CONFIGURATION", err);
		return -1;
	}

	/* device profiles */
	for (i = 12; i < profiles[11]; i += 4) {
		unsigned int profile = (profiles[i] << 8 | profiles[i + 1]);
		if (profile == 0)
			continue;
		info(udev, "profile 0x%02x\n", profile);

		switch (profile) {
		case 0x03:
		case 0x04:
		case 0x05:
			cd_mo = 1;
		break;
		case 0x10:
			cd_dvd_rom = 1;
			break;
		case 0x12:
			cd_dvd_ram = 1;
			break;
		case 0x13:
		case 0x14:
			cd_dvd_rw = 1;
			break;
		case 0x1B:
			cd_dvd_plus_r = 1;
			break;
		case 0x1A:
			cd_dvd_plus_rw = 1;
			break;
		case 0x2A:
			cd_dvd_plus_rw_dl = 1;
			break;
		case 0x2B:
			cd_dvd_plus_r_dl = 1;
			break;
		case 0x40:
			cd_bd = 1;
			break;
		case 0x41:
		case 0x42:
			cd_bd_r = 1;
			break;
		case 0x43:
			cd_bd_re = 1;
			break;
		case 0x50:
			cd_hddvd = 1;
			break;
		case 0x51:
			cd_hddvd_r = 1;
			break;
		case 0x52:
			cd_hddvd_rw = 1;
			break;
		default:
			break;
		}
	}

	/* current media profile */
	cur_profile = header[6] << 8 | header[7];
	info(udev, "current profile 0x%02x\n", cur_profile);
	if (cur_profile == 0) {
		info(udev, "no current profile, assuming no media\n");
		return -1;
	}

	cd_media = 1;

	switch (cur_profile) {
	case 0x03:
	case 0x04:
	case 0x05:
		cd_media_mo = 1;
		break;
	case 0x08:
		cd_media_cd_rom = 1;
		break;
	case 0x09:
		cd_media_cd_r = 1;
		break;
	case 0x0a:
		cd_media_cd_rw = 1;
		break;
	case 0x10:
		cd_media_dvd_rom = 1;
		break;
	case 0x11:
		cd_media_dvd_r = 1;
		break;
	case 0x12:
		cd_media_dvd_ram = 1;
		break;
	case 0x13:
	case 0x14:
		cd_media_dvd_rw = 1;
		break;
	case 0x1B:
		cd_media_dvd_plus_r = 1;
		break;
	case 0x1A:
		cd_media_dvd_plus_rw = 1;
		break;
	case 0x2A:
		cd_media_dvd_plus_rw_dl = 1;
		break;
	case 0x2B:
		cd_media_dvd_plus_r_dl = 1;
		break;
	case 0x40:
		cd_media_bd = 1;
		break;
	case 0x41:
	case 0x42:
		cd_media_bd_r = 1;
		break;
	case 0x43:
		cd_media_bd_re = 1;
		break;
	case 0x50:
		cd_media_hddvd = 1;
		break;
	case 0x51:
		cd_media_hddvd_r = 1;
		break;
	case 0x52:
		cd_media_hddvd_rw = 1;
		break;
	default:
		break;
	}
	return 0;
}

static int cd_media_info(struct udev *udev, int fd)
{
	struct scsi_cmd sc;
	unsigned char header[32];
	static const char *media_status[] = {
		"blank",
		"appendable",
		"complete",
		"other"
	};
	int err;

	memset (header, 0, sizeof (header));
	scsi_cmd_set(udev, &sc, 0, 0x51);
	scsi_cmd_set(udev, &sc, 8, sizeof(header));
	scsi_cmd_set(udev, &sc, 9, 0);
	err = scsi_cmd_run(udev, &sc, fd, header, sizeof(header));
	if ((err < 0)) {
		info_scsi_cmd_err(udev, "READ DISC INFORMATION", err);
		return -1;
	};

	info(udev, "disk type %02x\n", header[8]);

	/* exclude plain CDROM, some fake cdroms return 0 for "blank" media here */
	if (!cd_media_cd_rom && (header[2] & 3) < 4)
		cd_media_state = media_status[header[2] & 3];

	if ((header[2] & 3) != 2)
		cd_media_session_next = header[10] << 8 | header[5];
	cd_media_session_count = header[9] << 8 | header[4];
	cd_media_track_count = header[11] << 8 | header[6];

	return 0;
}

static int cd_media_toc(struct udev *udev, int fd)
{
	struct scsi_cmd sc;
	unsigned char header[12];
	unsigned char toc[2048];
	unsigned int len, i;
	unsigned char *p;
	int err;

	memset (header, 0, sizeof (header));
	scsi_cmd_set(udev, &sc, 0, 0x43);
	scsi_cmd_set(udev, &sc, 6, 1);
	scsi_cmd_set(udev, &sc, 8, sizeof(header));
	scsi_cmd_set(udev, &sc, 9, 0);
	err = scsi_cmd_run(udev, &sc, fd, header, sizeof(header));
	if ((err < 0)) {
		info_scsi_cmd_err(udev, "READ TOC", err);
		return -1;
	}

	len = (header[0] << 8 | header[1]) + 2;
	info(udev, "READ TOC: len: %d\n", len);
	if (len > sizeof(toc))
		return -1;
	if (len < 2)
		return -1;

	/* empty media has no tracks */
	if (len < 8)
		return 0;

	memset (toc, 0, sizeof (toc));
	scsi_cmd_set(udev, &sc, 0, 0x43);
	scsi_cmd_set(udev, &sc, 6, header[2]); /* First Track/Session Number */
	scsi_cmd_set(udev, &sc, 7, len >> 8);
	scsi_cmd_set(udev, &sc, 8, len);
	scsi_cmd_set(udev, &sc, 9, 0);
	err = scsi_cmd_run(udev, &sc, fd, toc, len);
	if ((err < 0)) {
		info_scsi_cmd_err(udev, "READ TOC (tracks)", err);
		return -1;
	}

	for (p = toc+4, i = 4; i < len-8; i += 8, p += 8) {
		unsigned int block;
		unsigned int is_data_track;

		is_data_track = (p[1] & 0x04) != 0;

		block = p[4] << 24 | p[5] << 16 | p[6] << 8 | p[7];
		info(udev, "track=%u info=0x%x(%s) start_block=%u\n",
		     p[2], p[1] & 0x0f, is_data_track ? "data":"audio", block);

		if (is_data_track)
			cd_media_track_count_data++;
		else
			cd_media_track_count_audio++;
	}

	memset (header, 0, sizeof (header));
	scsi_cmd_set(udev, &sc, 0, 0x43);
	scsi_cmd_set(udev, &sc, 2, 1); /* Session Info */
	scsi_cmd_set(udev, &sc, 8, 12);
	scsi_cmd_set(udev, &sc, 9, 0);
	err = scsi_cmd_run(udev, &sc, fd, header, sizeof(header));
	if ((err < 0)) {
		info_scsi_cmd_err(udev, "READ TOC (multi session)", err);
		return -1;
	}
	len = header[4+4] << 24 | header[4+5] << 16 | header[4+6] << 8 | header[4+7];
	info(udev, "last track %u starts at block %u\n", header[4+2], len);
	cd_media_session_last_offset = (unsigned long long int)len * 2048;
	return 0;
}

int main(int argc, char *argv[])
{
	struct udev *udev;
	static const struct option options[] = {
		{ "export", no_argument, NULL, 'x' },
		{ "debug", no_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	const char *node = NULL;
	int export = 0;
	int fd = -1;
	int cnt;
	int rc = 0;

	udev = udev_new();
	if (udev == NULL)
		goto exit;

	udev_log_init("cdrom_id");
	udev_set_log_fn(udev, log_fn);

	while (1) {
		int option;

		option = getopt_long(argc, argv, "dxh", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'd':
			debug = 1;
			if (udev_get_log_priority(udev) < LOG_INFO)
				udev_set_log_priority(udev, LOG_INFO);
			break;
		case 'x':
			export = 1;
			break;
		case 'h':
			printf("Usage: cdrom_id [options] <device>\n"
			       "  --export        export key/value pairs\n"
			       "  --debug         debug to stderr\n"
			       "  --help          print this help text\n\n");
			goto exit;
		default:
			rc = 1;
			goto exit;
		}
	}

	node = argv[optind];
	if (!node) {
		err(udev, "no device\n");
		fprintf(stderr, "no device\n");
		rc = 1;
		goto exit;
	}

	srand((unsigned int)getpid());
	for (cnt = 20; cnt > 0; cnt--) {
		struct timespec duration;

		fd = open(node, O_RDONLY|O_NONBLOCK|(is_mounted(node) ? 0 : O_EXCL));
		if (fd >= 0 || errno != EBUSY)
			break;
		duration.tv_sec = 0;
		duration.tv_nsec = (100 * 1000 * 1000) + (rand() % 100 * 1000 * 1000);
		nanosleep(&duration, NULL);
	}
	if (fd < 0) {
		info(udev, "unable to open '%s'\n", node);
		fprintf(stderr, "unable to open '%s'\n", node);
		rc = 1;
		goto exit;
	}
	info(udev, "probing: '%s'\n", node);

	/* same data as original cdrom_id */
	if (cd_capability_compat(udev, fd) < 0) {
		rc = 1;
		goto exit;
	}

	/* check for media - don't bail if there's no media as we still need to
         * to read profiles */
	cd_media_compat(udev, fd);

	/* check if drive talks MMC */
	if (cd_inquiry(udev, fd) < 0)
		goto print;

	/* read drive and possibly current profile */
	if (cd_profiles(udev, fd) < 0)
		goto print;

	/* get session/track info */
	if (cd_media_toc(udev, fd) < 0)
		goto print;

	/* get writable media state */
	if (cd_media_info(udev, fd) < 0)
		goto print;

print:
	printf("ID_CDROM=1\n");
	if (cd_cd_rom)
		printf("ID_CDROM_CD=1\n");
	if (cd_cd_r)
		printf("ID_CDROM_CD_R=1\n");
	if (cd_cd_rw)
		printf("ID_CDROM_CD_RW=1\n");
	if (cd_dvd_rom)
		printf("ID_CDROM_DVD=1\n");
	if (cd_dvd_r)
		printf("ID_CDROM_DVD_R=1\n");
	if (cd_dvd_rw)
		printf("ID_CDROM_DVD_RW=1\n");
	if (cd_dvd_ram)
		printf("ID_CDROM_DVD_RAM=1\n");
	if (cd_dvd_plus_r)
		printf("ID_CDROM_DVD_PLUS_R=1\n");
	if (cd_dvd_plus_rw)
		printf("ID_CDROM_DVD_PLUS_RW=1\n");
	if (cd_dvd_plus_r_dl)
		printf("ID_CDROM_DVD_PLUS_R_DL=1\n");
	if (cd_dvd_plus_rw_dl)
		printf("ID_CDROM_DVD_PLUS_RW_DL=1\n");
	if (cd_bd)
		printf("ID_CDROM_BD=1\n");
	if (cd_bd_r)
		printf("ID_CDROM_BD_R=1\n");
	if (cd_bd_re)
		printf("ID_CDROM_BD_RE=1\n");
	if (cd_hddvd)
		printf("ID_CDROM_HDDVD=1\n");
	if (cd_hddvd_r)
		printf("ID_CDROM_HDDVD_R=1\n");
	if (cd_hddvd_rw)
		printf("ID_CDROM_HDDVD_RW=1\n");
	if (cd_mo)
		printf("ID_CDROM_MO=1\n");
	if (cd_mrw)
		printf("ID_CDROM_MRW=1\n");
	if (cd_mrw_w)
		printf("ID_CDROM_MRW_W=1\n");

	if (cd_media)
		printf("ID_CDROM_MEDIA=1\n");
	if (cd_media_mo)
		printf("ID_CDROM_MEDIA_MO=1\n");
	if (cd_media_mrw)
		printf("ID_CDROM_MEDIA_MRW=1\n");
	if (cd_media_mrw_w)
		printf("ID_CDROM_MEDIA_MRW_W=1\n");
	if (cd_media_cd_rom)
		printf("ID_CDROM_MEDIA_CD=1\n");
	if (cd_media_cd_r)
		printf("ID_CDROM_MEDIA_CD_R=1\n");
	if (cd_media_cd_rw)
		printf("ID_CDROM_MEDIA_CD_RW=1\n");
	if (cd_media_dvd_rom)
		printf("ID_CDROM_MEDIA_DVD=1\n");
	if (cd_media_dvd_r)
		printf("ID_CDROM_MEDIA_DVD_R=1\n");
	if (cd_media_dvd_ram)
		printf("ID_CDROM_MEDIA_DVD_RAM=1\n");
	if (cd_media_dvd_rw)
		printf("ID_CDROM_MEDIA_DVD_RW=1\n");
	if (cd_media_dvd_plus_r)
		printf("ID_CDROM_MEDIA_DVD_PLUS_R=1\n");
	if (cd_media_dvd_plus_rw)
		printf("ID_CDROM_MEDIA_DVD_PLUS_RW=1\n");
	if (cd_media_dvd_plus_rw_dl)
		printf("ID_CDROM_MEDIA_DVD_PLUS_RW_DL=1\n");
	if (cd_media_dvd_plus_r_dl)
		printf("ID_CDROM_MEDIA_DVD_PLUS_R_DL=1\n");
	if (cd_media_bd)
		printf("ID_CDROM_MEDIA_BD=1\n");
	if (cd_media_bd_r)
		printf("ID_CDROM_MEDIA_BD_R=1\n");
	if (cd_media_bd_re)
		printf("ID_CDROM_MEDIA_BD_RE=1\n");
	if (cd_media_hddvd)
		printf("ID_CDROM_MEDIA_HDDVD=1\n");
	if (cd_media_hddvd_r)
		printf("ID_CDROM_MEDIA_HDDVD_R=1\n");
	if (cd_media_hddvd_rw)
		printf("ID_CDROM_MEDIA_HDDVD_RW=1\n");

	if (cd_media_state != NULL)
		printf("ID_CDROM_MEDIA_STATE=%s\n", cd_media_state);
	if (cd_media_session_next > 0)
		printf("ID_CDROM_MEDIA_SESSION_NEXT=%d\n", cd_media_session_next);
	if (cd_media_session_count > 0)
		printf("ID_CDROM_MEDIA_SESSION_COUNT=%d\n", cd_media_session_count);
	if (cd_media_track_count > 0)
		printf("ID_CDROM_MEDIA_TRACK_COUNT=%d\n", cd_media_track_count);
	if (cd_media_track_count_audio > 0)
		printf("ID_CDROM_MEDIA_TRACK_COUNT_AUDIO=%d\n", cd_media_track_count_audio);
	if (cd_media_track_count_data > 0)
		printf("ID_CDROM_MEDIA_TRACK_COUNT_DATA=%d\n", cd_media_track_count_data);
	if (cd_media_session_last_offset > 0)
		printf("ID_CDROM_MEDIA_SESSION_LAST_OFFSET=%llu\n", cd_media_session_last_offset);
exit:
	if (fd >= 0)
		close(fd);
	udev_unref(udev);
	udev_log_close();
	return rc;
}

