/*
 * cdrom_id - optical drive and media information prober
 *
 * Copyright (C) 2008-2010 Kay Sievers <kay@vrfy.org>
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
#include "random-util.h"

/* device info */
static unsigned int cd_cd_rom;
static unsigned int cd_cd_r;
static unsigned int cd_cd_rw;
static unsigned int cd_dvd_rom;
static unsigned int cd_dvd_r;
static unsigned int cd_dvd_rw;
static unsigned int cd_dvd_ram;
static unsigned int cd_dvd_plus_r;
static unsigned int cd_dvd_plus_rw;
static unsigned int cd_dvd_plus_r_dl;
static unsigned int cd_dvd_plus_rw_dl;
static unsigned int cd_bd;
static unsigned int cd_bd_r;
static unsigned int cd_bd_re;
static unsigned int cd_hddvd;
static unsigned int cd_hddvd_r;
static unsigned int cd_hddvd_rw;
static unsigned int cd_mo;
static unsigned int cd_mrw;
static unsigned int cd_mrw_w;

/* media info */
static unsigned int cd_media;
static unsigned int cd_media_cd_rom;
static unsigned int cd_media_cd_r;
static unsigned int cd_media_cd_rw;
static unsigned int cd_media_dvd_rom;
static unsigned int cd_media_dvd_r;
static unsigned int cd_media_dvd_rw;
static unsigned int cd_media_dvd_rw_ro; /* restricted overwrite mode */
static unsigned int cd_media_dvd_rw_seq; /* sequential mode */
static unsigned int cd_media_dvd_ram;
static unsigned int cd_media_dvd_plus_r;
static unsigned int cd_media_dvd_plus_rw;
static unsigned int cd_media_dvd_plus_r_dl;
static unsigned int cd_media_dvd_plus_rw_dl;
static unsigned int cd_media_bd;
static unsigned int cd_media_bd_r;
static unsigned int cd_media_bd_re;
static unsigned int cd_media_hddvd;
static unsigned int cd_media_hddvd_r;
static unsigned int cd_media_hddvd_rw;
static unsigned int cd_media_mo;
static unsigned int cd_media_mrw;
static unsigned int cd_media_mrw_w;

static const char *cd_media_state = NULL;
static unsigned int cd_media_session_next;
static unsigned int cd_media_session_count;
static unsigned int cd_media_track_count;
static unsigned int cd_media_track_count_data;
static unsigned int cd_media_track_count_audio;
static unsigned long long int cd_media_session_last_offset;

#define ERRCODE(s)        ((((s)[2] & 0x0F) << 16) | ((s)[12] << 8) | ((s)[13]))
#define SK(errcode)        (((errcode) >> 16) & 0xF)
#define ASC(errcode)        (((errcode) >> 8) & 0xFF)
#define ASCQ(errcode)        ((errcode) & 0xFF)

static bool is_mounted(const char *device)
{
        struct stat statbuf;
        FILE *fp;
        int maj, min;
        bool mounted = false;

        if (stat(device, &statbuf) < 0)
                return -ENODEV;

        fp = fopen("/proc/self/mountinfo", "re");
        if (fp == NULL)
                return -ENOSYS;
        while (fscanf(fp, "%*s %*s %i:%i %*[^\n]", &maj, &min) == 2) {
                if (makedev(maj, min) == statbuf.st_rdev) {
                        mounted = true;
                        break;
                }
        }
        fclose(fp);
        return mounted;
}

static void info_scsi_cmd_err(struct udev *udev, const char *cmd, int err)
{
        if (err == -1) {
                log_debug("%s failed", cmd);
                return;
        }
        log_debug("%s failed with SK=%Xh/ASC=%02Xh/ACQ=%02Xh", cmd, SK(err), ASC(err), ASCQ(err));
}

struct scsi_cmd {
        struct cdrom_generic_command cgc;
        union {
                struct request_sense s;
                unsigned char u[18];
        } _sense;
        struct sg_io_hdr sg_io;
};

static void scsi_cmd_init(struct udev *udev, struct scsi_cmd *cmd)
{
        memzero(cmd, sizeof(struct scsi_cmd));
        cmd->cgc.quiet = 1;
        cmd->cgc.sense = &cmd->_sense.s;
        cmd->sg_io.interface_id = 'S';
        cmd->sg_io.mx_sb_len = sizeof(cmd->_sense);
        cmd->sg_io.cmdp = cmd->cgc.cmd;
        cmd->sg_io.sbp = cmd->_sense.u;
        cmd->sg_io.flags = SG_FLAG_LUN_INHIBIT | SG_FLAG_DIRECT_IO;
}

static void scsi_cmd_set(struct udev *udev, struct scsi_cmd *cmd, size_t i, unsigned char arg)
{
        cmd->sg_io.cmd_len = i + 1;
        cmd->cgc.cmd[i] = arg;
}

#define CHECK_CONDITION 0x01

static int scsi_cmd_run(struct udev *udev, struct scsi_cmd *cmd, int fd, unsigned char *buf, size_t bufsize)
{
        int ret = 0;

        if (bufsize > 0) {
                cmd->sg_io.dxferp = buf;
                cmd->sg_io.dxfer_len = bufsize;
                cmd->sg_io.dxfer_direction = SG_DXFER_FROM_DEV;
        } else {
                cmd->sg_io.dxfer_direction = SG_DXFER_NONE;
        }
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

static int media_lock(struct udev *udev, int fd, bool lock)
{
        int err;

        /* disable the kernel's lock logic */
        err = ioctl(fd, CDROM_CLEAR_OPTIONS, CDO_LOCK);
        if (err < 0)
                log_debug("CDROM_CLEAR_OPTIONS, CDO_LOCK failed");

        err = ioctl(fd, CDROM_LOCKDOOR, lock ? 1 : 0);
        if (err < 0)
                log_debug("CDROM_LOCKDOOR failed");

        return err;
}

static int media_eject(struct udev *udev, int fd)
{
        struct scsi_cmd sc;
        int err;

        scsi_cmd_init(udev, &sc);
        scsi_cmd_set(udev, &sc, 0, 0x1b);
        scsi_cmd_set(udev, &sc, 4, 0x02);
        scsi_cmd_set(udev, &sc, 5, 0);
        err = scsi_cmd_run(udev, &sc, fd, NULL, 0);
        if ((err != 0)) {
                info_scsi_cmd_err(udev, "START_STOP_UNIT", err);
                return -1;
        }
        return 0;
}

static int cd_capability_compat(struct udev *udev, int fd)
{
        int capability;

        capability = ioctl(fd, CDROM_GET_CAPABILITY, NULL);
        if (capability < 0) {
                log_debug("CDROM_GET_CAPABILITY failed");
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
                log_debug("CDROM_DRIVE_STATUS != CDS_DISC_OK");
                return -1;
        }
        cd_media = 1;
        return 0;
}

static int cd_inquiry(struct udev *udev, int fd)
{
        struct scsi_cmd sc;
        unsigned char inq[128];
        int err;

        scsi_cmd_init(udev, &sc);
        scsi_cmd_set(udev, &sc, 0, 0x12);
        scsi_cmd_set(udev, &sc, 4, 36);
        scsi_cmd_set(udev, &sc, 5, 0);
        err = scsi_cmd_run(udev, &sc, fd, inq, 36);
        if ((err != 0)) {
                info_scsi_cmd_err(udev, "INQUIRY", err);
                return -1;
        }

        if ((inq[0] & 0x1F) != 5) {
                log_debug("not an MMC unit");
                return -1;
        }

        log_debug("INQUIRY: [%.8s][%.16s][%.4s]", inq + 8, inq + 16, inq + 32);
        return 0;
}

static void feature_profile_media(struct udev *udev, int cur_profile)
{
        switch (cur_profile) {
        case 0x03:
        case 0x04:
        case 0x05:
                log_debug("profile 0x%02x ", cur_profile);
                cd_media = 1;
                cd_media_mo = 1;
                break;
        case 0x08:
                log_debug("profile 0x%02x media_cd_rom", cur_profile);
                cd_media = 1;
                cd_media_cd_rom = 1;
                break;
        case 0x09:
                log_debug("profile 0x%02x media_cd_r", cur_profile);
                cd_media = 1;
                cd_media_cd_r = 1;
                break;
        case 0x0a:
                log_debug("profile 0x%02x media_cd_rw", cur_profile);
                cd_media = 1;
                cd_media_cd_rw = 1;
                break;
        case 0x10:
                log_debug("profile 0x%02x media_dvd_ro", cur_profile);
                cd_media = 1;
                cd_media_dvd_rom = 1;
                break;
        case 0x11:
                log_debug("profile 0x%02x media_dvd_r", cur_profile);
                cd_media = 1;
                cd_media_dvd_r = 1;
                break;
        case 0x12:
                log_debug("profile 0x%02x media_dvd_ram", cur_profile);
                cd_media = 1;
                cd_media_dvd_ram = 1;
                break;
        case 0x13:
                log_debug("profile 0x%02x media_dvd_rw_ro", cur_profile);
                cd_media = 1;
                cd_media_dvd_rw = 1;
                cd_media_dvd_rw_ro = 1;
                break;
        case 0x14:
                log_debug("profile 0x%02x media_dvd_rw_seq", cur_profile);
                cd_media = 1;
                cd_media_dvd_rw = 1;
                cd_media_dvd_rw_seq = 1;
                break;
        case 0x1B:
                log_debug("profile 0x%02x media_dvd_plus_r", cur_profile);
                cd_media = 1;
                cd_media_dvd_plus_r = 1;
                break;
        case 0x1A:
                log_debug("profile 0x%02x media_dvd_plus_rw", cur_profile);
                cd_media = 1;
                cd_media_dvd_plus_rw = 1;
                break;
        case 0x2A:
                log_debug("profile 0x%02x media_dvd_plus_rw_dl", cur_profile);
                cd_media = 1;
                cd_media_dvd_plus_rw_dl = 1;
                break;
        case 0x2B:
                log_debug("profile 0x%02x media_dvd_plus_r_dl", cur_profile);
                cd_media = 1;
                cd_media_dvd_plus_r_dl = 1;
                break;
        case 0x40:
                log_debug("profile 0x%02x media_bd", cur_profile);
                cd_media = 1;
                cd_media_bd = 1;
                break;
        case 0x41:
        case 0x42:
                log_debug("profile 0x%02x media_bd_r", cur_profile);
                cd_media = 1;
                cd_media_bd_r = 1;
                break;
        case 0x43:
                log_debug("profile 0x%02x media_bd_re", cur_profile);
                cd_media = 1;
                cd_media_bd_re = 1;
                break;
        case 0x50:
                log_debug("profile 0x%02x media_hddvd", cur_profile);
                cd_media = 1;
                cd_media_hddvd = 1;
                break;
        case 0x51:
                log_debug("profile 0x%02x media_hddvd_r", cur_profile);
                cd_media = 1;
                cd_media_hddvd_r = 1;
                break;
        case 0x52:
                log_debug("profile 0x%02x media_hddvd_rw", cur_profile);
                cd_media = 1;
                cd_media_hddvd_rw = 1;
                break;
        default:
                log_debug("profile 0x%02x <ignored>", cur_profile);
                break;
        }
}

static int feature_profiles(struct udev *udev, const unsigned char *profiles, size_t size)
{
        unsigned int i;

        for (i = 0; i+4 <= size; i += 4) {
                int profile;

                profile = profiles[i] << 8 | profiles[i+1];
                switch (profile) {
                case 0x03:
                case 0x04:
                case 0x05:
                        log_debug("profile 0x%02x mo", profile);
                        cd_mo = 1;
                        break;
                case 0x08:
                        log_debug("profile 0x%02x cd_rom", profile);
                        cd_cd_rom = 1;
                        break;
                case 0x09:
                        log_debug("profile 0x%02x cd_r", profile);
                        cd_cd_r = 1;
                        break;
                case 0x0A:
                        log_debug("profile 0x%02x cd_rw", profile);
                        cd_cd_rw = 1;
                        break;
                case 0x10:
                        log_debug("profile 0x%02x dvd_rom", profile);
                        cd_dvd_rom = 1;
                        break;
                case 0x12:
                        log_debug("profile 0x%02x dvd_ram", profile);
                        cd_dvd_ram = 1;
                        break;
                case 0x13:
                case 0x14:
                        log_debug("profile 0x%02x dvd_rw", profile);
                        cd_dvd_rw = 1;
                        break;
                case 0x1B:
                        log_debug("profile 0x%02x dvd_plus_r", profile);
                        cd_dvd_plus_r = 1;
                        break;
                case 0x1A:
                        log_debug("profile 0x%02x dvd_plus_rw", profile);
                        cd_dvd_plus_rw = 1;
                        break;
                case 0x2A:
                        log_debug("profile 0x%02x dvd_plus_rw_dl", profile);
                        cd_dvd_plus_rw_dl = 1;
                        break;
                case 0x2B:
                        log_debug("profile 0x%02x dvd_plus_r_dl", profile);
                        cd_dvd_plus_r_dl = 1;
                        break;
                case 0x40:
                        cd_bd = 1;
                        log_debug("profile 0x%02x bd", profile);
                        break;
                case 0x41:
                case 0x42:
                        cd_bd_r = 1;
                        log_debug("profile 0x%02x bd_r", profile);
                        break;
                case 0x43:
                        cd_bd_re = 1;
                        log_debug("profile 0x%02x bd_re", profile);
                        break;
                case 0x50:
                        cd_hddvd = 1;
                        log_debug("profile 0x%02x hddvd", profile);
                        break;
                case 0x51:
                        cd_hddvd_r = 1;
                        log_debug("profile 0x%02x hddvd_r", profile);
                        break;
                case 0x52:
                        cd_hddvd_rw = 1;
                        log_debug("profile 0x%02x hddvd_rw", profile);
                        break;
                default:
                        log_debug("profile 0x%02x <ignored>", profile);
                        break;
                }
        }
        return 0;
}

/* returns 0 if media was detected */
static int cd_profiles_old_mmc(struct udev *udev, int fd)
{
        struct scsi_cmd sc;
        int err;

        unsigned char header[32];

        scsi_cmd_init(udev, &sc);
        scsi_cmd_set(udev, &sc, 0, 0x51);
        scsi_cmd_set(udev, &sc, 8, sizeof(header));
        scsi_cmd_set(udev, &sc, 9, 0);
        err = scsi_cmd_run(udev, &sc, fd, header, sizeof(header));
        if ((err != 0)) {
                info_scsi_cmd_err(udev, "READ DISC INFORMATION", err);
                if (cd_media == 1) {
                        log_debug("no current profile, but disc is present; assuming CD-ROM");
                        cd_media_cd_rom = 1;
                        cd_media_track_count = 1;
                        cd_media_track_count_data = 1;
                        return 0;
                } else {
                        log_debug("no current profile, assuming no media");
                        return -1;
                }
        };

        cd_media = 1;

        if (header[2] & 16) {
                cd_media_cd_rw = 1;
                log_debug("profile 0x0a media_cd_rw");
        } else if ((header[2] & 3) < 2 && cd_cd_r) {
                cd_media_cd_r = 1;
                log_debug("profile 0x09 media_cd_r");
        } else {
                cd_media_cd_rom = 1;
                log_debug("profile 0x08 media_cd_rom");
        }
        return 0;
}

/* returns 0 if media was detected */
static int cd_profiles(struct udev *udev, int fd)
{
        struct scsi_cmd sc;
        unsigned char features[65530];
        unsigned int cur_profile = 0;
        unsigned int len;
        unsigned int i;
        int err;
        int ret;

        ret = -1;

        /* First query the current profile */
        scsi_cmd_init(udev, &sc);
        scsi_cmd_set(udev, &sc, 0, 0x46);
        scsi_cmd_set(udev, &sc, 8, 8);
        scsi_cmd_set(udev, &sc, 9, 0);
        err = scsi_cmd_run(udev, &sc, fd, features, 8);
        if ((err != 0)) {
                info_scsi_cmd_err(udev, "GET CONFIGURATION", err);
                /* handle pre-MMC2 drives which do not support GET CONFIGURATION */
                if (SK(err) == 0x5 && (ASC(err) == 0x20 || ASC(err) == 0x24)) {
                        log_debug("drive is pre-MMC2 and does not support 46h get configuration command");
                        log_debug("trying to work around the problem");
                        ret = cd_profiles_old_mmc(udev, fd);
                }
                goto out;
        }

        cur_profile = features[6] << 8 | features[7];
        if (cur_profile > 0) {
                log_debug("current profile 0x%02x", cur_profile);
                feature_profile_media (udev, cur_profile);
                ret = 0; /* we have media */
        } else {
                log_debug("no current profile, assuming no media");
        }

        len = features[0] << 24 | features[1] << 16 | features[2] << 8 | features[3];
        log_debug("GET CONFIGURATION: size of features buffer 0x%04x", len);

        if (len > sizeof(features)) {
                log_debug("can not get features in a single query, truncating");
                len = sizeof(features);
        } else if (len <= 8) {
                len = sizeof(features);
        }

        /* Now get the full feature buffer */
        scsi_cmd_init(udev, &sc);
        scsi_cmd_set(udev, &sc, 0, 0x46);
        scsi_cmd_set(udev, &sc, 7, ( len >> 8 ) & 0xff);
        scsi_cmd_set(udev, &sc, 8, len & 0xff);
        scsi_cmd_set(udev, &sc, 9, 0);
        err = scsi_cmd_run(udev, &sc, fd, features, len);
        if ((err != 0)) {
                info_scsi_cmd_err(udev, "GET CONFIGURATION", err);
                return -1;
        }

        /* parse the length once more, in case the drive decided to have other features suddenly :) */
        len = features[0] << 24 | features[1] << 16 | features[2] << 8 | features[3];
        log_debug("GET CONFIGURATION: size of features buffer 0x%04x", len);

        if (len > sizeof(features)) {
                log_debug("can not get features in a single query, truncating");
                len = sizeof(features);
        }

        /* device features */
        for (i = 8; i+4 < len; i += (4 + features[i+3])) {
                unsigned int feature;

                feature = features[i] << 8 | features[i+1];

                switch (feature) {
                case 0x00:
                        log_debug("GET CONFIGURATION: feature 'profiles', with %i entries", features[i+3] / 4);
                        feature_profiles(udev, &features[i]+4, MIN(features[i+3], len - i - 4));
                        break;
                default:
                        log_debug("GET CONFIGURATION: feature 0x%04x <ignored>, with 0x%02x bytes", feature, features[i+3]);
                        break;
                }
        }
out:
        return ret;
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

        scsi_cmd_init(udev, &sc);
        scsi_cmd_set(udev, &sc, 0, 0x51);
        scsi_cmd_set(udev, &sc, 8, sizeof(header) & 0xff);
        scsi_cmd_set(udev, &sc, 9, 0);
        err = scsi_cmd_run(udev, &sc, fd, header, sizeof(header));
        if ((err != 0)) {
                info_scsi_cmd_err(udev, "READ DISC INFORMATION", err);
                return -1;
        };

        cd_media = 1;
        log_debug("disk type %02x", header[8]);
        log_debug("hardware reported media status: %s", media_status[header[2] & 3]);

        /* exclude plain CDROM, some fake cdroms return 0 for "blank" media here */
        if (!cd_media_cd_rom)
                cd_media_state = media_status[header[2] & 3];

        /* fresh DVD-RW in restricted overwite mode reports itself as
         * "appendable"; change it to "blank" to make it consistent with what
         * gets reported after blanking, and what userspace expects  */
        if (cd_media_dvd_rw_ro && (header[2] & 3) == 1)
                cd_media_state = media_status[0];

        /* DVD+RW discs (and DVD-RW in restricted mode) once formatted are
         * always "complete", DVD-RAM are "other" or "complete" if the disc is
         * write protected; we need to check the contents if it is blank */
        if ((cd_media_dvd_rw_ro || cd_media_dvd_plus_rw || cd_media_dvd_plus_rw_dl || cd_media_dvd_ram) && (header[2] & 3) > 1) {
                unsigned char buffer[32 * 2048];
                unsigned char len;
                int offset;

                if (cd_media_dvd_ram) {
                        /* a write protected dvd-ram may report "complete" status */

                        unsigned char dvdstruct[8];
                        unsigned char format[12];

                        scsi_cmd_init(udev, &sc);
                        scsi_cmd_set(udev, &sc, 0, 0xAD);
                        scsi_cmd_set(udev, &sc, 7, 0xC0);
                        scsi_cmd_set(udev, &sc, 9, sizeof(dvdstruct));
                        scsi_cmd_set(udev, &sc, 11, 0);
                        err = scsi_cmd_run(udev, &sc, fd, dvdstruct, sizeof(dvdstruct));
                        if ((err != 0)) {
                                info_scsi_cmd_err(udev, "READ DVD STRUCTURE", err);
                                return -1;
                        }
                        if (dvdstruct[4] & 0x02) {
                                cd_media_state = media_status[2];
                                log_debug("write-protected DVD-RAM media inserted");
                                goto determined;
                        }

                        /* let's make sure we don't try to read unformatted media */
                        scsi_cmd_init(udev, &sc);
                        scsi_cmd_set(udev, &sc, 0, 0x23);
                        scsi_cmd_set(udev, &sc, 8, sizeof(format));
                        scsi_cmd_set(udev, &sc, 9, 0);
                        err = scsi_cmd_run(udev, &sc, fd, format, sizeof(format));
                        if ((err != 0)) {
                                info_scsi_cmd_err(udev, "READ DVD FORMAT CAPACITIES", err);
                                return -1;
                        }

                        len = format[3];
                        if (len & 7 || len < 16) {
                                log_debug("invalid format capacities length");
                                return -1;
                        }

                        switch(format[8] & 3) {
                            case 1:
                                log_debug("unformatted DVD-RAM media inserted");
                                /* This means that last format was interrupted
                                 * or failed, blank dvd-ram discs are factory
                                 * formatted. Take no action here as it takes
                                 * quite a while to reformat a dvd-ram and it's
                                 * not automatically started */
                                goto determined;

                            case 2:
                                log_debug("formatted DVD-RAM media inserted");
                                break;

                            case 3:
                                cd_media = 0; //return no media
                                log_debug("format capacities returned no media");
                                return -1;
                        }
                }

                /* Take a closer look at formatted media (unformatted DVD+RW
                 * has "blank" status", DVD-RAM was examined earlier) and check
                 * for ISO and UDF PVDs or a fs superblock presence and do it
                 * in one ioctl (we need just sectors 0 and 16) */
                scsi_cmd_init(udev, &sc);
                scsi_cmd_set(udev, &sc, 0, 0x28);
                scsi_cmd_set(udev, &sc, 5, 0);
                scsi_cmd_set(udev, &sc, 8, 32);
                scsi_cmd_set(udev, &sc, 9, 0);
                err = scsi_cmd_run(udev, &sc, fd, buffer, sizeof(buffer));
                if ((err != 0)) {
                        cd_media = 0;
                        info_scsi_cmd_err(udev, "READ FIRST 32 BLOCKS", err);
                        return -1;
                }

                /* if any non-zero data is found in sector 16 (iso and udf) or
                 * eventually 0 (fat32 boot sector, ext2 superblock, etc), disc
                 * is assumed non-blank */

                for (offset = 32768; offset < (32768 + 2048); offset++) {
                        if (buffer [offset]) {
                                log_debug("data in block 16, assuming complete");
                                goto determined;
                        }
                }

                for (offset = 0; offset < 2048; offset++) {
                        if (buffer [offset]) {
                                log_debug("data in block 0, assuming complete");
                                goto determined;
                        }
                }

                cd_media_state = media_status[0];
                log_debug("no data in blocks 0 or 16, assuming blank");
        }

determined:
        /* "other" is e. g. DVD-RAM, can't append sessions there; DVDs in
         * restricted overwrite mode can never append, only in sequential mode */
        if ((header[2] & 3) < 2 && !cd_media_dvd_rw_ro)
                cd_media_session_next = header[10] << 8 | header[5];
        cd_media_session_count = header[9] << 8 | header[4];
        cd_media_track_count = header[11] << 8 | header[6];

        return 0;
}

static int cd_media_toc(struct udev *udev, int fd)
{
        struct scsi_cmd sc;
        unsigned char header[12];
        unsigned char toc[65536];
        unsigned int len, i, num_tracks;
        unsigned char *p;
        int err;

        scsi_cmd_init(udev, &sc);
        scsi_cmd_set(udev, &sc, 0, 0x43);
        scsi_cmd_set(udev, &sc, 6, 1);
        scsi_cmd_set(udev, &sc, 8, sizeof(header) & 0xff);
        scsi_cmd_set(udev, &sc, 9, 0);
        err = scsi_cmd_run(udev, &sc, fd, header, sizeof(header));
        if ((err != 0)) {
                info_scsi_cmd_err(udev, "READ TOC", err);
                return -1;
        }

        len = (header[0] << 8 | header[1]) + 2;
        log_debug("READ TOC: len: %d, start track: %d, end track: %d", len, header[2], header[3]);
        if (len > sizeof(toc))
                return -1;
        if (len < 2)
                return -1;
        /* 2: first track, 3: last track */
        num_tracks = header[3] - header[2] + 1;

        /* empty media has no tracks */
        if (len < 8)
                return 0;

        scsi_cmd_init(udev, &sc);
        scsi_cmd_set(udev, &sc, 0, 0x43);
        scsi_cmd_set(udev, &sc, 6, header[2]); /* First Track/Session Number */
        scsi_cmd_set(udev, &sc, 7, (len >> 8) & 0xff);
        scsi_cmd_set(udev, &sc, 8, len & 0xff);
        scsi_cmd_set(udev, &sc, 9, 0);
        err = scsi_cmd_run(udev, &sc, fd, toc, len);
        if ((err != 0)) {
                info_scsi_cmd_err(udev, "READ TOC (tracks)", err);
                return -1;
        }

        /* Take care to not iterate beyond the last valid track as specified in
         * the TOC, but also avoid going beyond the TOC length, just in case
         * the last track number is invalidly large */
        for (p = toc+4, i = 4; i < len-8 && num_tracks > 0; i += 8, p += 8, --num_tracks) {
                unsigned int block;
                unsigned int is_data_track;

                is_data_track = (p[1] & 0x04) != 0;

                block = p[4] << 24 | p[5] << 16 | p[6] << 8 | p[7];
                log_debug("track=%u info=0x%x(%s) start_block=%u",
                     p[2], p[1] & 0x0f, is_data_track ? "data":"audio", block);

                if (is_data_track)
                        cd_media_track_count_data++;
                else
                        cd_media_track_count_audio++;
        }

        scsi_cmd_init(udev, &sc);
        scsi_cmd_set(udev, &sc, 0, 0x43);
        scsi_cmd_set(udev, &sc, 2, 1); /* Session Info */
        scsi_cmd_set(udev, &sc, 8, sizeof(header));
        scsi_cmd_set(udev, &sc, 9, 0);
        err = scsi_cmd_run(udev, &sc, fd, header, sizeof(header));
        if ((err != 0)) {
                info_scsi_cmd_err(udev, "READ TOC (multi session)", err);
                return -1;
        }
        len = header[4+4] << 24 | header[4+5] << 16 | header[4+6] << 8 | header[4+7];
        log_debug("last track %u starts at block %u", header[4+2], len);
        cd_media_session_last_offset = (unsigned long long int)len * 2048;
        return 0;
}

int main(int argc, char *argv[])
{
        struct udev *udev;
        static const struct option options[] = {
                { "lock-media", no_argument, NULL, 'l' },
                { "unlock-media", no_argument, NULL, 'u' },
                { "eject-media", no_argument, NULL, 'e' },
                { "debug", no_argument, NULL, 'd' },
                { "help", no_argument, NULL, 'h' },
                {}
        };
        bool eject = false;
        bool lock = false;
        bool unlock = false;
        const char *node = NULL;
        int fd = -1;
        int cnt;
        int rc = 0;

        log_parse_environment();
        log_open();

        udev = udev_new();
        if (udev == NULL)
                goto exit;

        while (1) {
                int option;

                option = getopt_long(argc, argv, "deluh", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 'l':
                        lock = true;
                        break;
                case 'u':
                        unlock = true;
                        break;
                case 'e':
                        eject = true;
                        break;
                case 'd':
                        log_set_target(LOG_TARGET_CONSOLE);
                        log_set_max_level(LOG_DEBUG);
                        log_open();
                        break;
                case 'h':
                        printf("Usage: cdrom_id [options] <device>\n"
                               "  -l,--lock-media    lock the media (to enable eject request events)\n"
                               "  -u,--unlock-media  unlock the media\n"
                               "  -e,--eject-media   eject the media\n"
                               "  -d,--debug         debug to stderr\n"
                               "  -h,--help          print this help text\n\n");
                        goto exit;
                default:
                        rc = 1;
                        goto exit;
                }
        }

        node = argv[optind];
        if (!node) {
                log_error("no device");
                fprintf(stderr, "no device\n");
                rc = 1;
                goto exit;
        }

        initialize_srand();
        for (cnt = 20; cnt > 0; cnt--) {
                struct timespec duration;

                fd = open(node, O_RDONLY|O_NONBLOCK|O_CLOEXEC|(is_mounted(node) ? 0 : O_EXCL));
                if (fd >= 0 || errno != EBUSY)
                        break;
                duration.tv_sec = 0;
                duration.tv_nsec = (100 * 1000 * 1000) + (rand() % 100 * 1000 * 1000);
                nanosleep(&duration, NULL);
        }
        if (fd < 0) {
                log_debug("unable to open '%s'", node);
                fprintf(stderr, "unable to open '%s'\n", node);
                rc = 1;
                goto exit;
        }
        log_debug("probing: '%s'", node);

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
                goto work;

        /* read drive and possibly current profile */
        if (cd_profiles(udev, fd) != 0)
                goto work;

        /* at this point we are guaranteed to have media in the drive - find out more about it */

        /* get session/track info */
        cd_media_toc(udev, fd);

        /* get writable media state */
        cd_media_info(udev, fd);

work:
        /* lock the media, so we enable eject button events */
        if (lock && cd_media) {
                log_debug("PREVENT_ALLOW_MEDIUM_REMOVAL (lock)");
                media_lock(udev, fd, true);
        }

        if (unlock && cd_media) {
                log_debug("PREVENT_ALLOW_MEDIUM_REMOVAL (unlock)");
                media_lock(udev, fd, false);
        }

        if (eject) {
                log_debug("PREVENT_ALLOW_MEDIUM_REMOVAL (unlock)");
                media_lock(udev, fd, false);
                log_debug("START_STOP_UNIT (eject)");
                media_eject(udev, fd);
        }

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
                printf("ID_CDROM_MEDIA_SESSION_NEXT=%u\n", cd_media_session_next);
        if (cd_media_session_count > 0)
                printf("ID_CDROM_MEDIA_SESSION_COUNT=%u\n", cd_media_session_count);
        if (cd_media_session_count > 1 && cd_media_session_last_offset > 0)
                printf("ID_CDROM_MEDIA_SESSION_LAST_OFFSET=%llu\n", cd_media_session_last_offset);
        if (cd_media_track_count > 0)
                printf("ID_CDROM_MEDIA_TRACK_COUNT=%u\n", cd_media_track_count);
        if (cd_media_track_count_audio > 0)
                printf("ID_CDROM_MEDIA_TRACK_COUNT_AUDIO=%u\n", cd_media_track_count_audio);
        if (cd_media_track_count_data > 0)
                printf("ID_CDROM_MEDIA_TRACK_COUNT_DATA=%u\n", cd_media_track_count_data);
exit:
        if (fd >= 0)
                close(fd);
        udev_unref(udev);
        log_close();
        return rc;
}
