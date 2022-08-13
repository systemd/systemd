/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * cdrom_id - optical drive and media information prober
 */

#include <fcntl.h>
#include <getopt.h>
#include <linux/cdrom.h>
#include <scsi/sg.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "fd-util.h"
#include "main-func.h"
#include "memory-util.h"
#include "random-util.h"
#include "sort-util.h"
#include "string-table.h"
#include "string-util.h"
#include "udev-util.h"
#include "unaligned.h"

static bool arg_eject = false;
static bool arg_lock = false;
static bool arg_unlock = false;
static const char *arg_node = NULL;

typedef enum Feature {
        FEATURE_RW_NONREMOVABLE = 0x01,
        FEATURE_RW_REMOVABLE    = 0x02,

        FEATURE_MO_SE           = 0x03, /* sector erase */
        FEATURE_MO_WO           = 0x04, /* write once */
        FEATURE_MO_AS           = 0x05, /* advance storage */

        FEATURE_CD_ROM          = 0x08,
        FEATURE_CD_R            = 0x09,
        FEATURE_CD_RW           = 0x0a,

        FEATURE_DVD_ROM         = 0x10,
        FEATURE_DVD_R           = 0x11,
        FEATURE_DVD_RAM         = 0x12,
        FEATURE_DVD_RW_RO       = 0x13, /* restricted overwrite mode */
        FEATURE_DVD_RW_SEQ      = 0x14, /* sequential mode */
        FEATURE_DVD_R_DL_SEQ    = 0x15, /* sequential recording */
        FEATURE_DVD_R_DL_JR     = 0x16, /* jump recording */
        FEATURE_DVD_RW_DL       = 0x17,
        FEATURE_DVD_R_DDR       = 0x18, /* download disc recording - dvd for css managed recording */
        FEATURE_DVD_PLUS_RW     = 0x1a,
        FEATURE_DVD_PLUS_R      = 0x1b,

        FEATURE_DDCD_ROM        = 0x20,
        FEATURE_DDCD_R          = 0x21,
        FEATURE_DDCD_RW         = 0x22,

        FEATURE_DVD_PLUS_RW_DL  = 0x2a,
        FEATURE_DVD_PLUS_R_DL   = 0x2b,

        FEATURE_BD              = 0x40,
        FEATURE_BD_R_SRM        = 0x41, /* sequential recording mode */
        FEATURE_BD_R_RRM        = 0x42, /* random recording mode */
        FEATURE_BD_RE           = 0x43,

        FEATURE_HDDVD           = 0x50,
        FEATURE_HDDVD_R         = 0x51,
        FEATURE_HDDVD_RAM       = 0x52,
        FEATURE_HDDVD_RW        = 0x53,
        FEATURE_HDDVD_R_DL      = 0x58,
        FEATURE_HDDVD_RW_DL     = 0x5a,

        FEATURE_MRW,
        FEATURE_MRW_W,

        _FEATURE_MAX,
        _FEATURE_INVALID = -EINVAL,
} Feature;

typedef enum MediaState {
        MEDIA_STATE_BLANK      = 0,
        MEDIA_STATE_APPENDABLE = 1,
        MEDIA_STATE_COMPLETE   = 2,
        MEDIA_STATE_OTHER      = 3,
        _MEDIA_STATE_MAX,
        _MEDIA_STATE_INVALID = -EINVAL,
} MediaState;

typedef struct Context {
        int fd;

        Feature *drive_features;
        size_t n_drive_feature;

        Feature media_feature;
        bool has_media;

        MediaState media_state;
        unsigned media_session_next;
        unsigned media_session_count;
        unsigned media_track_count;
        unsigned media_track_count_data;
        unsigned media_track_count_audio;
        uint64_t media_session_last_offset;
} Context;

#define CONTEXT_EMPTY {                                 \
                .fd = -1,                               \
                .media_feature = _FEATURE_INVALID,      \
                .media_state = _MEDIA_STATE_INVALID,    \
        }

static void context_clear(Context *c) {
        if (!c)
                return;

        safe_close(c->fd);
        free(c->drive_features);
}

static bool drive_has_feature(const Context *c, Feature f) {
        assert(c);

        for (size_t i = 0; i < c->n_drive_feature; i++)
                if (c->drive_features[i] == f)
                        return true;

        return false;
}

static int set_drive_feature(Context *c, Feature f) {
        assert(c);

        if (drive_has_feature(c, f))
                return 0;

        if (!GREEDY_REALLOC(c->drive_features, c->n_drive_feature + 1))
                return -ENOMEM;

        c->drive_features[c->n_drive_feature++] = f;
        return 1;
}

#define ERRCODE(s)      ((((s)[2] & 0x0F) << 16) | ((s)[12] << 8) | ((s)[13]))
#define SK(errcode)     (((errcode) >> 16) & 0xF)
#define ASC(errcode)    (((errcode) >> 8) & 0xFF)
#define ASCQ(errcode)   ((errcode) & 0xFF)
#define CHECK_CONDITION 0x01

static int log_scsi_debug_errno(int error, const char *msg) {
        assert(error != 0);

        /* error < 0 means errno-style error, error > 0 means SCSI error */

        if (error < 0)
                return log_debug_errno(error, "Failed to %s: %m", msg);

        return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                               "Failed to %s with SK=%X/ASC=%02X/ACQ=%02X",
                               msg, SK(error), ASC(error), ASCQ(error));
}

struct scsi_cmd {
        struct cdrom_generic_command cgc;
        union {
                struct request_sense s;
                unsigned char u[18];
        } _sense;
        struct sg_io_hdr sg_io;
};

static void scsi_cmd_init(struct scsi_cmd *cmd) {
        memzero(cmd, sizeof(struct scsi_cmd));
        cmd->cgc.quiet = 1;
        cmd->cgc.sense = &cmd->_sense.s;
        cmd->sg_io.interface_id = 'S';
        cmd->sg_io.mx_sb_len = sizeof(cmd->_sense);
        cmd->sg_io.cmdp = cmd->cgc.cmd;
        cmd->sg_io.sbp = cmd->_sense.u;
        cmd->sg_io.flags = SG_FLAG_LUN_INHIBIT | SG_FLAG_DIRECT_IO;
}

static void scsi_cmd_set(struct scsi_cmd *cmd, size_t i, unsigned char arg) {
        cmd->sg_io.cmd_len = i + 1;
        cmd->cgc.cmd[i] = arg;
}

static int scsi_cmd_run(struct scsi_cmd *cmd, int fd, unsigned char *buf, size_t bufsize) {
        int r;

        assert(cmd);
        assert(fd >= 0);
        assert(buf || bufsize == 0);

        /* Return 0 on success. On failure, return negative errno or positive error code. */

        if (bufsize > 0) {
                cmd->sg_io.dxferp = buf;
                cmd->sg_io.dxfer_len = bufsize;
                cmd->sg_io.dxfer_direction = SG_DXFER_FROM_DEV;
        } else
                cmd->sg_io.dxfer_direction = SG_DXFER_NONE;

        if (ioctl(fd, SG_IO, &cmd->sg_io) < 0)
                return -errno;

        if ((cmd->sg_io.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
                if (cmd->sg_io.masked_status & CHECK_CONDITION) {
                        r = ERRCODE(cmd->_sense.u);
                        if (r != 0)
                                return r;
                }
                return -EIO;
        }

        return 0;
}

static int scsi_cmd_run_and_log(struct scsi_cmd *cmd, int fd, unsigned char *buf, size_t bufsize, const char *msg) {
        int r;

        assert(msg);

        r = scsi_cmd_run(cmd, fd, buf, bufsize);
        if (r != 0)
                return log_scsi_debug_errno(r, msg);

        return 0;
}

static int media_lock(int fd, bool lock) {
        /* disable the kernel's lock logic */
        if (ioctl(fd, CDROM_CLEAR_OPTIONS, CDO_LOCK) < 0)
                log_debug_errno(errno, "Failed to issue ioctl(CDROM_CLEAR_OPTIONS, CDO_LOCK), ignoring: %m");

        if (ioctl(fd, CDROM_LOCKDOOR, lock ? 1 : 0) < 0)
                return log_debug_errno(errno, "Failed to issue ioctl(CDROM_LOCKDOOR): %m");

        return 0;
}

static int media_eject(int fd) {
        struct scsi_cmd sc;

        scsi_cmd_init(&sc);
        scsi_cmd_set(&sc, 0, GPCMD_START_STOP_UNIT);
        scsi_cmd_set(&sc, 4, 0x02);
        scsi_cmd_set(&sc, 5, 0);

        return scsi_cmd_run_and_log(&sc, fd, NULL, 0, "start/stop unit");
}

static int cd_capability_compat(Context *c) {
        int capability, r;

        assert(c);

        capability = ioctl(c->fd, CDROM_GET_CAPABILITY, NULL);
        if (capability < 0)
                return log_debug_errno(errno, "CDROM_GET_CAPABILITY failed");

        if (capability & CDC_CD_R) {
                r = set_drive_feature(c, FEATURE_CD_R);
                if (r < 0)
                        return log_oom_debug();
        }
        if (capability & CDC_CD_RW) {
                r = set_drive_feature(c, FEATURE_CD_RW);
                if (r < 0)
                        return log_oom_debug();
        }
        if (capability & CDC_DVD) {
                r = set_drive_feature(c, FEATURE_DVD_ROM);
                if (r < 0)
                        return log_oom_debug();
        }
        if (capability & CDC_DVD_R) {
                r = set_drive_feature(c, FEATURE_DVD_R);
                if (r < 0)
                        return log_oom_debug();
        }
        if (capability & CDC_DVD_RAM) {
                r = set_drive_feature(c, FEATURE_DVD_RAM);
                if (r < 0)
                        return log_oom_debug();
        }
        if (capability & CDC_MRW) {
                r = set_drive_feature(c, FEATURE_MRW);
                if (r < 0)
                        return log_oom_debug();
        }
        if (capability & CDC_MRW_W) {
                r = set_drive_feature(c, FEATURE_MRW_W);
                if (r < 0)
                        return log_oom_debug();
        }

        return 0;
}

static int cd_media_compat(Context *c) {
        int r;

        assert(c);

        r = ioctl(c->fd, CDROM_DRIVE_STATUS, CDSL_CURRENT);
        if (r < 0)
                return log_debug_errno(errno, "ioctl(CDROM_DRIVE_STATUS) failed: %m");
        if (r != CDS_DISC_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOMEDIUM),
                                       "ioctl(CDROM_DRIVE_STATUS) → %d (%s), ignoring.",
                                       r,
                                       r == CDS_NO_INFO ? "no info" :
                                       r == CDS_NO_DISC ? "no disc" :
                                       r == CDS_TRAY_OPEN ? "tray open" :
                                       r == CDS_DRIVE_NOT_READY ? "drive not ready" :
                                       "unknown status");

        c->has_media = true;
        return 0;
}

static int cd_inquiry(Context *c) {
        struct scsi_cmd sc;
        unsigned char inq[36];
        int r;

        assert(c);

        scsi_cmd_init(&sc);
        scsi_cmd_set(&sc, 0, GPCMD_INQUIRY);
        scsi_cmd_set(&sc, 4, sizeof(inq));
        scsi_cmd_set(&sc, 5, 0);
        r = scsi_cmd_run_and_log(&sc, c->fd, inq, sizeof(inq), "inquire");
        if (r < 0)
                return r;

        if ((inq[0] & 0x1F) != 5)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Not an MMC unit.");

        log_debug("INQUIRY: [%.8s][%.16s][%.4s]", inq + 8, inq + 16, inq + 32);
        return 0;
}

static int feature_profiles(Context *c, const unsigned char *profiles, size_t size) {
        int r;

        assert(c);

        for (size_t i = 0; i + 4 <= size; i += 4) {
                r = set_drive_feature(c, (Feature) unaligned_read_be16(&profiles[i]));
                if (r < 0)
                        return log_oom_debug();
        }

        return 1;
}

static int cd_profiles_old_mmc(Context *c) {
        disc_information discinfo;
        struct scsi_cmd sc;
        size_t len;
        int r;

        assert(c);

        scsi_cmd_init(&sc);
        scsi_cmd_set(&sc, 0, GPCMD_READ_DISC_INFO);
        scsi_cmd_set(&sc, 8, sizeof(discinfo.disc_information_length));
        scsi_cmd_set(&sc, 9, 0);
        r = scsi_cmd_run_and_log(&sc, c->fd, (unsigned char *)&discinfo.disc_information_length, sizeof(discinfo.disc_information_length), "read disc information");
        if (r >= 0) {
                /* Not all drives have the same disc_info length, so requeue
                 * packet with the length the drive tells us it can supply */
                len = be16toh(discinfo.disc_information_length) + sizeof(discinfo.disc_information_length);
                if (len > sizeof(discinfo))
                        len = sizeof(discinfo);

                scsi_cmd_init(&sc);
                scsi_cmd_set(&sc, 0, GPCMD_READ_DISC_INFO);
                scsi_cmd_set(&sc, 8, len);
                scsi_cmd_set(&sc, 9, 0);
                r = scsi_cmd_run_and_log(&sc, c->fd, (unsigned char *)&discinfo, len, "read disc information");
        }
        if (r < 0) {
                if (c->has_media) {
                        log_debug("No current profile, but disc is present; assuming CD-ROM.");
                        c->media_feature = FEATURE_CD_ROM;
                        c->media_track_count = 1;
                        c->media_track_count_data = 1;
                        return 1;
                } else
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOMEDIUM),
                                               "no current profile, assuming no media.");
        };

        c->has_media = true;

        if (discinfo.erasable)
                c->media_feature = FEATURE_CD_RW;
        else if (discinfo.disc_status < 2 && drive_has_feature(c, FEATURE_CD_R))
                c->media_feature = FEATURE_CD_R;
        else
                c->media_feature = FEATURE_CD_ROM;

        return 0;
}

static int cd_profiles(Context *c) {
        struct scsi_cmd sc;
        unsigned char features[65530];
        unsigned cur_profile;
        size_t len;
        int r;

        assert(c);

        /* First query the current profile */
        scsi_cmd_init(&sc);
        scsi_cmd_set(&sc, 0, GPCMD_GET_CONFIGURATION);
        scsi_cmd_set(&sc, 8, 8);
        scsi_cmd_set(&sc, 9, 0);
        r = scsi_cmd_run(&sc, c->fd, features, 8);
        if (r != 0) {
                /* handle pre-MMC2 drives which do not support GET CONFIGURATION */
                if (r > 0 && SK(r) == 0x5 && IN_SET(ASC(r), 0x20, 0x24)) {
                        log_debug("Drive is pre-MMC2 and does not support 46h get configuration command; "
                                  "trying to work around the problem.");
                        return cd_profiles_old_mmc(c);
                }

                return log_scsi_debug_errno(r, "get configuration");
        }

        cur_profile = unaligned_read_be16(&features[6]);
        if (cur_profile > 0) {
                log_debug("current profile 0x%02x", cur_profile);
                c->media_feature = (Feature) cur_profile;
                c->has_media = true;
        } else {
                log_debug("no current profile, assuming no media");
                c->has_media = false;
        }

        len = unaligned_read_be32(features);
        log_debug("GET CONFIGURATION: size of features buffer %zu", len);

        if (len > sizeof(features)) {
                log_debug("Cannot get features in a single query, truncating.");
                len = sizeof(features);
        } else if (len <= 8)
                len = sizeof(features);

        /* Now get the full feature buffer */
        scsi_cmd_init(&sc);
        scsi_cmd_set(&sc, 0, GPCMD_GET_CONFIGURATION);
        scsi_cmd_set(&sc, 7, (len >> 8) & 0xff);
        scsi_cmd_set(&sc, 8, len & 0xff);
        scsi_cmd_set(&sc, 9, 0);
        r = scsi_cmd_run_and_log(&sc, c->fd, features, len, "get configuration");
        if (r < 0)
                return r;

        /* parse the length once more, in case the drive decided to have other features suddenly :) */
        len = unaligned_read_be32(features);
        log_debug("GET CONFIGURATION: size of features buffer %zu", len);

        if (len > sizeof(features)) {
                log_debug("Cannot get features in a single query, truncating.");
                len = sizeof(features);
        }

        /* device features */
        for (size_t i = 8; i + 4 < len; i += 4 + features[i + 3]) {
                unsigned feature;

                feature = unaligned_read_be16(&features[i]);

                switch (feature) {
                case 0x00:
                        log_debug("GET CONFIGURATION: feature 'profiles', with %u entries", features[i + 3] / 4);
                        feature_profiles(c, features + i + 4, MIN(features[i + 3], len - i - 4));
                        break;
                default:
                        log_debug("GET CONFIGURATION: feature 0x%04x <ignored>, with 0x%02x bytes", feature, features[i + 3]);
                        break;
                }
        }

        return c->has_media;
}

static const char * const media_state_table[_MEDIA_STATE_MAX] = {
        [MEDIA_STATE_BLANK]      = "blank",
        [MEDIA_STATE_APPENDABLE] = "appendable",
        [MEDIA_STATE_COMPLETE]   = "complete",
        [MEDIA_STATE_OTHER]      = "other",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(media_state, MediaState);

static int dvd_ram_media_update_state(Context *c) {
        struct scsi_cmd sc;
        unsigned char dvdstruct[8];
        unsigned char format[12];
        unsigned char len;
        int r;

        assert(c);

        /* Return 1 if media state is determined. */

        if (c->media_feature != FEATURE_DVD_RAM)
                return 0;

        /* a write protected dvd-ram may report "complete" status */
        scsi_cmd_init(&sc);
        scsi_cmd_set(&sc, 0, GPCMD_READ_DVD_STRUCTURE);
        scsi_cmd_set(&sc, 7, 0xC0);
        scsi_cmd_set(&sc, 9, sizeof(dvdstruct));
        scsi_cmd_set(&sc, 11, 0);
        r = scsi_cmd_run_and_log(&sc, c->fd, dvdstruct, sizeof(dvdstruct), "read DVD structure");
        if (r < 0)
                return r;

        if (dvdstruct[4] & 0x02) {
                c->media_state = MEDIA_STATE_COMPLETE;
                log_debug("Write-protected DVD-RAM media inserted");
                return 1;
        }

        /* let's make sure we don't try to read unformatted media */
        scsi_cmd_init(&sc);
        scsi_cmd_set(&sc, 0, GPCMD_READ_FORMAT_CAPACITIES);
        scsi_cmd_set(&sc, 8, sizeof(format));
        scsi_cmd_set(&sc, 9, 0);
        r = scsi_cmd_run_and_log(&sc, c->fd, format, sizeof(format), "read DVD format capacities");
        if (r < 0)
                return r;

        len = format[3];
        if (len & 7 || len < 16)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid format capacities length.");

        switch (format[8] & 3) {
        case 1:
                /* This means that last format was interrupted or failed, blank dvd-ram discs are
                 * factory formatted. Take no action here as it takes quite a while to reformat a
                 * dvd-ram and it's not automatically started. */
                log_debug("Unformatted DVD-RAM media inserted.");
                return 1;

        case 2:
                log_debug("Formatted DVD-RAM media inserted.");
                return 0;

        case 3:
                c->has_media = false;
                return log_debug_errno(SYNTHETIC_ERRNO(ENOMEDIUM),
                                       "Format capacities returned no media.");
        }

        return 0;
}

static int dvd_media_update_state(Context *c) {
        struct scsi_cmd sc;
        unsigned char buffer[32 * 2048];
        int r;

        r = dvd_ram_media_update_state(c);
        if (r != 0)
                return r;

        /* Take a closer look at formatted media (unformatted DVD+RW
         * has "blank" status", DVD-RAM was examined earlier) and check
         * for ISO and UDF PVDs or a fs superblock presence and do it
         * in one ioctl (we need just sectors 0 and 16) */

        scsi_cmd_init(&sc);
        scsi_cmd_set(&sc, 0, GPCMD_READ_10);
        scsi_cmd_set(&sc, 5, 0);
        scsi_cmd_set(&sc, 8, sizeof(buffer)/2048);
        scsi_cmd_set(&sc, 9, 0);
        r = scsi_cmd_run_and_log(&sc, c->fd, buffer, sizeof(buffer), "read first 32 blocks");
        if (r < 0) {
                c->has_media = false;
                return r;
        }

        /* if any non-zero data is found in sector 16 (iso and udf) or
         * eventually 0 (fat32 boot sector, ext2 superblock, etc), disc
         * is assumed non-blank */

        for (size_t offset = 32768; offset < 32768 + 2048; offset++)
                if (buffer[offset] != 0) {
                        log_debug("Data in block 16, assuming complete.");
                        return 0;
                }

        for (size_t offset = 0; offset < 2048; offset++)
                if (buffer[offset] != 0) {
                        log_debug("Data in block 0, assuming complete.");
                        return 0;
                }

        log_debug("No data in blocks 0 or 16, assuming blank.");
        c->media_state = MEDIA_STATE_BLANK;
        return 0;
}

static int cd_media_info(Context *c) {
        struct scsi_cmd sc;
        unsigned char header[32];
        MediaState state;
        int r;

        assert(c);

        scsi_cmd_init(&sc);
        scsi_cmd_set(&sc, 0, GPCMD_READ_DISC_INFO);
        scsi_cmd_set(&sc, 8, sizeof(header));
        scsi_cmd_set(&sc, 9, 0);
        r = scsi_cmd_run_and_log(&sc, c->fd, header, sizeof(header), "read disc information");
        if (r < 0)
                return r;

        c->has_media = true;
        log_debug("disk type %02x", header[8]);

        state = (MediaState) (header[2] & 0x03);
        log_debug("hardware reported media status: %s", strna(media_state_to_string(state)));

        /* exclude plain CDROM, some fake cdroms return 0 for "blank" media here */
        if (c->media_feature != FEATURE_CD_ROM)
                c->media_state = state;

        /* fresh DVD-RW in restricted overwrite mode reports itself as
         * "appendable"; change it to "blank" to make it consistent with what
         * gets reported after blanking, and what userspace expects. */
        if (c->media_feature == FEATURE_DVD_RW_RO && state == MEDIA_STATE_APPENDABLE)
                c->media_state = MEDIA_STATE_BLANK;

        /* DVD+RW discs (and DVD-RW in restricted mode) once formatted are
         * always "complete", DVD-RAM are "other" or "complete" if the disc is
         * write protected; we need to check the contents if it is blank */
        if (IN_SET(c->media_feature, FEATURE_DVD_RW_RO, FEATURE_DVD_PLUS_RW, FEATURE_DVD_PLUS_RW_DL, FEATURE_DVD_RAM) &&
            IN_SET(state, MEDIA_STATE_COMPLETE, MEDIA_STATE_OTHER)) {
                r = dvd_media_update_state(c);
                if (r < 0)
                        return r;
        }

        /* "other" is e. g. DVD-RAM, can't append sessions there; DVDs in
         * restricted overwrite mode can never append, only in sequential mode */
        if (c->media_feature != FEATURE_DVD_RW_RO && IN_SET(state, MEDIA_STATE_BLANK, MEDIA_STATE_APPENDABLE))
                c->media_session_next = header[10] << 8 | header[5];
        c->media_session_count = header[9] << 8 | header[4];
        c->media_track_count = header[11] << 8 | header[6];

        return 0;
}

static int cd_media_toc(Context *c) {
        struct scsi_cmd sc;
        unsigned char header[12];
        unsigned char toc[65536];
        unsigned num_tracks;
        size_t len;
        int r;

        assert(c);

        scsi_cmd_init(&sc);
        scsi_cmd_set(&sc, 0, GPCMD_READ_TOC_PMA_ATIP);
        scsi_cmd_set(&sc, 6, 1);
        scsi_cmd_set(&sc, 8, sizeof(header));
        scsi_cmd_set(&sc, 9, 0);
        r = scsi_cmd_run_and_log(&sc, c->fd, header, sizeof(header), "read TOC");
        if (r < 0)
                return r;

        len = unaligned_read_be16(header) + 2;
        log_debug("READ TOC: len: %zu, start track: %u, end track: %u", len, header[2], header[3]);

        if (len > sizeof(toc))
                return -1;
        /* empty media has no tracks */
        if (len < 8)
                return 0;

        /* 2: first track, 3: last track */
        num_tracks = header[3] - header[2] + 1;

        scsi_cmd_init(&sc);
        scsi_cmd_set(&sc, 0, GPCMD_READ_TOC_PMA_ATIP);
        scsi_cmd_set(&sc, 6, header[2]); /* First Track/Session Number */
        scsi_cmd_set(&sc, 7, (len >> 8) & 0xff);
        scsi_cmd_set(&sc, 8, len & 0xff);
        scsi_cmd_set(&sc, 9, 0);
        r = scsi_cmd_run_and_log(&sc, c->fd, toc, len, "read TOC (tracks)");
        if (r < 0)
                return r;

        /* Take care to not iterate beyond the last valid track as specified in
         * the TOC, but also avoid going beyond the TOC length, just in case
         * the last track number is invalidly large */
        for (size_t i = 4; i + 8 <= len && num_tracks > 0; i += 8, --num_tracks) {
                bool is_data_track;
                uint32_t block;

                is_data_track = (toc[i + 1] & 0x04) != 0;
                block = unaligned_read_be32(&toc[i + 4]);

                log_debug("track=%u info=0x%x(%s) start_block=%"PRIu32,
                          toc[i + 2], toc[i + 1] & 0x0f, is_data_track ? "data":"audio", block);

                if (is_data_track)
                        c->media_track_count_data++;
                else
                        c->media_track_count_audio++;
        }

        scsi_cmd_init(&sc);
        scsi_cmd_set(&sc, 0, GPCMD_READ_TOC_PMA_ATIP);
        scsi_cmd_set(&sc, 2, 1); /* Session Info */
        scsi_cmd_set(&sc, 8, sizeof(header));
        scsi_cmd_set(&sc, 9, 0);
        r = scsi_cmd_run_and_log(&sc, c->fd, header, sizeof(header), "read TOC (multi session)");
        if (r < 0)
                return r;

        len = unaligned_read_be32(&header[8]);
        log_debug("last track %u starts at block %zu", header[4+2], len);
        c->media_session_last_offset = (uint64_t) len * 2048;

        return 0;
}

static int open_drive(Context *c) {
        int fd;

        assert(c);
        assert(c->fd < 0);

        for (int cnt = 0;; cnt++) {
                fd = open(arg_node, O_RDONLY|O_NONBLOCK|O_CLOEXEC);
                if (fd >= 0)
                        break;
                if (++cnt >= 20 || errno != EBUSY)
                        return log_debug_errno(errno, "Unable to open '%s': %m", arg_node);

                (void) usleep(100 * USEC_PER_MSEC + random_u64_range(100 * USEC_PER_MSEC));
        }

        log_debug("probing: '%s'", arg_node);
        c->fd = fd;
        return 0;
}

typedef struct FeatureToString {
        Feature feature;
        const char *str;
} FeatureToString;

static const FeatureToString feature_to_string[] = {
        { .feature = FEATURE_RW_NONREMOVABLE, .str = "RW_NONREMOVABLE", },
        { .feature = FEATURE_RW_REMOVABLE,    .str = "RW_REMOVABLE", },

        { .feature = FEATURE_MO_SE,           .str = "MO_SE", },
        { .feature = FEATURE_MO_WO,           .str = "MO_WO", },
        { .feature = FEATURE_MO_AS,           .str = "MO_AS", },

        { .feature = FEATURE_CD_ROM,          .str = "CD", },
        { .feature = FEATURE_CD_R,            .str = "CD_R", },
        { .feature = FEATURE_CD_RW,           .str = "CD_RW", },

        { .feature = FEATURE_DVD_ROM,         .str = "DVD", },
        { .feature = FEATURE_DVD_R,           .str = "DVD_R", },
        { .feature = FEATURE_DVD_RAM,         .str = "DVD_RAM", },
        { .feature = FEATURE_DVD_RW_RO,       .str = "DVD_RW_RO", },
        { .feature = FEATURE_DVD_RW_SEQ,      .str = "DVD_RW_SEQ", },
        { .feature = FEATURE_DVD_R_DL_SEQ,    .str = "DVD_R_DL_SEQ", },
        { .feature = FEATURE_DVD_R_DL_JR,     .str = "DVD_R_DL_JR", },
        { .feature = FEATURE_DVD_RW_DL,       .str = "DVD_RW_DL", },
        { .feature = FEATURE_DVD_R_DDR,       .str = "DVD_R_DDR", },
        { .feature = FEATURE_DVD_PLUS_RW,     .str = "DVD_PLUS_RW", },
        { .feature = FEATURE_DVD_PLUS_R,      .str = "DVD_PLUS_R", },

        { .feature = FEATURE_DDCD_ROM,        .str = "DDCD", },
        { .feature = FEATURE_DDCD_R,          .str = "DDCD_R", },
        { .feature = FEATURE_DDCD_RW,         .str = "DDCD_RW", },

        { .feature = FEATURE_DVD_PLUS_RW_DL,  .str = "DVD_PLUS_RW_DL", },
        { .feature = FEATURE_DVD_PLUS_R_DL,   .str = "DVD_PLUS_R_DL", },

        { .feature = FEATURE_BD,              .str = "BD", },
        { .feature = FEATURE_BD_R_SRM,        .str = "BD_R_SRM", },
        { .feature = FEATURE_BD_R_RRM,        .str = "BD_R_RRM", },
        { .feature = FEATURE_BD_RE,           .str = "BD_RE", },

        { .feature = FEATURE_HDDVD,           .str = "HDDVD", },
        { .feature = FEATURE_HDDVD_R,         .str = "HDDVD_R", },
        { .feature = FEATURE_HDDVD_RAM,       .str = "HDDVD_RAM", },
        { .feature = FEATURE_HDDVD_RW,        .str = "HDDVD_RW", },
        { .feature = FEATURE_HDDVD_R_DL,      .str = "HDDVD_R_DL", },
        { .feature = FEATURE_HDDVD_RW_DL,     .str = "HDDVD_RW_DL", },

        { .feature = FEATURE_MRW,             .str = "MRW", },
        { .feature = FEATURE_MRW_W,           .str = "MRW_W", },
};

static int feature_to_string_compare_func(const FeatureToString *a, const FeatureToString *b) {
        assert(a);
        assert(b);

        return CMP(a->feature, b->feature);
}

static void print_feature(Feature feature, const char *prefix) {
        FeatureToString *found, in = {
                .feature = feature,
        };

        assert(prefix);

        found = typesafe_bsearch(&in, feature_to_string, ELEMENTSOF(feature_to_string), feature_to_string_compare_func);
        if (!found)
                return (void) log_debug("Unknown feature 0x%02x, ignoring.", (unsigned) feature);

        printf("%s_%s=1\n", prefix, found->str);
}

static void print_properties(const Context *c) {
        const char *state;

        assert(c);

        printf("ID_CDROM=1\n");
        for (size_t i = 0; i < c->n_drive_feature; i++)
                print_feature(c->drive_features[i], "ID_CDROM");

        if (drive_has_feature(c, FEATURE_MO_SE) ||
            drive_has_feature(c, FEATURE_MO_WO) ||
            drive_has_feature(c, FEATURE_MO_AS))
                printf("ID_CDROM_MO=1\n");

        if (drive_has_feature(c, FEATURE_DVD_RW_RO) ||
            drive_has_feature(c, FEATURE_DVD_RW_SEQ))
                printf("ID_CDROM_DVD_RW=1\n");

        if (drive_has_feature(c, FEATURE_DVD_R_DL_SEQ) ||
            drive_has_feature(c, FEATURE_DVD_R_DL_JR))
                printf("ID_CDROM_DVD_R_DL=1\n");

        if (drive_has_feature(c, FEATURE_DVD_R_DDR))
                printf("ID_CDROM_DVD_R=1\n");

        if (drive_has_feature(c, FEATURE_BD_R_SRM) ||
            drive_has_feature(c, FEATURE_BD_R_RRM))
                printf("ID_CDROM_BD_R=1\n");

        if (c->has_media) {
                printf("ID_CDROM_MEDIA=1\n");
                print_feature(c->media_feature, "ID_CDROM_MEDIA");

                if (IN_SET(c->media_feature, FEATURE_MO_SE, FEATURE_MO_WO, FEATURE_MO_AS))
                        printf("ID_CDROM_MEDIA_MO=1\n");

                if (IN_SET(c->media_feature, FEATURE_DVD_RW_RO, FEATURE_DVD_RW_SEQ))
                        printf("ID_CDROM_MEDIA_DVD_RW=1\n");

                if (IN_SET(c->media_feature, FEATURE_DVD_R_DL_SEQ, FEATURE_DVD_R_DL_JR))
                        printf("ID_CDROM_MEDIA_DVD_R_DL=1\n");

                if (c->media_feature == FEATURE_DVD_R_DDR)
                        printf("ID_CDROM_MEDIA_DVD_R=1\n");

                if (IN_SET(c->media_feature, FEATURE_BD_R_SRM, FEATURE_BD_R_RRM))
                        printf("ID_CDROM_MEDIA_BD_R=1\n");
        }

        state = media_state_to_string(c->media_state);
        if (state)
                printf("ID_CDROM_MEDIA_STATE=%s\n", state);
        if (c->media_session_next > 0)
                printf("ID_CDROM_MEDIA_SESSION_NEXT=%u\n", c->media_session_next);
        if (c->media_session_count > 0)
                printf("ID_CDROM_MEDIA_SESSION_COUNT=%u\n", c->media_session_count);
        if (c->media_session_count > 1 && c->media_session_last_offset > 0)
                printf("ID_CDROM_MEDIA_SESSION_LAST_OFFSET=%" PRIu64 "\n", c->media_session_last_offset);
        if (c->media_track_count > 0)
                printf("ID_CDROM_MEDIA_TRACK_COUNT=%u\n", c->media_track_count);
        if (c->media_track_count_audio > 0)
                printf("ID_CDROM_MEDIA_TRACK_COUNT_AUDIO=%u\n", c->media_track_count_audio);
        if (c->media_track_count_data > 0)
                printf("ID_CDROM_MEDIA_TRACK_COUNT_DATA=%u\n", c->media_track_count_data);
}

static int help(void) {
        printf("Usage: %s [options] <device>\n"
               "  -l --lock-media    lock the media (to enable eject request events)\n"
               "  -u --unlock-media  unlock the media\n"
               "  -e --eject-media   eject the media\n"
               "  -d --debug         print debug messages to stderr\n"
               "  -h --help          print this help text\n"
               "\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "lock-media",   no_argument, NULL, 'l' },
                { "unlock-media", no_argument, NULL, 'u' },
                { "eject-media",  no_argument, NULL, 'e' },
                { "debug",        no_argument, NULL, 'd' },
                { "help",         no_argument, NULL, 'h' },
                {}
        };
        int c;

        while ((c = getopt_long(argc, argv, "deluh", options, NULL)) >= 0)
                switch (c) {
                case 'l':
                        arg_lock = true;
                        break;
                case 'u':
                        arg_unlock = true;
                        break;
                case 'e':
                        arg_eject = true;
                        break;
                case 'd':
                        log_set_target(LOG_TARGET_CONSOLE);
                        log_set_max_level(LOG_DEBUG);
                        log_open();
                        break;
                case 'h':
                        return help();
                default:
                        assert_not_reached();
                }

        arg_node = argv[optind];
        if (!arg_node)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No device specified.");

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(context_clear) Context c = CONTEXT_EMPTY;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        udev_parse_config();
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = open_drive(&c);
        if (r < 0)
                return r;

        /* same data as original cdrom_id */
        r = cd_capability_compat(&c);
        if (r < 0)
                return r;

        /* check for media - don't bail if there's no media as we still need to
         * to read profiles */
        (void) cd_media_compat(&c);

        /* check if drive talks MMC */
        if (cd_inquiry(&c) < 0)
                goto work;

        r = cd_profiles(&c); /* read drive and possibly current profile */
        if (r > 0) {
                /* at this point we are guaranteed to have media in the drive - find out more about it */

                /* get session/track info */
                (void) cd_media_toc(&c);

                /* get writable media state */
                (void) cd_media_info(&c);
        }

work:
        /* lock the media, so we enable eject button events */
        if (arg_lock && c.has_media) {
                log_debug("PREVENT_ALLOW_MEDIUM_REMOVAL (lock)");
                (void) media_lock(c.fd, true);
        }

        if (arg_unlock && c.has_media) {
                log_debug("PREVENT_ALLOW_MEDIUM_REMOVAL (unlock)");
                (void) media_lock(c.fd, false);
        }

        if (arg_eject) {
                log_debug("PREVENT_ALLOW_MEDIUM_REMOVAL (unlock)");
                (void) media_lock(c.fd, false);
                log_debug("START_STOP_UNIT (eject)");
                (void) media_eject(c.fd);
        }

        print_properties(&c);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
