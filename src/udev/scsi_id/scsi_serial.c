/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © IBM Corp. 2003
 *
 * Author: Patrick Mansfield<patmans@us.ibm.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bsg.h>
#include <linux/types.h>
#include <scsi/scsi.h>
#include <scsi/sg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "devnum-util.h"
#include "memory-util.h"
#include "random-util.h"
#include "scsi.h"
#include "scsi_id.h"
#include "string-util.h"

/*
 * A priority based list of id, naa, and binary/ascii for the identifier
 * descriptor in VPD page 0x83.
 *
 * Brute force search for a match starting with the first value in the
 * following id_search_list. This is not a performance issue, since there
 * is normally one or some small number of descriptors.
 */
static const struct scsi_id_search_values id_search_list[] = {
        { SCSI_ID_TGTGROUP, SCSI_ID_NAA_DONT_CARE,         SCSI_ID_BINARY },
        { SCSI_ID_NAA,      SCSI_ID_NAA_IEEE_REG_EXTENDED, SCSI_ID_BINARY },
        { SCSI_ID_NAA,      SCSI_ID_NAA_IEEE_REG_EXTENDED, SCSI_ID_ASCII  },
        { SCSI_ID_NAA,      SCSI_ID_NAA_IEEE_REG,          SCSI_ID_BINARY },
        { SCSI_ID_NAA,      SCSI_ID_NAA_IEEE_REG,          SCSI_ID_ASCII  },
        /*
         * Devices already exist using NAA values that are now marked
         * reserved. These should not conflict with other values, or it is
         * a bug in the device. As long as we find the IEEE extended one
         * first, we really don't care what other ones are used. Using
         * don't care here means that a device that returns multiple
         * non-IEEE descriptors in a random order will get different
         * names.
         */
        { SCSI_ID_NAA,             SCSI_ID_NAA_DONT_CARE, SCSI_ID_BINARY },
        { SCSI_ID_NAA,             SCSI_ID_NAA_DONT_CARE, SCSI_ID_ASCII  },
        { SCSI_ID_EUI_64,          SCSI_ID_NAA_DONT_CARE, SCSI_ID_BINARY },
        { SCSI_ID_EUI_64,          SCSI_ID_NAA_DONT_CARE, SCSI_ID_ASCII  },
        { SCSI_ID_T10_VENDOR,      SCSI_ID_NAA_DONT_CARE, SCSI_ID_BINARY },
        { SCSI_ID_T10_VENDOR,      SCSI_ID_NAA_DONT_CARE, SCSI_ID_ASCII  },
        { SCSI_ID_VENDOR_SPECIFIC, SCSI_ID_NAA_DONT_CARE, SCSI_ID_BINARY },
        { SCSI_ID_VENDOR_SPECIFIC, SCSI_ID_NAA_DONT_CARE, SCSI_ID_ASCII  },
};

static const char hex_str[]="0123456789abcdef";

/*
 * Values returned in the result/status, only the ones used by the code
 * are used here.
 */

#define DID_NO_CONNECT               0x01        /* Unable to connect before timeout */
#define DID_BUS_BUSY                 0x02        /* Bus remain busy until timeout */
#define DID_TIME_OUT                 0x03        /* Timed out for some other reason */
#define DID_TRANSPORT_DISRUPTED      0x0e        /* Transport disrupted and should retry */
#define DRIVER_TIMEOUT               0x06
#define DRIVER_SENSE                 0x08        /* Sense_buffer has been set */

/* The following "category" function returns one of the following */
#define SG_ERR_CAT_CLEAN                0        /* No errors or other information */
#define SG_ERR_CAT_MEDIA_CHANGED        1        /* interpreted from sense buffer */
#define SG_ERR_CAT_RESET                2        /* interpreted from sense buffer */
#define SG_ERR_CAT_TIMEOUT              3
#define SG_ERR_CAT_RECOVERED            4        /* Successful command after recovered err */
#define SG_ERR_CAT_NOTSUPPORTED         5        /* Illegal / unsupported command */
#define SG_ERR_CAT_RETRY                6        /* Command should be retried */
#define SG_ERR_CAT_SENSE               98        /* Something else in the sense buffer */
#define SG_ERR_CAT_OTHER               99        /* Some other error/warning */

static int do_scsi_page80_inquiry(struct scsi_id_device *dev_scsi, int fd,
                                  char *serial, char *serial_short, int max_len);

static int sg_err_category_new(int scsi_status, int msg_status, int
                               host_status, int driver_status, const
                               unsigned char *sense_buffer, int sb_len) {
        scsi_status &= 0x7e;

        /*
         * XXX change to return only two values - failed or OK.
         */

        if (!scsi_status && !host_status && !driver_status)
                return SG_ERR_CAT_CLEAN;

        if (IN_SET(scsi_status, SCSI_CHECK_CONDITION, SCSI_COMMAND_TERMINATED) ||
            (driver_status & 0xf) == DRIVER_SENSE) {
                if (sense_buffer && (sb_len > 2)) {
                        int sense_key;
                        unsigned char asc;

                        if (sense_buffer[0] & 0x2) {
                                sense_key = sense_buffer[1] & 0xf;
                                asc = sense_buffer[2];
                        } else {
                                sense_key = sense_buffer[2] & 0xf;
                                asc = (sb_len > 12) ? sense_buffer[12] : 0;
                        }

                        if (sense_key == RECOVERED_ERROR)
                                return SG_ERR_CAT_RECOVERED;
                        else if (sense_key == UNIT_ATTENTION) {
                                if (0x28 == asc)
                                        return SG_ERR_CAT_MEDIA_CHANGED;
                                if (0x29 == asc)
                                        return SG_ERR_CAT_RESET;
                        } else if (sense_key == ILLEGAL_REQUEST)
                                return SG_ERR_CAT_NOTSUPPORTED;
                }
                return SG_ERR_CAT_SENSE;
        }
        if (host_status) {
                if (IN_SET(host_status, DID_NO_CONNECT, DID_BUS_BUSY, DID_TIME_OUT))
                        return SG_ERR_CAT_TIMEOUT;
                if (host_status == DID_TRANSPORT_DISRUPTED)
                        return SG_ERR_CAT_RETRY;
        }
        if (driver_status) {
                if (driver_status == DRIVER_TIMEOUT)
                        return SG_ERR_CAT_TIMEOUT;
        }
        return SG_ERR_CAT_OTHER;
}

static int sg_err_category3(struct sg_io_hdr *hp) {
        return sg_err_category_new(hp->status, hp->msg_status,
                                   hp->host_status, hp->driver_status,
                                   hp->sbp, hp->sb_len_wr);
}

static int sg_err_category4(struct sg_io_v4 *hp) {
        return sg_err_category_new(hp->device_status, 0,
                                   hp->transport_status, hp->driver_status,
                                   (unsigned char *)(uintptr_t)hp->response,
                                   hp->response_len);
}

static int scsi_dump_sense(struct scsi_id_device *dev_scsi,
                           unsigned char *sense_buffer, int sb_len) {
        int s;
        unsigned code, sense_class, sense_key, asc, ascq;

        /*
         * Figure out and print the sense key, asc and ascq.
         *
         * If you want to suppress these for a particular drive model, add
         * a black list entry in the scsi_id config file.
         *
         * XXX We probably need to: lookup the sense/asc/ascq in a retry
         * table, and if found return 1 (after dumping the sense, asc, and
         * ascq). So, if/when we get something like a power on/reset,
         * we'll retry the command.
         */

        if (sb_len < 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: sense buffer empty",
                                       dev_scsi->kernel);

        sense_class = (sense_buffer[0] >> 4) & 0x07;
        code = sense_buffer[0] & 0xf;

        if (sense_class == 7) {
                /*
                 * extended sense data.
                 */
                s = sense_buffer[7] + 8;
                if (sb_len < s)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "%s: sense buffer too small %d bytes, %d bytes too short",
                                               dev_scsi->kernel, sb_len,
                                               s - sb_len);

                if (IN_SET(code, 0x0, 0x1)) {
                        sense_key = sense_buffer[2] & 0xf;
                        if (s < 14)
                                /*
                                 * Possible?
                                 */
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "%s: sense result too small %d bytes",
                                                       dev_scsi->kernel, s);

                        asc = sense_buffer[12];
                        ascq = sense_buffer[13];
                } else if (IN_SET(code, 0x2, 0x3)) {
                        sense_key = sense_buffer[1] & 0xf;
                        asc = sense_buffer[2];
                        ascq = sense_buffer[3];
                } else
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "%s: invalid sense code 0x%x",
                                               dev_scsi->kernel, code);

                log_debug("%s: sense key 0x%x ASC 0x%x ASCQ 0x%x",
                          dev_scsi->kernel, sense_key, asc, ascq);
        } else {
                if (sb_len < 4)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "%s: sense buffer too small %d bytes, %d bytes too short",
                                               dev_scsi->kernel, sb_len,
                                               4 - sb_len);

                if (sense_buffer[0] < 15)
                        log_debug("%s: old sense key: 0x%x", dev_scsi->kernel, sense_buffer[0] & 0x0fu);
                else
                        log_debug("%s: sense = %2x %2x",
                                  dev_scsi->kernel, sense_buffer[0], sense_buffer[2]);
                log_debug("%s: non-extended sense class %u code 0x%0x",
                          dev_scsi->kernel, sense_class, code);

        }

        return -1;
}

static int scsi_dump(struct scsi_id_device *dev_scsi, struct sg_io_hdr *io) {
        if (!io->status && !io->host_status && !io->msg_status &&
            !io->driver_status)
                /*
                 * Impossible, should not be called.
                 */
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: called with no error",
                                       __func__);

        log_debug("%s: sg_io failed status 0x%x 0x%x 0x%x 0x%x",
                  dev_scsi->kernel, io->driver_status, io->host_status, io->msg_status, io->status);
        if (io->status == SCSI_CHECK_CONDITION)
                return scsi_dump_sense(dev_scsi, io->sbp, io->sb_len_wr);
        else
                return -1;
}

static int scsi_dump_v4(struct scsi_id_device *dev_scsi, struct sg_io_v4 *io) {
        if (!io->device_status && !io->transport_status &&
            !io->driver_status)
                /*
                 * Impossible, should not be called.
                 */
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: called with no error",
                                       __func__);

        log_debug("%s: sg_io failed status 0x%x 0x%x 0x%x",
                  dev_scsi->kernel, io->driver_status, io->transport_status, io->device_status);
        if (io->device_status == SCSI_CHECK_CONDITION)
                return scsi_dump_sense(dev_scsi, (unsigned char *)(uintptr_t)io->response,
                                       io->response_len);
        else
                return -1;
}

static int scsi_inquiry(struct scsi_id_device *dev_scsi, int fd,
                        unsigned char evpd, unsigned char page,
                        unsigned char *buf, unsigned buflen) {
        unsigned char inq_cmd[INQUIRY_CMDLEN] =
                { INQUIRY_CMD, evpd, page, 0, buflen, 0 };
        unsigned char sense[SENSE_BUFF_LEN];
        void *io_buf;
        struct sg_io_v4 io_v4;
        struct sg_io_hdr io_hdr;
        int retry = 3; /* rather random */
        int retval;

        if (buflen > SCSI_INQ_BUFF_LEN)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "buflen %u too long", buflen);

resend:
        if (dev_scsi->use_sg == 4) {
                memzero(&io_v4, sizeof(struct sg_io_v4));
                io_v4.guard = 'Q';
                io_v4.protocol = BSG_PROTOCOL_SCSI;
                io_v4.subprotocol = BSG_SUB_PROTOCOL_SCSI_CMD;
                io_v4.request_len = sizeof(inq_cmd);
                io_v4.request = (uintptr_t)inq_cmd;
                io_v4.max_response_len = sizeof(sense);
                io_v4.response = (uintptr_t)sense;
                io_v4.din_xfer_len = buflen;
                io_v4.din_xferp = (uintptr_t)buf;
                io_buf = (void *)&io_v4;
        } else {
                memzero(&io_hdr, sizeof(struct sg_io_hdr));
                io_hdr.interface_id = 'S';
                io_hdr.cmd_len = sizeof(inq_cmd);
                io_hdr.mx_sb_len = sizeof(sense);
                io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
                io_hdr.dxfer_len = buflen;
                io_hdr.dxferp = buf;
                io_hdr.cmdp = inq_cmd;
                io_hdr.sbp = sense;
                io_hdr.timeout = DEF_TIMEOUT;
                io_buf = (void *)&io_hdr;
        }

        retval = ioctl(fd, SG_IO, io_buf);
        if (retval < 0) {
                if (IN_SET(errno, EINVAL, ENOSYS) && dev_scsi->use_sg == 4) {
                        dev_scsi->use_sg = 3;
                        goto resend;
                }
                log_debug_errno(errno, "%s: ioctl failed: %m", dev_scsi->kernel);
                goto error;
        }

        if (dev_scsi->use_sg == 4)
                retval = sg_err_category4(io_buf);
        else
                retval = sg_err_category3(io_buf);

        switch (retval) {
                case SG_ERR_CAT_NOTSUPPORTED:
                        buf[1] = 0;
                        _fallthrough_;
                case SG_ERR_CAT_CLEAN:
                case SG_ERR_CAT_RECOVERED:
                        retval = 0;
                        break;
                case SG_ERR_CAT_RETRY:
                        break;

                default:
                        if (dev_scsi->use_sg == 4)
                                retval = scsi_dump_v4(dev_scsi, io_buf);
                        else
                                retval = scsi_dump(dev_scsi, io_buf);
        }

        if (!retval) {
                retval = buflen;
        } else if (retval > 0) {
                if (--retry > 0)
                        goto resend;
                retval = -1;
        }

error:
        if (retval < 0)
                log_debug("%s: Unable to get INQUIRY vpd %d page 0x%x.",
                          dev_scsi->kernel, evpd, page);

        return retval;
}

/* Get list of supported EVPD pages */
static int do_scsi_page0_inquiry(struct scsi_id_device *dev_scsi, int fd,
                                 unsigned char *buffer, unsigned len) {
        int retval;

        memzero(buffer, len);
        retval = scsi_inquiry(dev_scsi, fd, 1, 0x0, buffer, len);
        if (retval < 0)
                return 1;

        if (buffer[1] != 0) {
                log_debug("%s: page 0 not available.", dev_scsi->kernel);
                return 1;
        }
        if (buffer[3] > len) {
                log_debug("%s: page 0 buffer too long %d", dev_scsi->kernel, buffer[3]);
                return 1;
        }

        /*
         * Following check is based on code once included in the 2.5.x
         * kernel.
         *
         * Some ill behaved devices return the standard inquiry here
         * rather than the evpd data, snoop the data to verify.
         */
        if (buffer[3] > MODEL_LENGTH) {
                /*
                 * If the vendor id appears in the page assume the page is
                 * invalid.
                 */
                if (strneq((char*) buffer + VENDOR_LENGTH, dev_scsi->vendor, VENDOR_LENGTH)) {
                        log_debug("%s: invalid page0 data", dev_scsi->kernel);
                        return 1;
                }
        }
        return 0;
}

static int append_vendor_model(
                const struct scsi_id_device *dev_scsi,
                char buf[static VENDOR_LENGTH + MODEL_LENGTH]) {

        assert(dev_scsi);
        assert(buf);

        if (strnlen(dev_scsi->vendor, VENDOR_LENGTH) != VENDOR_LENGTH)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: bad vendor string \"%s\"",
                                       dev_scsi->kernel, dev_scsi->vendor);
        if (strnlen(dev_scsi->model, MODEL_LENGTH) != MODEL_LENGTH)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s: bad model string \"%s\"",
                                       dev_scsi->kernel, dev_scsi->model);
        memcpy(buf, dev_scsi->vendor, VENDOR_LENGTH);
        memcpy(buf + VENDOR_LENGTH, dev_scsi->model, MODEL_LENGTH);
        return VENDOR_LENGTH + MODEL_LENGTH;
}

/*
 * check_fill_0x83_id - check the page 0x83 id, if OK allocate and fill
 * serial number.
 */
static int check_fill_0x83_id(struct scsi_id_device *dev_scsi,
                              unsigned char *page_83,
                              const struct scsi_id_search_values
                              *id_search, char *serial, char *serial_short,
                              int max_len, char *wwn,
                              char *wwn_vendor_extension, char *tgpt_group) {
        int i, j, s, len;

        /*
         * ASSOCIATION must be with the device (value 0)
         * or with the target port for SCSI_ID_TGTPORT
         */
        if ((page_83[1] & 0x30) == 0x10) {
                if (id_search->id_type != SCSI_ID_TGTGROUP)
                        return 1;
        } else if ((page_83[1] & 0x30) != 0)
                return 1;

        if ((page_83[1] & 0x0f) != id_search->id_type)
                return 1;

        /*
         * Possibly check NAA sub-type.
         */
        if ((id_search->naa_type != SCSI_ID_NAA_DONT_CARE) &&
            (id_search->naa_type != (page_83[4] & 0xf0) >> 4))
                return 1;

        /*
         * Check for matching code set - ASCII or BINARY.
         */
        if ((page_83[0] & 0x0f) != id_search->code_set)
                return 1;

        /*
         * page_83[3]: identifier length
         */
        len = page_83[3];
        if ((page_83[0] & 0x0f) != SCSI_ID_ASCII)
                /*
                 * If not ASCII, use two bytes for each binary value.
                 */
                len *= 2;

        /*
         * Add one byte for the NUL termination, and one for the id_type.
         */
        len += 2;
        if (id_search->id_type == SCSI_ID_VENDOR_SPECIFIC)
                len += VENDOR_LENGTH + MODEL_LENGTH;

        if (max_len < len) {
                log_debug("%s: length %d too short - need %d",
                          dev_scsi->kernel, max_len, len);
                return 1;
        }

        if (id_search->id_type == SCSI_ID_TGTGROUP && tgpt_group != NULL) {
                unsigned group;

                group = ((unsigned)page_83[6] << 8) | page_83[7];
                sprintf(tgpt_group,"%x", group);
                return 1;
        }

        serial[0] = hex_str[id_search->id_type];

        /*
         * For SCSI_ID_VENDOR_SPECIFIC prepend the vendor and model before
         * the id since it is not unique across all vendors and models,
         * this differs from SCSI_ID_T10_VENDOR, where the vendor is
         * included in the identifier.
         */
        if (id_search->id_type == SCSI_ID_VENDOR_SPECIFIC)
                if (append_vendor_model(dev_scsi, serial + 1) < 0)
                        return 1;

        i = 4; /* offset to the start of the identifier */
        s = j = strlen(serial);
        if ((page_83[0] & 0x0f) == SCSI_ID_ASCII) {
                /*
                 * ASCII descriptor.
                 */
                while (i < (4 + page_83[3]))
                        serial[j++] = page_83[i++];
        } else {
                /*
                 * Binary descriptor, convert to ASCII, using two bytes of
                 * ASCII for each byte in the page_83.
                 */
                while (i < (4 + page_83[3])) {
                        serial[j++] = hex_str[(page_83[i] & 0xf0) >> 4];
                        serial[j++] = hex_str[page_83[i] & 0x0f];
                        i++;
                }
        }

        strcpy(serial_short, serial + s);

        if (id_search->id_type == SCSI_ID_NAA && wwn != NULL) {
                strncpy(wwn, serial + s, 16);
                if (wwn_vendor_extension)
                        strncpy(wwn_vendor_extension, serial + s + 16, 16);
        }

        return 0;
}

/* Extract the raw binary from VPD 0x83 pre-SPC devices */
static int check_fill_0x83_prespc3(struct scsi_id_device *dev_scsi,
                                   unsigned char *page_83,
                                   const struct scsi_id_search_values
                                   *id_search, char *serial, char *serial_short, int max_len) {
        int i, j;

        serial[0] = hex_str[SCSI_ID_NAA];
        /* serial has been memset to zero before */
        j = strlen(serial);        /* j = 1; */

        for (i = 0; (i < page_83[3]) && (j < max_len-3); ++i) {
                serial[j++] = hex_str[(page_83[4+i] & 0xf0) >> 4];
                serial[j++] = hex_str[ page_83[4+i] & 0x0f];
        }
        serial[max_len-1] = 0;
        strncpy(serial_short, serial, max_len-1);
        return 0;
}

/* Get device identification VPD page */
static int do_scsi_page83_inquiry(struct scsi_id_device *dev_scsi, int fd,
                                  char *serial, char *serial_short, int len,
                                  char *unit_serial_number, char *wwn,
                                  char *wwn_vendor_extension, char *tgpt_group) {
        int retval;
        unsigned id_ind, j;
        unsigned char page_83[SCSI_INQ_BUFF_LEN];

        /* also pick up the page 80 serial number */
        do_scsi_page80_inquiry(dev_scsi, fd, NULL, unit_serial_number, MAX_SERIAL_LEN);

        memzero(page_83, SCSI_INQ_BUFF_LEN);
        retval = scsi_inquiry(dev_scsi, fd, 1, PAGE_83, page_83,
                              SCSI_INQ_BUFF_LEN);
        if (retval < 0)
                return 1;

        if (page_83[1] != PAGE_83) {
                log_debug("%s: Invalid page 0x83", dev_scsi->kernel);
                return 1;
        }

        /*
         * XXX Some devices (IBM 3542) return all spaces for an identifier if
         * the LUN is not actually configured. This leads to identifiers of
         * the form: "1            ".
         */

        /*
         * Model 4, 5, and (some) model 6 EMC Symmetrix devices return
         * a page 83 reply according to SCSI-2 format instead of SPC-2/3.
         *
         * The SCSI-2 page 83 format returns an IEEE WWN in binary
         * encoded hexi-decimal in the 16 bytes following the initial
         * 4-byte page 83 reply header.
         *
         * Both the SPC-2 and SPC-3 formats return an IEEE WWN as part
         * of an Identification descriptor.  The 3rd byte of the first
         * Identification descriptor is a reserved (BSZ) byte field.
         *
         * Reference the 7th byte of the page 83 reply to determine
         * whether the reply is compliant with SCSI-2 or SPC-2/3
         * specifications.  A zero value in the 7th byte indicates
         * an SPC-2/3 conformant reply, (i.e., the reserved field of the
         * first Identification descriptor).  This byte will be non-zero
         * for a SCSI-2 conformant page 83 reply from these EMC
         * Symmetrix models since the 7th byte of the reply corresponds
         * to the 4th and 5th nibbles of the 6-byte OUI for EMC, that is,
         * 0x006048.
         */

        if (page_83[6] != 0)
                return check_fill_0x83_prespc3(dev_scsi, page_83, id_search_list,
                                               serial, serial_short, len);

        /*
         * Search for a match in the prioritized id_search_list - since WWN ids
         * come first we can pick up the WWN in check_fill_0x83_id().
         */
        for (id_ind = 0;
             id_ind < sizeof(id_search_list)/sizeof(id_search_list[0]);
             id_ind++) {
                /*
                 * Examine each descriptor returned. There is normally only
                 * one or a small number of descriptors.
                 */
                for (j = 4; j <= ((unsigned)page_83[2] << 8) + (unsigned)page_83[3] + 3; j += page_83[j + 3] + 4) {
                        retval = check_fill_0x83_id(dev_scsi, page_83 + j,
                                                    id_search_list + id_ind,
                                                    serial, serial_short, len,
                                                    wwn, wwn_vendor_extension,
                                                    tgpt_group);
                        if (!retval)
                                return retval;
                        else if (retval < 0)
                                return retval;
                }
        }
        return 1;
}

/*
 * Get device identification VPD page for older SCSI-2 device which is not
 * compliant with either SPC-2 or SPC-3 format.
 *
 * Return the hard coded error code value 2 if the page 83 reply is not
 * conformant to the SCSI-2 format.
 */
static int do_scsi_page83_prespc3_inquiry(struct scsi_id_device *dev_scsi, int fd,
                                          char *serial, char *serial_short, int len) {
        int retval;
        int i, j;
        unsigned char page_83[SCSI_INQ_BUFF_LEN];

        memzero(page_83, SCSI_INQ_BUFF_LEN);
        retval = scsi_inquiry(dev_scsi, fd, 1, PAGE_83, page_83, SCSI_INQ_BUFF_LEN);
        if (retval < 0)
                return 1;

        if (page_83[1] != PAGE_83) {
                log_debug("%s: Invalid page 0x83", dev_scsi->kernel);
                return 1;
        }
        /*
         * Model 4, 5, and (some) model 6 EMC Symmetrix devices return
         * a page 83 reply according to SCSI-2 format instead of SPC-2/3.
         *
         * The SCSI-2 page 83 format returns an IEEE WWN in binary
         * encoded hexi-decimal in the 16 bytes following the initial
         * 4-byte page 83 reply header.
         *
         * Both the SPC-2 and SPC-3 formats return an IEEE WWN as part
         * of an Identification descriptor.  The 3rd byte of the first
         * Identification descriptor is a reserved (BSZ) byte field.
         *
         * Reference the 7th byte of the page 83 reply to determine
         * whether the reply is compliant with SCSI-2 or SPC-2/3
         * specifications.  A zero value in the 7th byte indicates
         * an SPC-2/3 conformant reply, (i.e., the reserved field of the
         * first Identification descriptor).  This byte will be non-zero
         * for a SCSI-2 conformant page 83 reply from these EMC
         * Symmetrix models since the 7th byte of the reply corresponds
         * to the 4th and 5th nibbles of the 6-byte OUI for EMC, that is,
         * 0x006048.
         */
        if (page_83[6] == 0)
                return 2;

        serial[0] = hex_str[SCSI_ID_NAA];
        /*
         * The first four bytes contain data, not a descriptor.
         */
        i = 4;
        j = strlen(serial);
        /*
         * Binary descriptor, convert to ASCII,
         * using two bytes of ASCII for each byte
         * in the page_83.
         */
        while (i < (page_83[3]+4)) {
                serial[j++] = hex_str[(page_83[i] & 0xf0) >> 4];
                serial[j++] = hex_str[page_83[i] & 0x0f];
                i++;
        }
        return 0;
}

/* Get unit serial number VPD page */
static int do_scsi_page80_inquiry(struct scsi_id_device *dev_scsi, int fd,
                                  char *serial, char *serial_short, int max_len) {
        int retval;
        int ser_ind;
        int i;
        int len;
        unsigned char buf[SCSI_INQ_BUFF_LEN];

        memzero(buf, SCSI_INQ_BUFF_LEN);
        retval = scsi_inquiry(dev_scsi, fd, 1, PAGE_80, buf, SCSI_INQ_BUFF_LEN);
        if (retval < 0)
                return retval;

        if (buf[1] != PAGE_80) {
                log_debug("%s: Invalid page 0x80", dev_scsi->kernel);
                return 1;
        }

        len = 1 + VENDOR_LENGTH + MODEL_LENGTH + buf[3];
        if (max_len < len) {
                log_debug("%s: length %d too short - need %d",
                          dev_scsi->kernel, max_len, len);
                return 1;
        }
        /*
         * Prepend 'S' to avoid unlikely collision with page 0x83 vendor
         * specific type where we prepend '0' + vendor + model.
         */
        len = buf[3];
        if (serial) {
                serial[0] = 'S';
                ser_ind = append_vendor_model(dev_scsi, serial + 1);
                if (ser_ind < 0)
                        return 1;
                ser_ind++; /* for the leading 'S' */
                for (i = 4; i < len + 4; i++, ser_ind++)
                        serial[ser_ind] = buf[i];
        }
        if (serial_short) {
                memcpy(serial_short, buf + 4, len);
                serial_short[len] = '\0';
        }
        return 0;
}

int scsi_std_inquiry(struct scsi_id_device *dev_scsi, const char *devname) {
        int fd;
        unsigned char buf[SCSI_INQ_BUFF_LEN];
        struct stat statbuf;
        int err = 0;

        fd = open(devname, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
        if (fd < 0) {
                log_debug_errno(errno, "scsi_id: cannot open %s: %m", devname);
                return 1;
        }

        if (fstat(fd, &statbuf) < 0) {
                log_debug_errno(errno, "scsi_id: cannot stat %s: %m", devname);
                err = 2;
                goto out;
        }
        format_devnum(statbuf.st_rdev, dev_scsi->kernel);

        memzero(buf, SCSI_INQ_BUFF_LEN);
        err = scsi_inquiry(dev_scsi, fd, 0, 0, buf, SCSI_INQ_BUFF_LEN);
        if (err < 0)
                goto out;

        err = 0;
        memcpy(dev_scsi->vendor, buf + 8, 8);
        dev_scsi->vendor[8] = '\0';
        memcpy(dev_scsi->model, buf + 16, 16);
        dev_scsi->model[16] = '\0';
        memcpy(dev_scsi->revision, buf + 32, 4);
        dev_scsi->revision[4] = '\0';
        dev_scsi->type = buf[0] & 0x1f;

out:
        close(fd);
        return err;
}

int scsi_get_serial(struct scsi_id_device *dev_scsi, const char *devname,
                    int page_code, int len) {
        unsigned char page0[SCSI_INQ_BUFF_LEN];
        int fd = -1;
        int cnt;
        int ind;
        int retval;

        memzero(dev_scsi->serial, len);
        for (cnt = 20; cnt > 0; cnt--) {
                struct timespec duration;

                fd = open(devname, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
                if (fd >= 0 || errno != EBUSY)
                        break;
                duration.tv_sec = 0;
                duration.tv_nsec = (200 * 1000 * 1000) + (random_u32() % 100 * 1000 * 1000);
                nanosleep(&duration, NULL);
        }
        if (fd < 0)
                return 1;

        if (page_code == PAGE_80) {
                if (do_scsi_page80_inquiry(dev_scsi, fd, dev_scsi->serial, dev_scsi->serial_short, len)) {
                        retval = 1;
                        goto completed;
                } else  {
                        retval = 0;
                        goto completed;
                }
        } else if (page_code == PAGE_83) {
                if (do_scsi_page83_inquiry(dev_scsi, fd, dev_scsi->serial, dev_scsi->serial_short, len, dev_scsi->unit_serial_number, dev_scsi->wwn, dev_scsi->wwn_vendor_extension, dev_scsi->tgpt_group)) {
                        retval = 1;
                        goto completed;
                } else  {
                        retval = 0;
                        goto completed;
                }
        } else if (page_code == PAGE_83_PRE_SPC3) {
                retval = do_scsi_page83_prespc3_inquiry(dev_scsi, fd, dev_scsi->serial, dev_scsi->serial_short, len);
                if (retval) {
                        /*
                         * Fallback to servicing a SPC-2/3 compliant page 83
                         * inquiry if the page 83 reply format does not
                         * conform to pre-SPC3 expectations.
                         */
                        if (retval == 2) {
                                if (do_scsi_page83_inquiry(dev_scsi, fd, dev_scsi->serial, dev_scsi->serial_short, len, dev_scsi->unit_serial_number, dev_scsi->wwn, dev_scsi->wwn_vendor_extension, dev_scsi->tgpt_group)) {
                                        retval = 1;
                                        goto completed;
                                } else  {
                                        retval = 0;
                                        goto completed;
                                }
                        }
                        else {
                                retval = 1;
                                goto completed;
                        }
                } else  {
                        retval = 0;
                        goto completed;
                }
        } else if (page_code != 0x00) {
                log_debug("%s: unsupported page code 0x%d", dev_scsi->kernel, page_code);
                retval = 1;
                goto completed;
        }

        /*
         * Get page 0, the page of the pages. By default, try from best to
         * worst of supported pages: 0x83 then 0x80.
         */
        if (do_scsi_page0_inquiry(dev_scsi, fd, page0, SCSI_INQ_BUFF_LEN)) {
                /*
                 * Don't try anything else. Black list if a specific page
                 * should be used for this vendor+model, or maybe have an
                 * optional fall-back to page 0x80 or page 0x83.
                 */
                retval = 1;
                goto completed;
        }

        for (ind = 4; ind <= page0[3] + 3; ind++)
                if (page0[ind] == PAGE_83)
                        if (!do_scsi_page83_inquiry(dev_scsi, fd,
                                                    dev_scsi->serial, dev_scsi->serial_short, len, dev_scsi->unit_serial_number, dev_scsi->wwn, dev_scsi->wwn_vendor_extension, dev_scsi->tgpt_group)) {
                                /*
                                 * Success
                                 */
                                retval = 0;
                                goto completed;
                        }

        for (ind = 4; ind <= page0[3] + 3; ind++)
                if (page0[ind] == PAGE_80)
                        if (!do_scsi_page80_inquiry(dev_scsi, fd,
                                                    dev_scsi->serial, dev_scsi->serial_short, len)) {
                                /*
                                 * Success
                                 */
                                retval = 0;
                                goto completed;
                        }
        retval = 1;

completed:
        close(fd);
        return retval;
}
