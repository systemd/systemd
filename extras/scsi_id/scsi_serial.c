/*
 * scsi_serial.c
 *
 * Code related to requesting and getting an id from a scsi device
 *
 * Copyright (C) IBM Corp. 2003
 *
 *  This library is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of the
 *  License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 *  USA
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <scsi/sg.h>
#include <sysfs/libsysfs.h>
#include "scsi_id.h"
#include "scsi.h"

/*
 * A priority based list of id, naa, and binary/ascii for the identifier
 * descriptor in VPD page 0x83.
 *
 * Brute force search for a match starting with the first value in the
 * following id_search_list. This is not a performance issue, since there
 * is normally one or some small number of descriptors.
 */
static const struct scsi_id_search_values id_search_list[] = {
	{ SCSI_ID_NAA,	SCSI_ID_NAA_IEEE_REG_EXTENDED,	SCSI_ID_BINARY },
	{ SCSI_ID_NAA,	SCSI_ID_NAA_IEEE_REG_EXTENDED,	SCSI_ID_ASCII },
	{ SCSI_ID_NAA,	SCSI_ID_NAA_IEEE_REG,	SCSI_ID_BINARY },
	{ SCSI_ID_NAA,	SCSI_ID_NAA_IEEE_REG,	SCSI_ID_ASCII },
	/*
	 * Devices already exist using NAA values that are now marked
	 * reserved. These should not conflict with other values, or it is
	 * a bug in the device. As long as we find the IEEE extended one
	 * first, we really don't care what other ones are used. Using
	 * don't care here means that a device that returns multiple
	 * non-IEEE descriptors in a random order will get different
	 * names.
	 */
	{ SCSI_ID_NAA,	SCSI_ID_NAA_DONT_CARE,	SCSI_ID_BINARY },
	{ SCSI_ID_NAA,	SCSI_ID_NAA_DONT_CARE,	SCSI_ID_ASCII },
	{ SCSI_ID_EUI_64,	SCSI_ID_NAA_DONT_CARE,	SCSI_ID_BINARY },
	{ SCSI_ID_EUI_64,	SCSI_ID_NAA_DONT_CARE,	SCSI_ID_ASCII },
	{ SCSI_ID_T10_VENDOR,	SCSI_ID_NAA_DONT_CARE,	SCSI_ID_BINARY },
	{ SCSI_ID_T10_VENDOR,	SCSI_ID_NAA_DONT_CARE,	SCSI_ID_ASCII },
	{ SCSI_ID_VENDOR_SPECIFIC,	SCSI_ID_NAA_DONT_CARE,	SCSI_ID_BINARY },
	{ SCSI_ID_VENDOR_SPECIFIC,	SCSI_ID_NAA_DONT_CARE,	SCSI_ID_ASCII },
};

static const char hex_str[]="0123456789abcdef";

/*
 * Values returned in the result/status, only the ones used by the code
 * are used here.
 */

#define DID_NO_CONNECT 0x01     /* Unable to connect before timeout */

#define DID_BUS_BUSY 0x02       /* Bus remain busy until timeout */
#define DID_TIME_OUT 0x03       /* Timed out for some other reason */

#define DRIVER_TIMEOUT 0x06
#define DRIVER_SENSE 0x08       /* Sense_buffer has been set */

/* The following "category" function returns one of the following */
#define SG_ERR_CAT_CLEAN	0      /* No errors or other information */
#define SG_ERR_CAT_MEDIA_CHANGED	1 /* interpreted from sense buffer */
#define SG_ERR_CAT_RESET	2      /* interpreted from sense buffer */
#define SG_ERR_CAT_TIMEOUT	3
#define SG_ERR_CAT_RECOVERED	4  /* Successful command after recovered err */
#define SG_ERR_CAT_SENSE	98     /* Something else in the sense buffer */
#define SG_ERR_CAT_OTHER	99     /* Some other error/warning */

static int sg_err_category_new(int scsi_status, int msg_status, int
			       host_status, int driver_status, const
			       unsigned char *sense_buffer, int sb_len)
{
	scsi_status &= 0x7e;

	/*
	 * XXX change to return only two values - failed or OK.
	 */

	/*
	 * checks msg_status
	 */
	if (!scsi_status && !msg_status && !host_status && !driver_status)
		return SG_ERR_CAT_CLEAN;

	if ((scsi_status == SCSI_CHECK_CONDITION) ||
	    (scsi_status == SCSI_COMMAND_TERMINATED) ||
	    ((driver_status & 0xf) == DRIVER_SENSE)) {
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
			}
		}
		return SG_ERR_CAT_SENSE;
	}
	if (!host_status) {
		if ((host_status == DID_NO_CONNECT) ||
		    (host_status == DID_BUS_BUSY) ||
		    (host_status == DID_TIME_OUT))
			return SG_ERR_CAT_TIMEOUT;
	}
	if (!driver_status) {
		if (driver_status == DRIVER_TIMEOUT)
			return SG_ERR_CAT_TIMEOUT;
	}
	return SG_ERR_CAT_OTHER;
}

static int sg_err_category3(struct sg_io_hdr *hp)
{
	return sg_err_category_new(hp->status, hp->msg_status,
				   hp->host_status, hp->driver_status,
				   hp->sbp, hp->sb_len_wr);
}

static int scsi_dump_sense(struct sysfs_device *scsi_dev, struct sg_io_hdr *io)
{
	unsigned char *sense_buffer;
	int s;
	int sb_len;
	int code;
	int sense_class;
	int sense_key;
	int descriptor_format;
	int asc, ascq;
#ifdef DUMP_SENSE
	char out_buffer[256];
	int i, j;
#endif

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

	dprintf("got check condition\n");

	sb_len = io->sb_len_wr;
	if (sb_len < 1) {
		log_message(LOG_WARNING, "%s: sense buffer empty\n",
			    scsi_dev->name);
		return -1;
	}

	sense_buffer = io->sbp;
	sense_class = (sense_buffer[0] >> 4) & 0x07;
	code = sense_buffer[0] & 0xf;

	if (sense_class == 7) {
		/*
		 * extended sense data.
		 */
		s = sense_buffer[7] + 8;
		if (sb_len < s) {
			log_message(LOG_WARNING,
				    "%s: sense buffer too small %d bytes,"
				    " %d bytes too short\n", scsi_dev->name,
				    sb_len, s - sb_len);
			return -1;
		}
		if ((code == 0x0) || (code == 0x1)) {
			descriptor_format = 0;
			sense_key = sense_buffer[2] & 0xf;
			if (s < 14) {
				/*
				 * Possible?
				 */
				log_message(LOG_WARNING, "%s: sense result too"
					    " small %d bytes\n",
					    scsi_dev->name, s);
				return -1;
			}
			asc = sense_buffer[12];
			ascq = sense_buffer[13];
		} else if ((code == 0x2) || (code == 0x3)) {
			descriptor_format = 1;
			sense_key = sense_buffer[1] & 0xf;
			asc = sense_buffer[2];
			ascq = sense_buffer[3];
		} else {
			log_message(LOG_WARNING,
				    "%s: invalid sense code 0x%x\n",
				    scsi_dev->name, code);
			return -1;
		}
		log_message(LOG_WARNING,
			    "%s: sense key 0x%x ASC 0x%x ASCQ 0x%x\n",
			    scsi_dev->name, sense_key, asc, ascq);
	} else {
		if (sb_len < 4) {
			log_message(LOG_WARNING,
				    "%s: sense buffer too small %d bytes, %d bytes too short\n",
				    scsi_dev->name, sb_len, 4 - sb_len);
			return -1;
		}

		if (sense_buffer[0] < 15)
			log_message(LOG_WARNING, "%s: old sense key: 0x%x\n",
				    scsi_dev->name, sense_buffer[0] & 0x0f);
		else
			log_message(LOG_WARNING, "%s: sense = %2x %2x\n",
				    scsi_dev->name,  sense_buffer[0],
				    sense_buffer[2]);
		log_message(LOG_WARNING,
			    "%s: non-extended sense class %d code 0x%0x\n",
			    scsi_dev->name, sense_class, code);

	}

#ifdef DUMP_SENSE
	for (i = 0, j = 0; (i < s) && (j < 254); i++) {
		dprintf("i %d, j %d\n", i, j);
		out_buffer[j++] = hex_str[(sense_buffer[i] & 0xf0) >> 4];
		out_buffer[j++] = hex_str[sense_buffer[i] & 0x0f];
		out_buffer[j++] = ' ';
	}
	out_buffer[j] = '\0';
	log_message(LOG_WARNING, "%s: sense dump:\n", scsi_dev->name);
	log_message(LOG_WARNING, "%s: %s\n", scsi_dev->name, out_buffer);

#endif
	return -1;
}

static int scsi_dump(struct sysfs_device *scsi_dev, struct sg_io_hdr *io)
{
	if (!io->status && !io->host_status && !io->msg_status &&
	    !io->driver_status) {
		/*
		 * Impossible, should not be called.
		 */
		log_message(LOG_WARNING, "%s: called with no error\n",
			    __FUNCTION__);
		return -1;
	}

	log_message(LOG_WARNING, "%s: sg_io failed status 0x%x 0x%x 0x%x 0x%x\n",
		    scsi_dev->name, io->driver_status, io->host_status,
		    io->msg_status, io->status);
	if (io->status == SCSI_CHECK_CONDITION)
		return scsi_dump_sense(scsi_dev, io);
	else
		return -1;
}

static int scsi_inquiry(struct sysfs_device *scsi_dev, int fd, unsigned
			char evpd, unsigned char page, unsigned char *buf,
			unsigned int buflen)
{
	unsigned char inq_cmd[INQUIRY_CMDLEN] =
		{ INQUIRY_CMD, evpd, page, 0, buflen, 0 };
	unsigned char sense[SENSE_BUFF_LEN];
	struct sg_io_hdr io_hdr;
	int retval;
	unsigned char *inq;
	unsigned char *buffer;
	int retry = 3; /* rather random */

	if (buflen > 255) {
		log_message(LOG_WARNING, "buflen %d too long\n", buflen);
		return -1;
	}
	inq = malloc(OFFSET + sizeof (inq_cmd) + 512);
	memset(inq, 0, OFFSET + sizeof (inq_cmd) + 512);
	buffer = inq + OFFSET;

resend:
	memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
	io_hdr.interface_id = 'S';
	io_hdr.cmd_len = sizeof(inq_cmd);
	io_hdr.mx_sb_len = sizeof(sense);
	io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
	io_hdr.dxfer_len = buflen;
	io_hdr.dxferp = buffer;
	io_hdr.cmdp = inq_cmd;
	io_hdr.sbp = sense;
	io_hdr.timeout = DEF_TIMEOUT;

	if (ioctl(fd, SG_IO, &io_hdr) < 0) {
		log_message(LOG_WARNING, "%s: ioctl failed: %s\n",
			    scsi_dev->name, strerror(errno));
		return -1;
	}

	retval = sg_err_category3(&io_hdr);

	switch (retval) {
		case SG_ERR_CAT_CLEAN:
		case SG_ERR_CAT_RECOVERED:
			retval = 0;
			break;

		default:
			retval = scsi_dump(scsi_dev, &io_hdr);
	}

	if (!retval) {
		retval = buflen;
		memcpy(buf, buffer, retval);
	} else if (retval > 0) {
		if (--retry > 0) {
			dprintf("%s: Retrying ...\n", scsi_dev->name);
			goto resend;
		}
		retval = -1;
	}

	free(inq);
	return retval;
}

static int do_scsi_page0_inquiry(struct sysfs_device *scsi_dev, int fd,
				 char *buffer, int len)
{
	int retval;
	char vendor[MAX_ATTR_LEN];

	memset(buffer, 0, len);
	retval = scsi_inquiry(scsi_dev, fd, 1, 0x0, buffer, len);
	if (retval < 0)
		return 1;

	if (buffer[1] != 0) {
		log_message(LOG_WARNING, "%s: page 0 not available.\n",
			    scsi_dev->name);
		return 1;
	}
	if (buffer[3] > len) {
		log_message(LOG_WARNING, "%s: page 0 buffer too long %d\n",
			   scsi_dev->name,  buffer[3]);
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
		if (sysfs_get_attr(scsi_dev->path, "vendor", vendor,
				   MAX_ATTR_LEN)) {
			log_message(LOG_WARNING,
				    "%s: cannot get model attribute\n",
				    scsi_dev->name);
			return 1;
		}
		if (!strncmp(&buffer[VENDOR_LENGTH], vendor, VENDOR_LENGTH)) {
			log_message(LOG_WARNING, "%s: invalid page0 data\n",
				    scsi_dev->name);
			return 1;
		}
	}
	return 0;
}

/*
 * The caller checks that serial is long enough to include the vendor +
 * model.
 */
static int prepend_vendor_model(struct sysfs_device *scsi_dev, char *serial)
{
	char attr[MAX_ATTR_LEN];
	int ind;

	if (sysfs_get_attr(scsi_dev->path, "vendor", attr, MAX_ATTR_LEN)) {
		log_message(LOG_WARNING, "%s: cannot get vendor attribute\n",
			    scsi_dev->name);
		return 1;
	}
	strncpy(serial, attr, VENDOR_LENGTH);
	ind = strlen(serial) - 1;
	/*
	 * Remove sysfs added newlines.
	 */
	if (serial[ind] == '\n')
		serial[ind] = '\0';

	if (sysfs_get_attr(scsi_dev->path, "model", attr, MAX_ATTR_LEN)) {
		log_message(LOG_WARNING, "%s: cannot get model attribute\n",
			    scsi_dev->name);
		return 1;
	}
	strncat(serial, attr, MODEL_LENGTH);
	ind = strlen(serial) - 1;
	if (serial[ind] == '\n')
		serial[ind] = '\0';
	else
		ind++;

	/*
	 * This is not a complete check, since we are using strncat/cpy
	 * above, ind will never be too large.
	 */
	if (ind != (VENDOR_LENGTH + MODEL_LENGTH)) {
		log_message(LOG_WARNING, "%s: expected length %d, got length %d\n",
			    scsi_dev->name, (VENDOR_LENGTH + MODEL_LENGTH),
			    ind);
		return 1;
	}
	return ind;
}

/**
 * check_fill_0x83_id - check the page 0x83 id, if OK allocate and fill
 * serial number.
 **/
static int check_fill_0x83_id(struct sysfs_device *scsi_dev, char
			      *page_83, const struct scsi_id_search_values
			      *id_search, char *serial, int max_len)
{
	int i, j, len;

	/*
	 * ASSOCIATION must be with the device (value 0)
	 */
	if ((page_83[1] & 0x30) != 0)
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
		log_message(LOG_WARNING, "%s: length %d too short - need %d\n",
			    scsi_dev->name, max_len, len);
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
		if (prepend_vendor_model(scsi_dev, &serial[1]) < 0) {
			dprintf("prepend failed\n");
			return 1;
		}

	i = 4; /* offset to the start of the identifier */
	j = strlen(serial);
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
	return 0;
}

static int do_scsi_page83_inquiry(struct sysfs_device *scsi_dev, int fd,
				  char *serial, int len)
{
	int retval;
	int id_ind, j;
	unsigned char page_83[256];

	memset(page_83, 0, 256);
	retval = scsi_inquiry(scsi_dev, fd, 1, 0x83, page_83, 255);
	if (retval < 0)
		return 1;

	if (page_83[1] != 0x83) {
		log_message(LOG_WARNING, "%s: Invalid page 0x83\n",
			    scsi_dev->name);
		return 1;
	}
	
	/*
	 * XXX Some devices (IBM 3542) return all spaces for an identifier if
	 * the LUN is not actually configured. This leads to identifers of
	 * the form: "1            ".
	 */

	/*
	 * Search for a match in the prioritized id_search_list.
	 */
	for (id_ind = 0;
	     id_ind < sizeof(id_search_list)/sizeof(id_search_list[0]);
	     id_ind++) {
		/*
		 * Examine each descriptor returned. There is normally only
		 * one or a small number of descriptors.
		 */
		for (j = 4; j <= page_83[3] + 3;
			j += page_83[j + 3] + 4) {
			retval = check_fill_0x83_id(scsi_dev, &page_83[j],
						    &id_search_list[id_ind],
						    serial, len);
			dprintf("%s id desc %d/%d/%d\n", scsi_dev->name,
				id_search_list[id_ind].id_type,
				id_search_list[id_ind].naa_type,
				id_search_list[id_ind].code_set);
			if (!retval) {
				dprintf("	used\n");
				return retval;
			} else if (retval < 0) {
				dprintf("	failed\n");
				return retval;
			} else {
				dprintf("	not used\n");
			}
		}
	}
	return 1;
}

static int do_scsi_page80_inquiry(struct sysfs_device *scsi_dev, int fd,
				  char *serial, int max_len)
{
	int retval;
	int ser_ind;
	int i;
	int len;
	unsigned char buf[256];

	memset(buf, 0, 256);
	retval = scsi_inquiry(scsi_dev, fd, 1, 0x80, buf, 255);
	if (retval < 0)
		return retval;

	if (buf[1] != 0x80) {
		log_message(LOG_WARNING, "%s: Invalid page 0x80\n",
			    scsi_dev->name);
		return 1;
	}

	len = 1 + VENDOR_LENGTH + MODEL_LENGTH + buf[3];
	if (max_len < len) {
		log_message(LOG_WARNING, "%s: length %d too short - need %d\n",
			    scsi_dev->name, max_len, len);
		return 1;
	}
	/*
	 * Prepend 'S' to avoid unlikely collision with page 0x83 vendor
	 * specific type where we prepend '0' + vendor + model.
	 */
	serial[0] = 'S';
	ser_ind = prepend_vendor_model(scsi_dev, &serial[1]);
	if (ser_ind < 0)
		return 1;
	len = buf[3];
	for (i = 4; i < len + 4; i++, ser_ind++)
		serial[ser_ind] = buf[i];
	return 0;
}

int scsi_get_serial (struct sysfs_device *scsi_dev, const char *devname,
		     int page_code, char *serial, int len)
{
	unsigned char page0[256];
	int fd;
	int ind;
	int retval;

	if (len > 255) {
	}
	memset(serial, 0, len);
	dprintf("opening %s\n", devname);
	fd = open(devname, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		log_message(LOG_WARNING, "%s: cannot open %s: %s\n",
			    scsi_dev->name, devname, strerror(errno));
		return 1;
	}

	if (page_code == 0x80) {
		if (do_scsi_page80_inquiry(scsi_dev, fd, serial, len)) {
			retval = 1;
			goto completed;
		} else  {
			retval = 0;
			goto completed;
		}
	} else if (page_code == 0x83) {
		if (do_scsi_page83_inquiry(scsi_dev, fd, serial, len)) {
			retval = 1;
			goto completed;
		} else  {
			retval = 0;
			goto completed;
		}
	} else if (page_code != 0x00) {
		log_message(LOG_WARNING, "%s: unsupported page code 0x%d\n",
			    scsi_dev->name, page_code);
		return 1;
	}

	/*
	 * Get page 0, the page of the pages. By default, try from best to
	 * worst of supported pages: 0x83 then 0x80.
	 */
	if (do_scsi_page0_inquiry(scsi_dev, fd, page0, 255)) {
		/*
		 * Don't try anything else. Black list if a specific page
		 * should be used for this vendor+model, or maybe have an
		 * optional fall-back to page 0x80 or page 0x83.
		 */
		retval = 1;
		goto completed;
	}

	dprintf("%s: Checking page0\n", scsi_dev->name);

	for (ind = 4; ind <= page0[3] + 3; ind++)
		if (page0[ind] == 0x83)
			if (!do_scsi_page83_inquiry(scsi_dev, fd, serial,
						    len)) {
				/*
				 * Success
				 */
				retval = 0;
				goto completed;
			}

	for (ind = 4; ind <= page0[3] + 3; ind++)
		if (page0[ind] == 0x80)
			if (!do_scsi_page80_inquiry(scsi_dev, fd, serial,
						    len)) {
				/*
				 * Success
				 */
				retval = 0;
				goto completed;
			}
	retval = 1;
completed:
	if (close(fd) < 0)
		log_message(LOG_WARNING, "%s: close failed: %s\n", 
			    scsi_dev->name, strerror(errno));
	return retval;
}
