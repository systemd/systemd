#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <libsysfs.h>
#include "devinfo.h"
#include "sg_include.h"

#define FILE_NAME_SIZE 255

void
basename(char * str1, char * str2)
{
        char *p = str1 + (strlen(str1) - 1);
 
        while (*--p != '/')
                continue;
        strcpy(str2, ++p);
}

static int
do_inq(int sg_fd, int cmddt, int evpd, unsigned int pg_op,
       void *resp, int mx_resp_len, int noisy)
{
        unsigned char inqCmdBlk[INQUIRY_CMDLEN] =
            { INQUIRY_CMD, 0, 0, 0, 0, 0 };
        unsigned char sense_b[SENSE_BUFF_LEN];
        struct sg_io_hdr io_hdr;
                                                                                                                 
        if (cmddt)
                inqCmdBlk[1] |= 2;
        if (evpd)
                inqCmdBlk[1] |= 1;
        inqCmdBlk[2] = (unsigned char) pg_op;
        inqCmdBlk[4] = (unsigned char) mx_resp_len;
        memset(&io_hdr, 0, sizeof (struct sg_io_hdr));
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof (inqCmdBlk);
        io_hdr.mx_sb_len = sizeof (sense_b);
        io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
        io_hdr.dxfer_len = mx_resp_len;
        io_hdr.dxferp = resp;
        io_hdr.cmdp = inqCmdBlk;
        io_hdr.sbp = sense_b;
        io_hdr.timeout = DEF_TIMEOUT;
 
        if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
                perror("SG_IO (inquiry) error");
                return -1;
        }
 
        /* treat SG_ERR here to get rid of sg_err.[ch] */
        io_hdr.status &= 0x7e;
        if ((0 == io_hdr.status) && (0 == io_hdr.host_status) &&
            (0 == io_hdr.driver_status))
                return 0;
        if ((SCSI_CHECK_CONDITION == io_hdr.status) ||
            (SCSI_COMMAND_TERMINATED == io_hdr.status) ||
            (SG_ERR_DRIVER_SENSE == (0xf & io_hdr.driver_status))) {
                if (io_hdr.sbp && (io_hdr.sb_len_wr > 2)) {
                        int sense_key;
                        unsigned char * sense_buffer = io_hdr.sbp;
                        if (sense_buffer[0] & 0x2)
                                sense_key = sense_buffer[1] & 0xf;
                        else
                                sense_key = sense_buffer[2] & 0xf;
                        if(RECOVERED_ERROR == sense_key)
                                return 0;
                }
        }
        return -1;
}

int
get_serial (char * str, char * devname)
{
	int fd;
        int len;
        char buff[MX_ALLOC_LEN + 1];

	if ((fd = open(devname, O_RDONLY)) < 0)
                return 0;

	if (0 == do_inq(fd, 0, 1, 0x80, buff, MX_ALLOC_LEN, 0)) {
		len = buff[3];
		if (len > 0) {
			memcpy(str, buff + 4, len);
			buff[len] = '\0';
		}
		close(fd);
		return 1;
	}
	close(fd);
        return 0;
}

int
get_lun_strings(char * vendor_id, char * product_id, char * rev, char * devname)
{
        int fd;
        char buff[36];
        char attr_path[FILE_NAME_SIZE];
	char sysfs_path[FILE_NAME_SIZE];
        char basedev[FILE_NAME_SIZE];
                                                                                                                 
	if (0 == sysfs_get_mnt_path(sysfs_path, FILE_NAME_SIZE)) {
                /* sysfs style */
                basename(devname, basedev);
 
                sprintf(attr_path, "%s/block/%s/device/vendor",
                        sysfs_path, basedev);
                if (0 > sysfs_read_attribute_value(attr_path,
                    vendor_id, 8)) return 0;
 
                sprintf(attr_path, "%s/block/%s/device/model",
                        sysfs_path, basedev);
                if (0 > sysfs_read_attribute_value(attr_path,
                    product_id, 16)) return 0;
 
                sprintf(attr_path, "%s/block/%s/device/rev",
                        sysfs_path, basedev);
                if (0 > sysfs_read_attribute_value(attr_path,
                    rev, 4)) return 0;
        } else {
                /* ioctl style */
                if ((fd = open(devname, O_RDONLY)) < 0)
                        return 0;
                if (0 != do_inq(fd, 0, 0, 0, buff, 36, 1))
                        return 0;
                memcpy(vendor_id, &buff[8], 8);
                memcpy(product_id, &buff[16], 16);
                memcpy(rev, &buff[32], 4);
                close(fd);
                return 1;
        }
        return 0;
}

static void
sprint_wwid(char * buff, const char * str)
{
        int i;
        const char *p;
        char *cursor;
        unsigned char c;
                                                                                                                 
        p = str;
        cursor = buff;
        for (i = 0; i <= WWID_SIZE / 2 - 1; i++) {
                c = *p++;
                sprintf(cursor, "%.2x", (int) (unsigned char) c);
                cursor += 2;
        }
        buff[WWID_SIZE - 1] = '\0';
}
                                                                                                                 
/* get EVPD page 0x83 off 8 */
/* tested ok with StorageWorks */
int
get_evpd_wwid(char * devname, char * wwid)
{
        int fd;
        char buff[64];
                                                                                                                 
        if ((fd = open(devname, O_RDONLY)) < 0)
                        return 0;
                                                                                                                 
        if (0 == do_inq(fd, 0, 1, 0x83, buff, sizeof (buff), 1)) {
                sprint_wwid(wwid, &buff[8]);
                close(fd);
                return 1; /* success */
        }
        close(fd);
        return 0; /* not good */
}

long
get_disk_size (char * devname) {
        long size;
        int fd;
        char attr_path[FILE_NAME_SIZE];
        char sysfs_path[FILE_NAME_SIZE];
        char buff[FILE_NAME_SIZE];
        char basedev[FILE_NAME_SIZE];
                                                                                                                 
        if (0 == sysfs_get_mnt_path(sysfs_path, FILE_NAME_SIZE)) {
                basename(devname, basedev);
                sprintf(attr_path, "%s/block/%s/size",
                        sysfs_path, basedev);
                if (0 > sysfs_read_attribute_value(attr_path, buff,
                                         FILE_NAME_SIZE * sizeof(char)))
                        return -1;
                size = atoi(buff);
                return size;
        } else {
                if ((fd = open(devname, O_RDONLY)) < 0)
                        return -1;
                if(!ioctl(fd, BLKGETSIZE, &size))
                        return size;
        }
        return -1;
}

