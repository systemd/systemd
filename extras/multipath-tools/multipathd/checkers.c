#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "sg_include.h"

#define TUR_CMD_LEN      6

/*
 * test IO functions : add yours here
 *
 * returns 0 : path gone valid
 * returns 1 : path still failed
 */

int readsector0 (char *devnode)
{
	int fd, r;
	char buf;

	fd = open (devnode, O_RDONLY);
	if (read (fd, &buf, 1) != 1)
		r = 0;
	else
		r = 1;
	
	close (fd);

	return r;
}

int tur(char *devnode)
{
        unsigned char turCmdBlk[TUR_CMD_LEN] = { 0x00, 0, 0, 0, 0, 0 };
        struct sg_io_hdr io_hdr;
        unsigned char sense_buffer[32];
	int fd;

	fd = open (devnode, O_RDONLY);

        memset(&io_hdr, 0, sizeof (struct sg_io_hdr));
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof (turCmdBlk);
        io_hdr.mx_sb_len = sizeof (sense_buffer);
        io_hdr.dxfer_direction = SG_DXFER_NONE;
        io_hdr.cmdp = turCmdBlk;
        io_hdr.sbp = sense_buffer;
        io_hdr.timeout = 20000;
        io_hdr.pack_id = 0;
        if (ioctl(fd, SG_IO, &io_hdr) < 0) {
                close(fd);
                return 0;
        }
        if (io_hdr.info & SG_INFO_OK_MASK) {
                return 0;
        }
        return 1;
}
