/*
 * Copyright (C) 2010 - Maxim Levitsky
 *
 * mtd_probe is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * mtd_probe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with mtd_probe; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <sys/ioctl.h>
#include <mtd/mtd-user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "mtd_probe.h"

int main(int argc, char** argv)
{
        int mtd_fd;
        int error;
        mtd_info_t mtd_info;

        if (argc != 2) {
                printf("usage: mtd_probe /dev/mtd[n]\n");
                return 1;
        }

        mtd_fd = open(argv[1], O_RDONLY|O_CLOEXEC);
        if (mtd_fd == -1) {
                perror("open");
                exit(-1);
        }

        error = ioctl(mtd_fd, MEMGETINFO, &mtd_info);
        if (error == -1) {
                perror("ioctl");
                exit(-1);
        }

        probe_smart_media(mtd_fd, &mtd_info);
        return -1;
}
