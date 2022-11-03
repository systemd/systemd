/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2010 - Maxim Levitsky
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

#include <errno.h>
#include <fcntl.h>
#include <mtd/mtd-user.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "mtd_probe.h"

int main(int argc, char** argv) {
        _cleanup_close_ int mtd_fd = -1;
        mtd_info_t mtd_info;

        if (argc != 2) {
                printf("usage: mtd_probe /dev/mtd[n]\n");
                return EXIT_FAILURE;
        }

        mtd_fd = open(argv[1], O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (mtd_fd < 0) {
                log_error_errno(errno, "Failed to open: %m");
                return EXIT_FAILURE;
        }

        if (ioctl(mtd_fd, MEMGETINFO, &mtd_info) < 0) {
                log_error_errno(errno, "Failed to issue MEMGETINFO ioctl: %m");
                return EXIT_FAILURE;
        }

        if (probe_smart_media(mtd_fd, &mtd_info) < 0)
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}
