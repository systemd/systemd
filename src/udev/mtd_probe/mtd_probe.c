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

#include <fcntl.h>
#include <mtd/mtd-user.h>
#include <sys/ioctl.h>

#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "mtd_probe.h"
#include "verbs.h"

COMMAND(
        "mtd_probe\0",
        "Probe MTD devices.",
        .argspec = "/dev/mtdN\0",
        .option_namespace = "common",
);

static int run(int argc, char** argv) {
        _cleanup_close_ int mtd_fd = -EBADF;
        mtd_info_t mtd_info;
        int r;

        char **args = NULL;
        r = common_parse_argv_full(argc, argv, /* min_args= */ 1, /* max_args= */ 1, &args);
        if (r <= 0)
                return r;

        const char *device = args[0];

        mtd_fd = open(device, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (mtd_fd < 0) {
                bool ignore = ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(errno);
                log_full_errno(ignore ? LOG_DEBUG : LOG_WARNING, errno,
                               "Failed to open device node '%s'%s: %m",
                               device, ignore ? ", ignoring" : "");
                return ignore ? 0 : -errno;
        }

        if (ioctl(mtd_fd, MEMGETINFO, &mtd_info) < 0)
                return log_error_errno(errno, "MEMGETINFO ioctl failed: %m");

        return probe_smart_media(mtd_fd, &mtd_info);
}

DEFINE_MAIN_FUNCTION(run);
