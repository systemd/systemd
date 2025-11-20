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
#include <getopt.h>
#include <mtd/mtd-user.h>
#include <stdio.h>
#include <sys/ioctl.h>

#include "build.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "mtd_probe.h"

static const char *arg_device = NULL;

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "help",     no_argument, NULL, 'h' },
                { "version",  no_argument, NULL, 'v' },
                {}
        };
        int c;

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        printf("%s /dev/mtd[n]\n\n"
                               "  -h --help     Show this help text\n"
                               "     --version  Show package version\n",
                               program_invocation_short_name);
                        return 0;
                case 'v':
                        return version();
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached();
                }

        if (argc > 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Error: unexpected argument.");

        arg_device = argv[optind];
        return 1;
}

static int run(int argc, char** argv) {
        _cleanup_close_ int mtd_fd = -EBADF;
        mtd_info_t mtd_info;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        mtd_fd = open(argv[1], O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (mtd_fd < 0) {
                bool ignore = ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(errno);
                log_full_errno(ignore ? LOG_DEBUG : LOG_WARNING, errno,
                               "Failed to open device node '%s'%s: %m",
                               argv[1], ignore ? ", ignoring" : "");
                return ignore ? 0 : -errno;
        }

        if (ioctl(mtd_fd, MEMGETINFO, &mtd_info) < 0)
                return log_error_errno(errno, "MEMGETINFO ioctl failed: %m");

        return probe_smart_media(mtd_fd, &mtd_info);
}

DEFINE_MAIN_FUNCTION(run);
