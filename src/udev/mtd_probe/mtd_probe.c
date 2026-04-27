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

#include "build.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "main-func.h"
#include "mtd_probe.h"
#include "options.h"
#include "strv.h"

static const char *arg_device = NULL;

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        help_cmdline("[OPTIONS...] /dev/mtd[n]");
        help_abstract("Probe MTD devices.");
        help_section("Options:");

        return table_print_or_warn(options);
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser state = { argc, argv };
        const char *arg;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();
                }

        char **args = option_parser_get_args(&state);
        if (strv_length(args) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Need exactly one DEVICE argument.");

        arg_device = args[0];
        return 1;
}

static int run(int argc, char** argv) {
        _cleanup_close_ int mtd_fd = -EBADF;
        mtd_info_t mtd_info;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        mtd_fd = open(arg_device, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (mtd_fd < 0) {
                bool ignore = ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(errno);
                log_full_errno(ignore ? LOG_DEBUG : LOG_WARNING, errno,
                               "Failed to open device node '%s'%s: %m",
                               arg_device, ignore ? ", ignoring" : "");
                return ignore ? 0 : -errno;
        }

        if (ioctl(mtd_fd, MEMGETINFO, &mtd_info) < 0)
                return log_error_errno(errno, "MEMGETINFO ioctl failed: %m");

        return probe_smart_media(mtd_fd, &mtd_info);
}

DEFINE_MAIN_FUNCTION(run);
