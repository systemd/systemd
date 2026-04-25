/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2009 Filippo Argiolas <filippo.argiolas@gmail.com>
 */

#include <fcntl.h>
#include <linux/videodev2.h>
#include <stdio.h>
#include <sys/ioctl.h>

#include "build.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

static const char *arg_device = NULL;

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        help_cmdline("[OPTIONS...] DEVICE");
        help_abstract("Video4Linux device identification.");
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
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Need exactly one DEVICE argument.");

        arg_device = args[0];
        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_close_ int fd = -EBADF;
        struct v4l2_capability v2cap;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        fd = open(arg_device, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                bool ignore = ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(errno);
                log_full_errno(ignore ? LOG_DEBUG : LOG_WARNING, errno,
                               "Failed to open device node '%s'%s: %m",
                               arg_device, ignore ? ", ignoring" : "");
                return ignore ? 0 : -errno;
        }

        if (ioctl(fd, VIDIOC_QUERYCAP, &v2cap) == 0) {
                int capabilities;

                printf("ID_V4L_VERSION=2\n");
                if (utf8_is_valid((char *)v2cap.card) && !string_has_cc((char *)v2cap.card, /* ok= */ NULL))
                        printf("ID_V4L_PRODUCT=%s\n", v2cap.card);
                printf("ID_V4L_CAPABILITIES=:");

                if (v2cap.capabilities & V4L2_CAP_DEVICE_CAPS)
                        capabilities = v2cap.device_caps;
                else
                        capabilities = v2cap.capabilities;

                if ((capabilities & V4L2_CAP_VIDEO_CAPTURE) > 0 ||
                    (capabilities & V4L2_CAP_VIDEO_CAPTURE_MPLANE) > 0)
                        printf("capture:");
                if ((capabilities & V4L2_CAP_VIDEO_OUTPUT) > 0 ||
                    (capabilities & V4L2_CAP_VIDEO_OUTPUT_MPLANE) > 0)
                        printf("video_output:");
                if ((capabilities & V4L2_CAP_VIDEO_OVERLAY) > 0)
                        printf("video_overlay:");
                if ((capabilities & V4L2_CAP_AUDIO) > 0)
                        printf("audio:");
                if ((capabilities & V4L2_CAP_TUNER) > 0)
                        printf("tuner:");
                if ((capabilities & V4L2_CAP_RADIO) > 0)
                        printf("radio:");
                printf("\n");
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
