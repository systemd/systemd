/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2009 Filippo Argiolas <filippo.argiolas@gmail.com>
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/videodev2.h>

#include "build.h"
#include "fd-util.h"
#include "main-func.h"

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
                        printf("%s [OPTIONS...] DEVICE\n\n"
                               "Video4Linux device identification.\n\n"
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

        if (!argv[optind])
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "DEVICE argument missing.");

        arg_device = argv[optind];
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
        if (fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", arg_device);

        if (ioctl(fd, VIDIOC_QUERYCAP, &v2cap) == 0) {
                int capabilities;

                printf("ID_V4L_VERSION=2\n");
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
