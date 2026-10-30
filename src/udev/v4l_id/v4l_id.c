/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2009 Filippo Argiolas <filippo.argiolas@gmail.com>
 */

#include <fcntl.h>
#include <linux/videodev2.h>
#include <stdio.h>
#include <sys/ioctl.h>

#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "string-util.h"
#include "utf8.h"
#include "verbs.h"

COMMAND(
        "v4l_id\0",
        "Identify Video4Linux devices.",
        .argspec = "DEVICE\0",
        .option_namespace = "common",
);

static int run(int argc, char *argv[]) {
        _cleanup_close_ int fd = -EBADF;
        struct v4l2_capability v2cap;
        int r;

        char **args = NULL;
        r = common_parse_argv_full(argc, argv, /* min_args= */ 1, /* max_args= */ 1, &args);
        if (r <= 0)
                return r;

        const char *device = args[0];

        fd = open(device, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0) {
                bool ignore = ERRNO_IS_DEVICE_ABSENT_OR_EMPTY(errno);
                log_full_errno(ignore ? LOG_DEBUG : LOG_WARNING, errno,
                               "Failed to open device node '%s'%s: %m",
                               device, ignore ? ", ignoring" : "");
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
