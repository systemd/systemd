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
#include "fs-util.h"
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

static const struct {
        uint32_t flag;
        const char *name;
} capabilities_table[] = {
        { V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_VIDEO_CAPTURE_MPLANE, "capture"              },
        { V4L2_CAP_VIDEO_OUTPUT | V4L2_CAP_VIDEO_OUTPUT_MPLANE,   "video_output"         },
        { V4L2_CAP_VIDEO_OVERLAY,                                 "video_overlay"        },
        { V4L2_CAP_VBI_CAPTURE,                                   "vbi_capture"          },
        { V4L2_CAP_VBI_OUTPUT,                                    "vbi_output"           },
        { V4L2_CAP_SLICED_VBI_CAPTURE,                            "sliced_vbi_capture"   },
        { V4L2_CAP_SLICED_VBI_OUTPUT,                             "sliced_vbi_output"    },
        { V4L2_CAP_RDS_CAPTURE,                                   "rds_capture"          },
        { V4L2_CAP_VIDEO_OUTPUT_OVERLAY,                          "video_output_overlay" },
        { V4L2_CAP_HW_FREQ_SEEK,                                  "hw_freq_seek"         },
        { V4L2_CAP_RDS_OUTPUT,                                    "rds_output"           },
        { V4L2_CAP_VIDEO_M2M | V4L2_CAP_VIDEO_M2M_MPLANE,         "video_m2m"            },
        { V4L2_CAP_VIDEO_CAPTURE_MPLANE |
          V4L2_CAP_VIDEO_OUTPUT_MPLANE |
          V4L2_CAP_VIDEO_M2M_MPLANE,                              "mplane"               },
        { V4L2_CAP_AUDIO,                                         "audio"                },
        { V4L2_CAP_TUNER,                                         "tuner"                },
        { V4L2_CAP_RADIO,                                         "radio"                },
        { V4L2_CAP_MODULATOR,                                     "modulator"            },
        { V4L2_CAP_SDR_CAPTURE,                                   "sdr_capture"          },
        { V4L2_CAP_EXT_PIX_FORMAT,                                "ext_pix_format"       },
        { V4L2_CAP_SDR_OUTPUT,                                    "sdr_output"           },
        { V4L2_CAP_META_CAPTURE,                                  "meta_capture"         },
        { V4L2_CAP_READWRITE,                                     "readwrite"            },
        { V4L2_CAP_EDID,                                          "edid"                 },
        { V4L2_CAP_STREAMING,                                     "streaming"            },
        { V4L2_CAP_META_OUTPUT,                                   "meta_output"          },
        { V4L2_CAP_TOUCH,                                         "touch"                },
        { V4L2_CAP_IO_MC,                                         "io_mc"                },
};

static int run(int argc, char *argv[]) {
        _cleanup_close_ int fd = -EBADF;
        struct v4l2_capability v2cap;
        int r;

        char **args = NULL;
        r = common_parse_argv_full(argc, argv, /* min_args= */ 1, /* max_args= */ 1, &args);
        if (r <= 0)
                return r;

        const char *device = args[0];

        fd = xopenat(AT_FDCWD, device, O_RDONLY|O_NOCTTY);
        if (fd < 0) {
                bool ignore = ERRNO_IS_NEG_DEVICE_ABSENT_OR_EMPTY(fd);
                log_full_errno(ignore ? LOG_DEBUG : LOG_WARNING, fd,
                               "Failed to open device node '%s'%s: %m",
                               device, ignore ? ", ignoring" : "");
                return ignore ? 0 : fd;
        }

        if (ioctl(fd, VIDIOC_QUERYCAP, &v2cap) == 0) {
                uint32_t capabilities;

                printf("ID_V4L_VERSION=2\n");
                if (utf8_is_valid((char *)v2cap.card) && !string_has_cc((char *)v2cap.card, /* ok= */ NULL))
                        printf("ID_V4L_PRODUCT=%s\n", v2cap.card);
                printf("ID_V4L_CAPABILITIES=:");

                if (v2cap.capabilities & V4L2_CAP_DEVICE_CAPS)
                        capabilities = v2cap.device_caps;
                else
                        capabilities = v2cap.capabilities;

                FOREACH_ELEMENT(i, capabilities_table)
                        if ((capabilities & i->flag) > 0)
                                printf("%s:", i->name);

                printf("\n");
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
