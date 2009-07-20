/*
 * Copyright (C) 2009 Kay Sievers <kay.sievers@vrfy.org>
 * Copyright (c) 2009 Filippo Argiolas <filippo.argiolas@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details:
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <linux/videodev.h>
#include <linux/videodev2.h>

int main (int argc, char *argv[])
{
	static const struct option options[] = {
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	int fd;
	char *device;
	struct video_capability v1cap;
	struct v4l2_capability v2cap;

	while (1) {
		int option;

		option = getopt_long(argc, argv, "h", options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'h':
			printf("Usage: v4l_id [--help] <device file>\n\n");
			return 0;
		default:
			return 1;
		}
	}
	device = argv[optind];

	if (device == NULL)
		return 2;
	fd = open (device, O_RDONLY);
	if (fd < 0)
		return 3;

	if (ioctl (fd, VIDIOC_QUERYCAP, &v2cap) == 0) {
		printf("ID_V4L_VERSION=2\n");
		printf("ID_V4L_PRODUCT=%s\n", v2cap.card);
		printf("ID_V4L_CAPABILITIES=:");
		if ((v2cap.capabilities & V4L2_CAP_VIDEO_CAPTURE) > 0)
			printf("capture:");
		if ((v2cap.capabilities & V4L2_CAP_VIDEO_OUTPUT) > 0)
			printf("video_output:");
		if ((v2cap.capabilities & V4L2_CAP_VIDEO_OVERLAY) > 0)
			printf("video_overlay:");
		if ((v2cap.capabilities & V4L2_CAP_AUDIO) > 0)
			printf("audio:");
		if ((v2cap.capabilities & V4L2_CAP_TUNER) > 0)
			printf("tuner:");
		if ((v2cap.capabilities & V4L2_CAP_RADIO) > 0)
			printf("radio:");
		printf("\n");
	} else if (ioctl (fd, VIDIOCGCAP, &v1cap) == 0) {
		printf("ID_V4L_VERSION=1\n");
		printf("ID_V4L_PRODUCT=%s\n", v1cap.name);
		printf("ID_V4L_CAPABILITIES=:");
		if ((v1cap.type & VID_TYPE_CAPTURE) > 0)
			printf("capture:");
		if ((v1cap.type & VID_TYPE_OVERLAY) > 0)
			printf("video_overlay:");
		if (v1cap.audios > 0)
			printf("audio:");
		if ((v1cap.type & VID_TYPE_TUNER) > 0)
			printf("tuner:");
		printf("\n");
	}

	close (fd);
	return 0;
}
