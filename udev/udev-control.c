/*
 * Copyright (C) 2005-2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "udev.h"
#include "udevd.h"

struct udev_ctrl {
	int sock;
	struct sockaddr_un saddr;
	socklen_t addrlen;
};

struct udev_ctrl *udev_ctrl_new_from_socket(const char *socket_path)
{
	struct udev_ctrl *uctrl;

	uctrl = malloc(sizeof(struct udev_ctrl));
	if (uctrl == NULL)
		return NULL;
	memset(uctrl, 0x00, sizeof(struct udev_ctrl));

	uctrl->sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (uctrl->sock < 0) {
		err("error getting socket: %s\n", strerror(errno));
		free(uctrl);
		return NULL;
	}

	uctrl->saddr.sun_family = AF_LOCAL;
	strcpy(uctrl->saddr.sun_path, socket_path);
	uctrl->addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(uctrl->saddr.sun_path);
	/* translate leading '@' to abstract namespace */
	if (uctrl->saddr.sun_path[0] == '@')
		uctrl->saddr.sun_path[0] = '\0';
	return uctrl;
}

void udev_ctrl_unref(struct udev_ctrl *uctrl)
{
	if (uctrl == NULL)
		return;
	close(uctrl->sock);
}

static int ctrl_send(struct udev_ctrl *uctrl, enum udevd_ctrl_msg_type type, int intval, const char *buf)
{
	struct udevd_ctrl_msg ctrl_msg;
	int err;

	memset(&ctrl_msg, 0x00, sizeof(struct udevd_ctrl_msg));
	strcpy(ctrl_msg.magic, UDEVD_CTRL_MAGIC);
	ctrl_msg.type = type;

	if (buf != NULL)
		strlcpy(ctrl_msg.buf, buf, sizeof(ctrl_msg.buf));
	else
		ctrl_msg.intval = intval;

	err = sendto(uctrl->sock, &ctrl_msg, sizeof(ctrl_msg), 0, (struct sockaddr *)&uctrl->saddr, uctrl->addrlen);
	if (err == -1) {
		err("error sending message: %s\n", strerror(errno));
	}
	return err;
}

int udev_ctrl_set_log_level(struct udev_ctrl *uctrl, int priority)
{
	ctrl_send(uctrl, UDEVD_CTRL_SET_LOG_LEVEL, priority, NULL);
	return 0;
}

int udev_ctrl_stop_exec_queue(struct udev_ctrl *uctrl)
{
	ctrl_send(uctrl, UDEVD_CTRL_STOP_EXEC_QUEUE, 0, NULL);
	return 0;
}

int udev_ctrl_start_exec_queue(struct udev_ctrl *uctrl)
{
	ctrl_send(uctrl, UDEVD_CTRL_START_EXEC_QUEUE, 0, NULL);
	return 0;
}

int udev_ctrl_reload_rules(struct udev_ctrl *uctrl)
{
	ctrl_send(uctrl, UDEVD_CTRL_RELOAD_RULES, 0, NULL);
	return 0;
}

int udev_ctrl_set_env(struct udev_ctrl *uctrl, const char *key)
{
	ctrl_send(uctrl, UDEVD_CTRL_ENV, 0, optarg);
	return 0;
}

int udev_ctrl_set_max_childs(struct udev_ctrl *uctrl, int count)
{
	ctrl_send(uctrl, UDEVD_CTRL_SET_MAX_CHILDS, count, NULL);
	return 0;
}

int udev_ctrl_set_max_childs_running(struct udev_ctrl *uctrl, int count)
{
	ctrl_send(uctrl, UDEVD_CTRL_SET_MAX_CHILDS_RUNNING, count, NULL);
	return 0;
}
