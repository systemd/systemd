/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "libudev.h"
#include "libudev-private.h"

/* wire protocol magic must match */
#define UDEV_CTRL_MAGIC				0xdead1dea

enum udev_ctrl_msg_type {
	UDEV_CTRL_UNKNOWN,
	UDEV_CTRL_SET_LOG_LEVEL,
	UDEV_CTRL_STOP_EXEC_QUEUE,
	UDEV_CTRL_START_EXEC_QUEUE,
	UDEV_CTRL_RELOAD_RULES,
	UDEV_CTRL_SET_ENV,
	UDEV_CTRL_SET_CHILDREN_MAX,
	UDEV_CTRL_SETTLE,
};

struct udev_ctrl_msg_wire {
	char version[16];
	unsigned int magic;
	enum udev_ctrl_msg_type type;
	union {
		int intval;
		char buf[256];
	};
};

struct udev_ctrl_msg {
	int refcount;
	struct udev_ctrl *uctrl;
	struct udev_ctrl_msg_wire ctrl_msg_wire;
	pid_t pid;
};

struct udev_ctrl {
	int refcount;
	struct udev *udev;
	int sock;
	struct sockaddr_un saddr;
	socklen_t addrlen;
};

struct udev_ctrl *udev_ctrl_new_from_socket(struct udev *udev, const char *socket_path)
{
	struct udev_ctrl *uctrl;

	uctrl = calloc(1, sizeof(struct udev_ctrl));
	if (uctrl == NULL)
		return NULL;
	uctrl->refcount = 1;
	uctrl->udev = udev;

	uctrl->sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (uctrl->sock < 0) {
		err(udev, "error getting socket: %m\n");
		udev_ctrl_unref(uctrl);
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

int udev_ctrl_enable_receiving(struct udev_ctrl *uctrl)
{
	int err;
	const int feature_on = 1;

	err= bind(uctrl->sock, (struct sockaddr *)&uctrl->saddr, uctrl->addrlen);
	if (err < 0) {
		err(uctrl->udev, "bind failed: %m\n");
		return err;
	}

	/* enable receiving of the sender credentials */
	setsockopt(uctrl->sock, SOL_SOCKET, SO_PASSCRED, &feature_on, sizeof(feature_on));
	return 0;
}

struct udev *udev_ctrl_get_udev(struct udev_ctrl *uctrl)
{
	return uctrl->udev;
}

struct udev_ctrl *udev_ctrl_ref(struct udev_ctrl *uctrl)
{
	if (uctrl == NULL)
		return NULL;
	uctrl->refcount++;
	return uctrl;
}

void udev_ctrl_unref(struct udev_ctrl *uctrl)
{
	if (uctrl == NULL)
		return;
	uctrl->refcount--;
	if (uctrl->refcount > 0)
		return;
	if (uctrl->sock >= 0)
		close(uctrl->sock);
	free(uctrl);
}

int udev_ctrl_get_fd(struct udev_ctrl *uctrl)
{
	if (uctrl == NULL)
		return -1;
	return uctrl->sock;
}

static int ctrl_send(struct udev_ctrl *uctrl, enum udev_ctrl_msg_type type, int intval, const char *buf)
{
	struct udev_ctrl_msg_wire ctrl_msg_wire;
	int err;

	memset(&ctrl_msg_wire, 0x00, sizeof(struct udev_ctrl_msg_wire));
	strcpy(ctrl_msg_wire.version, "udev-" VERSION);
	ctrl_msg_wire.magic = UDEV_CTRL_MAGIC;
	ctrl_msg_wire.type = type;

	if (buf != NULL)
		util_strscpy(ctrl_msg_wire.buf, sizeof(ctrl_msg_wire.buf), buf);
	else
		ctrl_msg_wire.intval = intval;

	err = sendto(uctrl->sock, &ctrl_msg_wire, sizeof(ctrl_msg_wire), 0,
		     (struct sockaddr *)&uctrl->saddr, uctrl->addrlen);
	if (err == -1) {
		err(uctrl->udev, "error sending message: %m\n");
	}
	return err;
}

int udev_ctrl_send_set_log_level(struct udev_ctrl *uctrl, int priority)
{
	return ctrl_send(uctrl, UDEV_CTRL_SET_LOG_LEVEL, priority, NULL);
}

int udev_ctrl_send_stop_exec_queue(struct udev_ctrl *uctrl)
{
	return ctrl_send(uctrl, UDEV_CTRL_STOP_EXEC_QUEUE, 0, NULL);
}

int udev_ctrl_send_start_exec_queue(struct udev_ctrl *uctrl)
{
	return ctrl_send(uctrl, UDEV_CTRL_START_EXEC_QUEUE, 0, NULL);
}

int udev_ctrl_send_reload_rules(struct udev_ctrl *uctrl)
{
	return ctrl_send(uctrl, UDEV_CTRL_RELOAD_RULES, 0, NULL);
}

int udev_ctrl_send_set_env(struct udev_ctrl *uctrl, const char *key)
{
	return ctrl_send(uctrl, UDEV_CTRL_SET_ENV, 0, key);
}

int udev_ctrl_send_set_children_max(struct udev_ctrl *uctrl, int count)
{
	return ctrl_send(uctrl, UDEV_CTRL_SET_CHILDREN_MAX, count, NULL);
}

int udev_ctrl_send_settle(struct udev_ctrl *uctrl)
{
	return ctrl_send(uctrl, UDEV_CTRL_SETTLE, 0, NULL);
}

struct udev_ctrl_msg *udev_ctrl_receive_msg(struct udev_ctrl *uctrl)
{
	struct udev_ctrl_msg *uctrl_msg;
	ssize_t size;
	struct msghdr smsg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct ucred *cred;
	char cred_msg[CMSG_SPACE(sizeof(struct ucred))];

	uctrl_msg = calloc(1, sizeof(struct udev_ctrl_msg));
	if (uctrl_msg == NULL)
		return NULL;
	uctrl_msg->refcount = 1;
	uctrl_msg->uctrl = uctrl;

	iov.iov_base = &uctrl_msg->ctrl_msg_wire;
	iov.iov_len = sizeof(struct udev_ctrl_msg_wire);

	memset(&smsg, 0x00, sizeof(struct msghdr));
	smsg.msg_iov = &iov;
	smsg.msg_iovlen = 1;
	smsg.msg_control = cred_msg;
	smsg.msg_controllen = sizeof(cred_msg);

	size = recvmsg(uctrl->sock, &smsg, 0);
	if (size <  0) {
		err(uctrl->udev, "unable to receive user udevd message: %m\n");
		goto err;
	}
	cmsg = CMSG_FIRSTHDR(&smsg);
	cred = (struct ucred *) CMSG_DATA(cmsg);

	if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
		err(uctrl->udev, "no sender credentials received, message ignored\n");
		goto err;
	}

	if (cred->uid != 0) {
		err(uctrl->udev, "sender uid=%i, message ignored\n", cred->uid);
		goto err;
	}

	uctrl_msg->pid = cred->pid;

	if (uctrl_msg->ctrl_msg_wire.magic != UDEV_CTRL_MAGIC) {
		err(uctrl->udev, "message magic 0x%08x doesn't match, ignore it\n", uctrl_msg->ctrl_msg_wire.magic);
		goto err;
	}

	dbg(uctrl->udev, "created ctrl_msg %p (%i)\n", uctrl_msg, uctrl_msg->ctrl_msg_wire.type);
	return uctrl_msg;
err:
	udev_ctrl_msg_unref(uctrl_msg);
	return NULL;
}

struct udev_ctrl_msg *udev_ctrl_msg_ref(struct udev_ctrl_msg *ctrl_msg)
{
	if (ctrl_msg == NULL)
		return NULL;
	ctrl_msg->refcount++;
	return ctrl_msg;
}

void udev_ctrl_msg_unref(struct udev_ctrl_msg *ctrl_msg)
{
	if (ctrl_msg == NULL)
		return;
	ctrl_msg->refcount--;
	if (ctrl_msg->refcount > 0)
		return;
	dbg(ctrl_msg->uctrl->udev, "release ctrl_msg %p\n", ctrl_msg);
	free(ctrl_msg);
}

int udev_ctrl_get_set_log_level(struct udev_ctrl_msg *ctrl_msg)
{
	if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_SET_LOG_LEVEL)
		return ctrl_msg->ctrl_msg_wire.intval;
	return -1;
}

int udev_ctrl_get_stop_exec_queue(struct udev_ctrl_msg *ctrl_msg)
{
	if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_STOP_EXEC_QUEUE)
		return 1;
	return -1;
}

int udev_ctrl_get_start_exec_queue(struct udev_ctrl_msg *ctrl_msg)
{
	if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_START_EXEC_QUEUE)
		return 1;
	return -1;
}

int udev_ctrl_get_reload_rules(struct udev_ctrl_msg *ctrl_msg)
{
	if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_RELOAD_RULES)
		return 1;
	return -1;
}

const char *udev_ctrl_get_set_env(struct udev_ctrl_msg *ctrl_msg)
{
	if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_SET_ENV)
		return ctrl_msg->ctrl_msg_wire.buf;
	return NULL;
}

int udev_ctrl_get_set_children_max(struct udev_ctrl_msg *ctrl_msg)
{
	if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_SET_CHILDREN_MAX)
		return ctrl_msg->ctrl_msg_wire.intval;
	return -1;
}

pid_t udev_ctrl_get_settle(struct udev_ctrl_msg *ctrl_msg)
{
	if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_SETTLE)
		return ctrl_msg->pid;
	return -1;
}
