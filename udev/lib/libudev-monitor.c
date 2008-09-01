/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "libudev.h"
#include "libudev-private.h"
#include "../udev.h"

struct udev_monitor {
	struct udev *udev;
	int refcount;
	int socket;
};

/**
 * udev_monitor_new_from_socket:
 * @udev: udev library context
 * @socket_path: unix socket path
 *
 * Create new udev monitor, setup and connect to a specified socket. The
 * path to a socket can point to an existing socket file, or it will be
 * created if needed. If neccessary, the permissions adjustment as well as
 * the later cleanup of the socket file, needs to be done by the caller.
 * If the socket path starts with a '@' character, an abstract namespace
 * socket will be used.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the ressources of the udev monitor.
 *
 * Returns: a new udev monitor, or #NULL, in case of an error
 **/
struct udev_monitor *udev_monitor_new_from_socket(struct udev *udev, const char *socket_path)
{
	struct udev_monitor *udev_monitor;
	struct sockaddr_un saddr;
	socklen_t addrlen;
	const int on = 1;

	if (udev == NULL)
		return NULL;
	if (socket_path == NULL)
		return NULL;
	udev_monitor = malloc(sizeof(struct udev_monitor));
	if (udev_monitor == NULL)
		return NULL;
	memset(udev_monitor, 0x00, sizeof(struct udev_monitor));
	udev_monitor->refcount = 1;
	udev_monitor->udev = udev;

	memset(&saddr, 0x00, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	strcpy(saddr.sun_path, socket_path);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path);

	/* translate leading '@' to abstract namespace */
	if (saddr.sun_path[0] == '@')
		saddr.sun_path[0] = '\0';

	udev_monitor->socket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (udev_monitor->socket == -1) {
		log_err(udev, "error getting socket: %s\n", strerror(errno));
		free(udev_monitor);
		return NULL;
	}

	if (bind(udev_monitor->socket, (struct sockaddr *) &saddr, addrlen) < 0) {
		log_err(udev, "bind failed: %s\n", strerror(errno));
		close(udev_monitor->socket);
		free(udev_monitor);
		return NULL;
	}

	/* enable receiving of the sender credentials */
	setsockopt(udev_monitor->socket, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));
	log_info(udev_monitor->udev, "udev_monitor: %p created\n", udev_monitor);

	return udev_monitor;
}

/**
 * udev_monitor_ref:
 * @udev_monitor: udev monitor
 *
 * Take a reference of a udev monitor.
 *
 * Returns: the passed udev monitor
 **/
struct udev_monitor *udev_monitor_ref(struct udev_monitor *udev_monitor)
{
	if (udev_monitor == NULL)
		return NULL;
	udev_monitor->refcount++;
	return udev_monitor;
}

/**
 * udev_monitor_unref:
 * @udev_monitor: udev monitor
 *
 * Drop a reference of a udev monitor. If the refcount reaches zero,
 * the bound socket will be closed, and the ressources of the monitor
 * will be released.
 *
 **/
void udev_monitor_unref(struct udev_monitor *udev_monitor)
{
	if (udev_monitor == NULL)
		return;
	udev_monitor->refcount--;
	if (udev_monitor->refcount > 0)
		return;
	close(udev_monitor->socket);
	log_info(udev_monitor->udev, "udev_monitor: %p released\n", udev_monitor);
	free(udev_monitor);
}

/**
 * udev_monitor_get_udev:
 * @udev_monitor: udev monitor
 *
 * Retrieve the udev library context the monitor was created with.
 *
 * Returns: the udev library context
 **/
struct udev *udev_monitor_get_udev(struct udev_monitor *udev_monitor)
{
	if (udev_monitor == NULL)
		return NULL;
	return udev_monitor->udev;
}

/**
 * udev_monitor_get_fd:
 * @udev_monitor: udev monitor
 *
 * Retrieve the socket file descriptor associated with the monitor.
 *
 * Returns: the socket file descriptor
 **/
int udev_monitor_get_fd(struct udev_monitor *udev_monitor)
{
	if (udev_monitor == NULL)
		return -1;
	return udev_monitor->socket;
}

/**
 * udev_monitor_get_device:
 * @udev_monitor: udev monitor
 *
 * Retrieve data from the udev monitor socket, allocate a new udev
 * device, fill in the received data, and return the device.
 *
 * Only socket connections with uid=0 are accepted. The caller
 * needs to make sure, that there is data to read from the socket,
 * the call will block until the socket becomes readable.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the ressources of the udev device.
 *
 * Returns: a new udev device, or #NULL, in case of an error
 **/
struct udev_device *udev_monitor_get_device(struct udev_monitor *udev_monitor)
{
	struct udev_device *udev_device;
	struct msghdr smsg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct ucred *cred;
	char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
	char buf[4096];
	size_t bufpos;

	if (udev_monitor == NULL)
		return NULL;
	memset(buf, 0x00, sizeof(buf));
	iov.iov_base = &buf;
	iov.iov_len = sizeof(buf);
	memset (&smsg, 0x00, sizeof(struct msghdr));
	smsg.msg_iov = &iov;
	smsg.msg_iovlen = 1;
	smsg.msg_control = cred_msg;
	smsg.msg_controllen = sizeof(cred_msg);

	if (recvmsg(udev_monitor->socket, &smsg, 0) < 0) {
		if (errno != EINTR)
			log_info(udev_monitor->udev, "unable to receive message");
		return NULL;
	}
	cmsg = CMSG_FIRSTHDR(&smsg);
	cred = (struct ucred *)CMSG_DATA (cmsg);

	if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
		log_info(udev_monitor->udev, "no sender credentials received, message ignored");
		return NULL;
	}

	if (cred->uid != 0) {
		log_info(udev_monitor->udev, "sender uid=%d, message ignored", cred->uid);
		return NULL;
	}

	/* skip header */
	bufpos = strlen(buf) + 1;
	if (bufpos < sizeof("a@/d") || bufpos >= sizeof(buf)) {
		log_info(udev_monitor->udev, "invalid message length");
		return NULL;
	}

	/* check message header */
	if (strstr(buf, "@/") == NULL) {
		log_info(udev_monitor->udev, "unrecognized message header");
		return NULL;
	}

	udev_device = device_init(udev_monitor->udev);
	if (udev_device == NULL) {
		return NULL;
	}

	while (bufpos < sizeof(buf)) {
		char *key;
		size_t keylen;

		key = &buf[bufpos];
		keylen = strlen(key);
		if (keylen == 0)
			break;
		bufpos += keylen + 1;

		if (strncmp(key, "DEVPATH=", 8) == 0) {
			udev_device->devpath = strdup(&key[8]);
		} else if (strncmp(key, "SUBSYSTEM=", 10) == 0) {
			udev_device->subsystem = strdup(&key[10]);
		} else if (strncmp(key, "DEVNAME=", 8) == 0) {
			udev_device->devname = strdup(&key[8]);
		} else if (strncmp(key, "DEVLINKS=", 9) == 0) {
			char *slink = &key[9];
			char *next = strchr(slink, ' ');

			while (next != NULL) {
				next[0] = '\0';
				name_list_add(&udev_device->link_list, slink, 0);
				slink = &next[1];
				next = strchr(slink, ' ');
			}
			if (slink[0] != '\0')
				name_list_add(&udev_device->link_list, slink, 0);
		}
		name_list_add(&udev_device->env_list, key, 0);
	}

	return udev_device;
}
