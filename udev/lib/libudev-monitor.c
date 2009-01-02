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
#include <linux/netlink.h>

#include "libudev.h"
#include "libudev-private.h"

struct udev_monitor {
	struct udev *udev;
	int refcount;
	int sock;
	struct sockaddr_nl snl;
	struct sockaddr_un sun;
	socklen_t addrlen;
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
 * release the resources of the udev monitor.
 *
 * Returns: a new udev monitor, or #NULL, in case of an error
 **/
struct udev_monitor *udev_monitor_new_from_socket(struct udev *udev, const char *socket_path)
{
	struct udev_monitor *udev_monitor;
	struct stat statbuf;

	if (udev == NULL)
		return NULL;
	if (socket_path == NULL)
		return NULL;
	udev_monitor = calloc(1, sizeof(struct udev_monitor));
	if (udev_monitor == NULL)
		return NULL;
	udev_monitor->refcount = 1;
	udev_monitor->udev = udev;

	udev_monitor->sun.sun_family = AF_LOCAL;
	if (socket_path[0] == '@') {
		/* translate leading '@' to abstract namespace */
		util_strlcpy(udev_monitor->sun.sun_path, socket_path, sizeof(udev_monitor->sun.sun_path));
		udev_monitor->sun.sun_path[0] = '\0';
		udev_monitor->addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(socket_path);
	} else if (stat(socket_path, &statbuf) == 0 && S_ISSOCK(statbuf.st_mode)) {
		/* existing socket file */
		util_strlcpy(udev_monitor->sun.sun_path, socket_path, sizeof(udev_monitor->sun.sun_path));
		udev_monitor->addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(socket_path);
	} else {
		/* no socket file, assume abstract namespace socket */
		util_strlcpy(&udev_monitor->sun.sun_path[1], socket_path, sizeof(udev_monitor->sun.sun_path)-1);
		udev_monitor->addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(socket_path)+1;
	}
	udev_monitor->sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (udev_monitor->sock == -1) {
		err(udev, "error getting socket: %m\n");
		free(udev_monitor);
		return NULL;
	}
	dbg(udev, "monitor %p created with '%s'\n", udev_monitor, socket_path);
	return udev_monitor;
}

struct udev_monitor *udev_monitor_new_from_netlink(struct udev *udev)
{
	struct udev_monitor *udev_monitor;

	if (udev == NULL)
		return NULL;
	udev_monitor = calloc(1, sizeof(struct udev_monitor));
	if (udev_monitor == NULL)
		return NULL;
	udev_monitor->refcount = 1;
	udev_monitor->udev = udev;

	udev_monitor->sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (udev_monitor->sock == -1) {
		err(udev, "error getting socket: %m\n");
		free(udev_monitor);
		return NULL;
	}

	udev_monitor->snl.nl_family = AF_NETLINK;
	udev_monitor->snl.nl_pid = getpid();
	udev_monitor->snl.nl_groups = 1;

	dbg(udev, "monitor %p created with NETLINK_KOBJECT_UEVENT\n", udev_monitor);
	return udev_monitor;
}

int udev_monitor_enable_receiving(struct udev_monitor *udev_monitor)
{
	int err;
	const int on = 1;

	if (udev_monitor->snl.nl_family != 0) {
		err = bind(udev_monitor->sock, (struct sockaddr *)&udev_monitor->snl, sizeof(struct sockaddr_nl));
		if (err < 0) {
			err(udev_monitor->udev, "bind failed: %m\n");
			return err;
		}
		dbg(udev_monitor->udev, "monitor %p listening on netlink\n", udev_monitor);
	} else if (udev_monitor->sun.sun_family != 0) {
		err = bind(udev_monitor->sock, (struct sockaddr *)&udev_monitor->sun, udev_monitor->addrlen);
		if (err < 0) {
			err(udev_monitor->udev, "bind failed: %m\n");
			return err;
		}
		/* enable receiving of the sender credentials */
		setsockopt(udev_monitor->sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));
		dbg(udev_monitor->udev, "monitor %p listening on socket\n", udev_monitor);
	}
	return 0;
}

int udev_monitor_set_receive_buffer_size(struct udev_monitor *udev_monitor, int size)
{
	if (udev_monitor == NULL)
		return -1;
	return setsockopt(udev_monitor->sock, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size));
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
 * Drop a reference ofa udev monitor. If the refcount reaches zero,
 * the bound socket will be closed, and the resources of the monitor
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
	if (udev_monitor->sock >= 0)
		close(udev_monitor->sock);
	dbg(udev_monitor->udev, "monitor %p released\n", udev_monitor);
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
	return udev_monitor->sock;
}

/**
 * udev_monitor_receive_device:
 * @udev_monitor: udev monitor
 *
 * Receive data from the udev monitor socket, allocate a new udev
 * device, fill in the received data, and return the device.
 *
 * Only socket connections with uid=0 are accepted. The caller
 * needs to make sure that there is data to read from the socket.
 * The call will block until the socket becomes readable.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev device.
 *
 * Returns: a new udev device, or #NULL, in case of an error
 **/
struct udev_device *udev_monitor_receive_device(struct udev_monitor *udev_monitor)
{
	struct udev_device *udev_device;
	struct msghdr smsg;
	struct iovec iov;
	char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
	char buf[4096];
	size_t bufpos;
	int devpath_set = 0;
	int subsystem_set = 0;
	int action_set = 0;
	int maj = 0;
	int min = 0;

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

	if (recvmsg(udev_monitor->sock, &smsg, 0) < 0) {
		if (errno != EINTR)
			info(udev_monitor->udev, "unable to receive message");
		return NULL;
	}

	if (udev_monitor->sun.sun_family != 0) {
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&smsg);
		struct ucred *cred = (struct ucred *)CMSG_DATA (cmsg);

		if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
			info(udev_monitor->udev, "no sender credentials received, message ignored");
			return NULL;
		}

		if (cred->uid != 0) {
			info(udev_monitor->udev, "sender uid=%d, message ignored", cred->uid);
			return NULL;
		}
	}

	/* skip header */
	bufpos = strlen(buf) + 1;
	if (bufpos < sizeof("a@/d") || bufpos >= sizeof(buf)) {
		info(udev_monitor->udev, "invalid message length");
		return NULL;
	}

	/* check message header */
	if (strstr(buf, "@/") == NULL) {
		info(udev_monitor->udev, "unrecognized message header");
		return NULL;
	}

	udev_device = device_new(udev_monitor->udev);
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
			char path[UTIL_PATH_SIZE];

			util_strlcpy(path, udev_get_sys_path(udev_monitor->udev), sizeof(path));
			util_strlcat(path, &key[8], sizeof(path));
			udev_device_set_syspath(udev_device, path);
			devpath_set = 1;
		} else if (strncmp(key, "SUBSYSTEM=", 10) == 0) {
			udev_device_set_subsystem(udev_device, &key[10]);
			subsystem_set = 1;
		} else if (strncmp(key, "DEVTYPE=", 8) == 0) {
			udev_device_set_devtype(udev_device, &key[8]);
		} else if (strncmp(key, "DEVNAME=", 8) == 0) {
			udev_device_set_devnode(udev_device, &key[8]);
		} else if (strncmp(key, "DEVLINKS=", 9) == 0) {
			char devlinks[UTIL_PATH_SIZE];
			char *slink;
			char *next;

			util_strlcpy(devlinks, &key[9], sizeof(devlinks));
			slink = devlinks;
			next = strchr(slink, ' ');
			while (next != NULL) {
				next[0] = '\0';
				udev_device_add_devlink(udev_device, slink);
				slink = &next[1];
				next = strchr(slink, ' ');
			}
			if (slink[0] != '\0')
				udev_device_add_devlink(udev_device, slink);
		} else if (strncmp(key, "DRIVER=", 7) == 0) {
			udev_device_set_driver(udev_device, &key[7]);
		} else if (strncmp(key, "ACTION=", 7) == 0) {
			udev_device_set_action(udev_device, &key[7]);
			action_set = 1;
		} else if (strncmp(key, "MAJOR=", 6) == 0) {
			maj = strtoull(&key[6], NULL, 10);
		} else if (strncmp(key, "MINOR=", 6) == 0) {
			min = strtoull(&key[6], NULL, 10);
		} else if (strncmp(key, "DEVPATH_OLD=", 12) == 0) {
			udev_device_set_devpath_old(udev_device, &key[12]);
		} else if (strncmp(key, "PHYSDEVPATH=", 12) == 0) {
			udev_device_set_physdevpath(udev_device, &key[12]);
		} else if (strncmp(key, "SEQNUM=", 7) == 0) {
			udev_device_set_seqnum(udev_device, strtoull(&key[7], NULL, 10));
		} else if (strncmp(key, "TIMEOUT=", 8) == 0) {
			udev_device_set_timeout(udev_device, strtoull(&key[8], NULL, 10));
		} else if (strncmp(key, "PHYSDEV", 7) == 0) {
			/* skip deprecated values */
			continue;
		} else {
			udev_device_add_property_from_string(udev_device, key);
		}
	}
	if (!devpath_set || !subsystem_set || !action_set) {
		info(udev_monitor->udev, "missing values, skip\n");
		udev_device_unref(udev_device);
		return NULL;
	}
	if (maj > 0)
		udev_device_set_devnum(udev_device, makedev(maj, min));
	udev_device_set_info_loaded(udev_device);
	return udev_device;
}

int udev_monitor_send_device(struct udev_monitor *udev_monitor, struct udev_device *udev_device)
{
	const char *buf;
	ssize_t len;
	ssize_t count;

	len = udev_device_get_properties_monitor_buf(udev_device, &buf);
	if (len < 32)
		return -1;
	count = sendto(udev_monitor->sock,
		       buf, len, 0,
		       (struct sockaddr *)&udev_monitor->sun, udev_monitor->addrlen);
	info(udev_monitor->udev, "passed %zi bytes to monitor %p, \n", count, udev_monitor);
	return count;
}
