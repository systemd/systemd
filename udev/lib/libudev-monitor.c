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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/filter.h>

#include "libudev.h"
#include "libudev-private.h"

struct udev_monitor {
	struct udev *udev;
	int refcount;
	int sock;
	struct sockaddr_nl snl;
	struct sockaddr_nl snl_peer;
	struct sockaddr_un sun;
	socklen_t addrlen;
	struct udev_list_node filter_subsystem_list;
};

enum udev_monitor_netlink_group {
	UDEV_MONITOR_KERNEL	= 1,
	UDEV_MONITOR_UDEV	= 2,
};

#define UDEV_MONITOR_MAGIC		0xcafe1dea
struct udev_monitor_netlink_header {
	/* udev version text */
	char version[16];
	/*
	 * magic to protect against daemon <-> library message format mismatch
	 * used in the kernel from socket filter rules; needs to be stored in network order
	 */
	unsigned int magic;
	/* properties buffer */
	unsigned short properties_off;
	unsigned short properties_len;
	/*
	 * hashes of some common device properties strings to filter with socket filters in
	 * the client used in the kernel from socket filter rules; needs to be stored in
	 * network order
	 */
	unsigned int filter_subsystem;
	unsigned int filter_devtype;
};

static struct udev_monitor *udev_monitor_new(struct udev *udev)
{
	struct udev_monitor *udev_monitor;

	udev_monitor = calloc(1, sizeof(struct udev_monitor));
	if (udev_monitor == NULL)
		return NULL;
	udev_monitor->refcount = 1;
	udev_monitor->udev = udev;
	udev_list_init(&udev_monitor->filter_subsystem_list);
	return udev_monitor;
}

/**
 * udev_monitor_new_from_socket:
 * @udev: udev library context
 * @socket_path: unix socket path
 *
 * Create new udev monitor and connect to a specified socket. The
 * path to a socket either points to an existing socket file, or if
 * the socket path starts with a '@' character, an abstract namespace
 * socket will be used.
 *
 * A socket file will not be created. If it does not already exist,
 * it will fall-back and connect to an abstract namespace socket with
 * the given path. The permissions adjustment of a socket file, as
 * well as the later cleanup, needs to be done by the caller.
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
	udev_monitor = udev_monitor_new(udev);
	if (udev_monitor == NULL)
		return NULL;

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
	util_set_fd_cloexec(udev_monitor->sock);

	dbg(udev, "monitor %p created with '%s'\n", udev_monitor, socket_path);
	return udev_monitor;
}

/**
 * udev_monitor_new_from_netlink:
 * @udev: udev library context
 * @name: name of event source
 *
 * Create new udev monitor and connect to a specified event
 * source. Valid sources identifiers are "udev" and "kernel".
 *
 * Applications should usually not connect directly to the
 * "kernel" events, because the devices might not be useable
 * at that time, before udev has configured them, and created
 * device nodes.
 *
 * Accessing devices at the same time as udev, might result
 * in unpredictable behavior.
 *
 * The "udev" events are sent out after udev has finished its
 * event processing, all rules have been processed, and needed
 * device nodes are created.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the udev monitor.
 *
 * Returns: a new udev monitor, or #NULL, in case of an error
 **/
struct udev_monitor *udev_monitor_new_from_netlink(struct udev *udev, const char *name)
{
	struct udev_monitor *udev_monitor;
	unsigned int group;

	if (udev == NULL)
		return NULL;

	if (name == NULL)
		return NULL;
	if (strcmp(name, "kernel") == 0)
		group = UDEV_MONITOR_KERNEL;
	else if (strcmp(name, "udev") == 0)
		group = UDEV_MONITOR_UDEV;
	else
		return NULL;

	udev_monitor = udev_monitor_new(udev);
	if (udev_monitor == NULL)
		return NULL;

	udev_monitor->sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (udev_monitor->sock == -1) {
		err(udev, "error getting socket: %m\n");
		free(udev_monitor);
		return NULL;
	}
	util_set_fd_cloexec(udev_monitor->sock);

	udev_monitor->snl.nl_family = AF_NETLINK;
	udev_monitor->snl.nl_groups = group;
	udev_monitor->snl_peer.nl_family = AF_NETLINK;
	udev_monitor->snl_peer.nl_groups = UDEV_MONITOR_UDEV;

	dbg(udev, "monitor %p created with NETLINK_KOBJECT_UEVENT (%u)\n", udev_monitor, group);
	return udev_monitor;
}

static inline void bpf_stmt(struct sock_filter *inss, unsigned int *i,
			    unsigned short code, unsigned int data)
{
	struct sock_filter *ins = &inss[*i];

	ins->code = code;
	ins->k = data;
	(*i)++;
}

static inline void bpf_jmp(struct sock_filter *inss, unsigned int *i,
			   unsigned short code, unsigned int data,
			   unsigned short jt, unsigned short jf)
{
	struct sock_filter *ins = &inss[*i];

	ins->code = code;
	ins->jt = jt;
	ins->jf = jf;
	ins->k = data;
	(*i)++;
}

int udev_monitor_filter_update(struct udev_monitor *udev_monitor)
{
	static struct sock_filter ins[256];
	static struct sock_fprog filter;
	unsigned int i;
	struct udev_list_entry *list_entry;
	int err;

	if (udev_list_get_entry(&udev_monitor->filter_subsystem_list) == NULL)
		return 0;

	memset(ins, 0x00, sizeof(ins));
	i = 0;

	/* load magic in A */
	bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, magic));
	/* jump if magic matches */
	bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, UDEV_MONITOR_MAGIC, 1, 0);
	/* wrong magic, pass packet */
	bpf_stmt(ins, &i, BPF_RET|BPF_K, 0xffffffff);

	/* add all subsystem match values */
	udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_monitor->filter_subsystem_list)) {
		unsigned int hash;

		/* load filter_subsystem value in A */
		bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, filter_subsystem));
		hash = util_string_hash32(udev_list_entry_get_name(list_entry));
		if (udev_list_entry_get_value(list_entry) == NULL) {
			/* jump if subsystem does not match */
			bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, hash, 0, 1);
		} else {
			/* jump if subsystem does not match */
			bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, hash, 0, 3);

			/* load filter_devtype value in A */
			bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, filter_devtype));
			/* jump if value does not match */
			hash = util_string_hash32(udev_list_entry_get_value(list_entry));
			bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, hash, 0, 1);
		}

		/* matched, pass packet */
		bpf_stmt(ins, &i, BPF_RET|BPF_K, 0xffffffff);

		if (i+1 >= ARRAY_SIZE(ins))
			return -1;
	}
	/* nothing matched, drop packet */
	bpf_stmt(ins, &i, BPF_RET|BPF_K, 0);

	/* install filter */
	filter.len = i;
	filter.filter = ins;
	err = setsockopt(udev_monitor->sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
	return err;
}

int udev_monitor_enable_receiving(struct udev_monitor *udev_monitor)
{
	int err;
	const int on = 1;

	if (udev_monitor->sun.sun_family != 0) {
		err = bind(udev_monitor->sock,
			   (struct sockaddr *)&udev_monitor->sun, udev_monitor->addrlen);
	} else if (udev_monitor->snl.nl_family != 0) {
		udev_monitor_filter_update(udev_monitor);
		err = bind(udev_monitor->sock,
			   (struct sockaddr *)&udev_monitor->snl, sizeof(struct sockaddr_nl));
	} else {
		return -EINVAL;
	}

	if (err < 0) {
		err(udev_monitor->udev, "bind failed: %m\n");
		return err;
	}

	/* enable receiving of sender credentials */
	setsockopt(udev_monitor->sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));
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
 * Drop a reference of a udev monitor. If the refcount reaches zero,
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
	udev_list_cleanup_entries(udev_monitor->udev, &udev_monitor->filter_subsystem_list);
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

static int passes_filter(struct udev_monitor *udev_monitor, struct udev_device *udev_device)
{
	struct udev_list_entry *list_entry;

	if (udev_list_get_entry(&udev_monitor->filter_subsystem_list) == NULL)
		return 1;

	udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_monitor->filter_subsystem_list)) {
		const char *subsys = udev_list_entry_get_name(list_entry);
		const char *dsubsys = udev_device_get_subsystem(udev_device);
		const char *devtype;
		const char *ddevtype;

		if (strcmp(dsubsys, subsys) != 0)
			continue;

		devtype = udev_list_entry_get_value(list_entry);
		if (devtype == NULL)
			return 1;
		ddevtype = udev_device_get_devtype(udev_device);
		if (ddevtype == NULL)
			continue;
		if (strcmp(ddevtype, devtype) == 0)
			return 1;
	}
	return 0;
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
	struct cmsghdr *cmsg;
	struct sockaddr_nl snl;
	struct ucred *cred;
	char buf[8192];
	ssize_t buflen;
	ssize_t bufpos;
	struct udev_monitor_netlink_header *nlh;
	int devpath_set = 0;
	int subsystem_set = 0;
	int action_set = 0;
	int maj = 0;
	int min = 0;

retry:
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

	if (udev_monitor->snl.nl_family != 0) {
		smsg.msg_name = &snl;
		smsg.msg_namelen = sizeof(snl);
	}

	buflen = recvmsg(udev_monitor->sock, &smsg, 0);
	if (buflen < 0) {
		if (errno != EINTR)
			info(udev_monitor->udev, "unable to receive message\n");
		return NULL;
	}

	if (buflen < 32 || (size_t)buflen >= sizeof(buf)) {
		info(udev_monitor->udev, "invalid message length\n");
		return NULL;
	}

	if (udev_monitor->snl.nl_family != 0) {
		if (snl.nl_groups == 0) {
			info(udev_monitor->udev, "unicast netlink message ignored\n");
			return NULL;
		}
		if ((snl.nl_groups == UDEV_MONITOR_KERNEL) && (snl.nl_pid > 0)) {
			info(udev_monitor->udev, "multicast kernel netlink message from pid %d ignored\n", snl.nl_pid);
			return NULL;
		}
	}

	cmsg = CMSG_FIRSTHDR(&smsg);
	if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
		info(udev_monitor->udev, "no sender credentials received, message ignored\n");
		return NULL;
	}

	cred = (struct ucred *)CMSG_DATA(cmsg);
	if (cred->uid != 0) {
		info(udev_monitor->udev, "sender uid=%d, message ignored\n", cred->uid);
		return NULL;
	}

	if (strncmp(buf, "udev-", 5) == 0) {
		/* udev message needs proper version magic */
		nlh = (struct udev_monitor_netlink_header *) buf;
		if (nlh->magic != htonl(UDEV_MONITOR_MAGIC))
			return NULL;
		if (nlh->properties_off < sizeof(struct udev_monitor_netlink_header))
			return NULL;
		if (nlh->properties_off+32U > buflen)
			return NULL;
		bufpos = nlh->properties_off;
	} else {
		/* kernel message with header */
		bufpos = strlen(buf) + 1;
		if ((size_t)bufpos < sizeof("a@/d") || bufpos >= buflen) {
			info(udev_monitor->udev, "invalid message length\n");
			return NULL;
		}

		/* check message header */
		if (strstr(buf, "@/") == NULL) {
			info(udev_monitor->udev, "unrecognized message header\n");
			return NULL;
		}
	}

	udev_device = device_new(udev_monitor->udev);
	if (udev_device == NULL) {
		return NULL;
	}

	while (bufpos < buflen) {
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

	/* skip device, if it does not pass the current filter */
	if (!passes_filter(udev_monitor, udev_device)) {
		struct pollfd pfd[1];
		int rc;

		udev_device_unref(udev_device);

		/* if something is queued, get next device */
		pfd[0].fd = udev_monitor->sock;
		pfd[0].events = POLLIN;
		rc = poll(pfd, 1, 0);
		if (rc > 0)
			goto retry;
		return NULL;
	}

	if (maj > 0)
		udev_device_set_devnum(udev_device, makedev(maj, min));
	udev_device_set_info_loaded(udev_device);
	return udev_device;
}

int udev_monitor_send_device(struct udev_monitor *udev_monitor, struct udev_device *udev_device)
{
	struct msghdr smsg;
	struct iovec iov[2];
	const char *buf;
	ssize_t blen;
	ssize_t count;

	blen = udev_device_get_properties_monitor_buf(udev_device, &buf);
	if (blen < 32)
		return -1;

	if (udev_monitor->sun.sun_family != 0) {
		const char *action;
		char header[2048];
		size_t hlen;

		/* header <action>@<devpath> */
		action = udev_device_get_action(udev_device);
		if (action == NULL)
			return -EINVAL;
		util_strlcpy(header, action, sizeof(header));
		util_strlcat(header, "@", sizeof(header));
		hlen = util_strlcat(header, udev_device_get_devpath(udev_device), sizeof(header))+1;
		if (hlen >= sizeof(header))
			return -EINVAL;
		iov[0].iov_base = header;
		iov[0].iov_len = hlen;

		/* add properties list */
		iov[1].iov_base = (char *)buf;
		iov[1].iov_len = blen;

		memset(&smsg, 0x00, sizeof(struct msghdr));
		smsg.msg_iov = iov;
		smsg.msg_iovlen = 2;
		smsg.msg_name = &udev_monitor->sun;
		smsg.msg_namelen = udev_monitor->addrlen;
	} else if (udev_monitor->snl.nl_family != 0) {
		const char *val;
		struct udev_monitor_netlink_header nlh;


		/* add versioned header */
		memset(&nlh, 0x00, sizeof(struct udev_monitor_netlink_header));
		util_strlcpy(nlh.version, "udev-" VERSION, sizeof(nlh.version));
		nlh.magic = htonl(UDEV_MONITOR_MAGIC);
		val = udev_device_get_subsystem(udev_device);
		nlh.filter_subsystem = htonl(util_string_hash32(val));
		val = udev_device_get_devtype(udev_device);
		if (val != NULL)
			nlh.filter_devtype = htonl(util_string_hash32(val));
		iov[0].iov_base = &nlh;
		iov[0].iov_len = sizeof(struct udev_monitor_netlink_header);

		/* add properties list */
		nlh.properties_off = iov[0].iov_len;
		nlh.properties_len = blen;
		iov[1].iov_base = (char *)buf;
		iov[1].iov_len = blen;

		memset(&smsg, 0x00, sizeof(struct msghdr));
		smsg.msg_iov = iov;
		smsg.msg_iovlen = 2;
		/* no destination besides the muticast group, we will always get ECONNREFUSED */
		smsg.msg_name = &udev_monitor->snl_peer;
		smsg.msg_namelen = sizeof(struct sockaddr_nl);
	} else {
		return -1;
	}

	count = sendmsg(udev_monitor->sock, &smsg, 0);
	info(udev_monitor->udev, "passed %zi bytes to monitor %p\n", count, udev_monitor);
	return count;
}

int udev_monitor_filter_add_match_subsystem_devtype(struct udev_monitor *udev_monitor, const char *subsystem, const char *devtype)
{
	if (udev_monitor == NULL)
		return -EINVAL;
	if (subsystem == NULL)
		return 0;
	if (udev_list_entry_add(udev_monitor->udev,
				&udev_monitor->filter_subsystem_list, subsystem, devtype, 0, 0) == NULL)
		return -ENOMEM;
	return 0;
}

int udev_monitor_filter_remove(struct udev_monitor *udev_monitor)
{
	static struct sock_fprog filter = { 0, NULL };

	udev_list_cleanup_entries(udev_monitor->udev, &udev_monitor->filter_subsystem_list);
	return setsockopt(udev_monitor->sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
}
