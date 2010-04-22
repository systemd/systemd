/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008-2010 Kay Sievers <kay.sievers@vrfy.org>
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

/**
 * SECTION:libudev-monitor
 * @short_description: device event source
 *
 * Connects to a device event source.
 */

/**
 * udev_monitor:
 *
 * Opaque object handling one event source.
 */
struct udev_monitor {
	struct udev *udev;
	int refcount;
	int sock;
	struct sockaddr_nl snl;
	struct sockaddr_nl snl_trusted_sender;
	struct sockaddr_nl snl_destination;
	struct sockaddr_un sun;
	socklen_t addrlen;
	struct udev_list_node filter_subsystem_list;
	struct udev_list_node filter_tag_list;
};

enum udev_monitor_netlink_group {
	UDEV_MONITOR_NONE,
	UDEV_MONITOR_KERNEL,
	UDEV_MONITOR_UDEV,
};

#define UDEV_MONITOR_MAGIC		0xfeedcafe
struct udev_monitor_netlink_header {
	/* "libudev" prefix to distinguish libudev and kernel messages */
	char prefix[8];
	/*
	 * magic to protect against daemon <-> library message format mismatch
	 * used in the kernel from socket filter rules; needs to be stored in network order
	 */
	unsigned int magic;
	/* total length of header structure known to the sender */
	unsigned int header_size;
	/* properties string buffer */
	unsigned int properties_off;
	unsigned int properties_len;
	/*
	 * hashes of primary device properties strings, to let libudev subscribers
	 * use in-kernel socket filters; values need to be stored in network order
	 */
	unsigned int filter_subsystem_hash;
	unsigned int filter_devtype_hash;
	unsigned int filter_tag_bloom_hi;
	unsigned int filter_tag_bloom_lo;
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
	udev_list_init(&udev_monitor->filter_tag_list);
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
		util_strscpy(udev_monitor->sun.sun_path, sizeof(udev_monitor->sun.sun_path), socket_path);
		udev_monitor->sun.sun_path[0] = '\0';
		udev_monitor->addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(socket_path);
	} else if (stat(socket_path, &statbuf) == 0 && S_ISSOCK(statbuf.st_mode)) {
		/* existing socket file */
		util_strscpy(udev_monitor->sun.sun_path, sizeof(udev_monitor->sun.sun_path), socket_path);
		udev_monitor->addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(socket_path);
	} else {
		/* no socket file, assume abstract namespace socket */
		util_strscpy(&udev_monitor->sun.sun_path[1], sizeof(udev_monitor->sun.sun_path)-1, socket_path);
		udev_monitor->addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(socket_path)+1;
	}
	udev_monitor->sock = socket(AF_LOCAL, SOCK_DGRAM|SOCK_CLOEXEC, 0);
	if (udev_monitor->sock == -1) {
		err(udev, "error getting socket: %m\n");
		free(udev_monitor);
		return NULL;
	}

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
		group = UDEV_MONITOR_NONE;
	else if (strcmp(name, "udev") == 0)
		group = UDEV_MONITOR_UDEV;
	else if (strcmp(name, "kernel") == 0)
		group = UDEV_MONITOR_KERNEL;
	else
		return NULL;

	udev_monitor = udev_monitor_new(udev);
	if (udev_monitor == NULL)
		return NULL;

	udev_monitor->sock = socket(PF_NETLINK, SOCK_DGRAM|SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
	if (udev_monitor->sock == -1) {
		err(udev, "error getting socket: %m\n");
		free(udev_monitor);
		return NULL;
	}

	udev_monitor->snl.nl_family = AF_NETLINK;
	udev_monitor->snl.nl_groups = group;

	/* default destination for sending */
	udev_monitor->snl_destination.nl_family = AF_NETLINK;
	udev_monitor->snl_destination.nl_groups = UDEV_MONITOR_UDEV;

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

/**
 * udev_monitor_filter_update:
 * @udev_monitor: monitor
 *
 * Update the installed filter. This might only be needed, if the filter was removed or changed.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
int udev_monitor_filter_update(struct udev_monitor *udev_monitor)
{
	struct sock_filter ins[512];
	struct sock_fprog filter;
	unsigned int i;
	struct udev_list_entry *list_entry;
	int err;

	if (udev_list_get_entry(&udev_monitor->filter_subsystem_list) == NULL &&
	    udev_list_get_entry(&udev_monitor->filter_tag_list) == NULL)
		return 0;

	memset(ins, 0x00, sizeof(ins));
	i = 0;

	/* load magic in A */
	bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, magic));
	/* jump if magic matches */
	bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, UDEV_MONITOR_MAGIC, 1, 0);
	/* wrong magic, pass packet */
	bpf_stmt(ins, &i, BPF_RET|BPF_K, 0xffffffff);

	if (udev_list_get_entry(&udev_monitor->filter_tag_list) != NULL) {
		int tag_matches;

		/* count tag matches, to calculate end of tag match block */
		tag_matches = 0;
		udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_monitor->filter_tag_list))
			tag_matches++;

		/* add all tags matches */
		udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_monitor->filter_tag_list)) {
			uint64_t tag_bloom_bits = util_string_bloom64(udev_list_entry_get_name(list_entry));
			uint32_t tag_bloom_hi = tag_bloom_bits >> 32;
			uint32_t tag_bloom_lo = tag_bloom_bits & 0xffffffff;

			/* load device bloom bits in A */
			bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, filter_tag_bloom_hi));
			/* clear bits (tag bits & bloom bits) */
			bpf_stmt(ins, &i, BPF_ALU|BPF_AND|BPF_K, tag_bloom_hi);
			/* jump to next tag if it does not match */
			bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, tag_bloom_hi, 0, 3);

			/* load device bloom bits in A */
			bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, filter_tag_bloom_lo));
			/* clear bits (tag bits & bloom bits) */
			bpf_stmt(ins, &i, BPF_ALU|BPF_AND|BPF_K, tag_bloom_lo);
			/* jump behind end of tag match block if tag matches */
			tag_matches--;
			bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, tag_bloom_lo, 1 + (tag_matches * 6), 0);
		}

		/* nothing matched, drop packet */
		bpf_stmt(ins, &i, BPF_RET|BPF_K, 0);
	}

	/* add all subsystem matches */
	if (udev_list_get_entry(&udev_monitor->filter_subsystem_list) != NULL) {
		udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_monitor->filter_subsystem_list)) {
			unsigned int hash = util_string_hash32(udev_list_entry_get_name(list_entry));

			/* load device subsystem value in A */
			bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, filter_subsystem_hash));
			if (udev_list_entry_get_value(list_entry) == NULL) {
				/* jump if subsystem does not match */
				bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, hash, 0, 1);
			} else {
				/* jump if subsystem does not match */
				bpf_jmp(ins, &i, BPF_JMP|BPF_JEQ|BPF_K, hash, 0, 3);

				/* load device devtype value in A */
				bpf_stmt(ins, &i, BPF_LD|BPF_W|BPF_ABS, offsetof(struct udev_monitor_netlink_header, filter_devtype_hash));
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
	}

	/* matched, pass packet */
	bpf_stmt(ins, &i, BPF_RET|BPF_K, 0xffffffff);

	/* install filter */
	filter.len = i;
	filter.filter = ins;
	err = setsockopt(udev_monitor->sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
	return err;
}

int udev_monitor_allow_unicast_sender(struct udev_monitor *udev_monitor, struct udev_monitor *sender)
{
	udev_monitor->snl_trusted_sender.nl_pid = sender->snl.nl_pid;
	return 0;
}
/**
 * udev_monitor_enable_receiving:
 * @udev_monitor: the monitor which should receive events
 *
 * Binds the @udev_monitor socket to the event source.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
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
		if (err == 0) {
			struct sockaddr_nl snl;
			socklen_t addrlen;

			/*
			 * get the address the kernel has assigned us
			 * it is usually, but not necessarily the pid
			 */
			addrlen = sizeof(struct sockaddr_nl);
			err = getsockname(udev_monitor->sock, (struct sockaddr *)&snl, &addrlen);
			if (err == 0)
				udev_monitor->snl.nl_pid = snl.nl_pid;
		}
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

int udev_monitor_disconnect(struct udev_monitor *udev_monitor)
{
	int err;

	err = close(udev_monitor->sock);
	udev_monitor->sock = -1;
	return err;
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
	udev_list_cleanup_entries(udev_monitor->udev, &udev_monitor->filter_tag_list);
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
		goto tag;
	udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_monitor->filter_subsystem_list)) {
		const char *subsys = udev_list_entry_get_name(list_entry);
		const char *dsubsys = udev_device_get_subsystem(udev_device);
		const char *devtype;
		const char *ddevtype;

		if (strcmp(dsubsys, subsys) != 0)
			continue;

		devtype = udev_list_entry_get_value(list_entry);
		if (devtype == NULL)
			goto tag;
		ddevtype = udev_device_get_devtype(udev_device);
		if (ddevtype == NULL)
			continue;
		if (strcmp(ddevtype, devtype) == 0)
			goto tag;
	}
	return 0;

tag:
	if (udev_list_get_entry(&udev_monitor->filter_tag_list) == NULL)
		return 1;
	udev_list_entry_foreach(list_entry, udev_list_get_entry(&udev_monitor->filter_tag_list)) {
		const char *tag = udev_list_entry_get_name(list_entry);

		if (udev_device_has_tag(udev_device, tag))
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
			/* unicast message, check if we trust the sender */
			if (udev_monitor->snl_trusted_sender.nl_pid == 0 ||
			    snl.nl_pid != udev_monitor->snl_trusted_sender.nl_pid) {
				info(udev_monitor->udev, "unicast netlink message ignored\n");
				return NULL;
			}
		} else if (snl.nl_groups == UDEV_MONITOR_KERNEL) {
			if (snl.nl_pid > 0) {
				info(udev_monitor->udev, "multicast kernel netlink message from pid %d ignored\n",
				     snl.nl_pid);
				return NULL;
			}
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

	if (memcmp(buf, "libudev", 8) == 0) {
		/* udev message needs proper version magic */
		nlh = (struct udev_monitor_netlink_header *) buf;
		if (nlh->magic != htonl(UDEV_MONITOR_MAGIC))
			return NULL;
		if (nlh->properties_off+32 > buflen)
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

	udev_device = udev_device_new(udev_monitor->udev);
	if (udev_device == NULL)
		return NULL;
	udev_device_set_info_loaded(udev_device);

	while (bufpos < buflen) {
		char *key;
		size_t keylen;

		key = &buf[bufpos];
		keylen = strlen(key);
		if (keylen == 0)
			break;
		bufpos += keylen + 1;
		udev_device_add_property_from_string_parse(udev_device, key);
	}

	if (udev_device_add_property_from_string_parse_finish(udev_device) < 0) {
		info(udev_monitor->udev, "missing values, invalid device\n");
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

	return udev_device;
}

int udev_monitor_send_device(struct udev_monitor *udev_monitor,
			     struct udev_monitor *destination, struct udev_device *udev_device)
{
	const char *buf;
	ssize_t blen;
	ssize_t count;

	blen = udev_device_get_properties_monitor_buf(udev_device, &buf);
	if (blen < 32)
		return -EINVAL;

	if (udev_monitor->sun.sun_family != 0) {
		struct msghdr smsg;
		struct iovec iov[2];
		const char *action;
		char header[2048];
		char *s;

		/* header <action>@<devpath> */
		action = udev_device_get_action(udev_device);
		if (action == NULL)
			return -EINVAL;
		s = header;
		if (util_strpcpyl(&s, sizeof(header), action, "@", udev_device_get_devpath(udev_device), NULL) == 0)
			return -EINVAL;
		iov[0].iov_base = header;
		iov[0].iov_len = (s - header)+1;

		/* add properties list */
		iov[1].iov_base = (char *)buf;
		iov[1].iov_len = blen;

		memset(&smsg, 0x00, sizeof(struct msghdr));
		smsg.msg_iov = iov;
		smsg.msg_iovlen = 2;
		smsg.msg_name = &udev_monitor->sun;
		smsg.msg_namelen = udev_monitor->addrlen;
		count = sendmsg(udev_monitor->sock, &smsg, 0);
		info(udev_monitor->udev, "passed %zi bytes to socket monitor %p\n", count, udev_monitor);
		return count;
	}

	if (udev_monitor->snl.nl_family != 0) {
		struct msghdr smsg;
		struct iovec iov[2];
		const char *val;
		struct udev_monitor_netlink_header nlh;
		struct udev_list_entry *list_entry;
		uint64_t tag_bloom_bits;

		/* add versioned header */
		memset(&nlh, 0x00, sizeof(struct udev_monitor_netlink_header));
		memcpy(nlh.prefix, "libudev", 8);
		nlh.magic = htonl(UDEV_MONITOR_MAGIC);
		nlh.header_size = sizeof(struct udev_monitor_netlink_header);
		val = udev_device_get_subsystem(udev_device);
		nlh.filter_subsystem_hash = htonl(util_string_hash32(val));
		val = udev_device_get_devtype(udev_device);
		if (val != NULL)
			nlh.filter_devtype_hash = htonl(util_string_hash32(val));
		iov[0].iov_base = &nlh;
		iov[0].iov_len = sizeof(struct udev_monitor_netlink_header);

		/* add tag bloom filter */
		tag_bloom_bits = 0;
		udev_list_entry_foreach(list_entry, udev_device_get_tags_list_entry(udev_device))
			tag_bloom_bits |= util_string_bloom64(udev_list_entry_get_name(list_entry));
		if (tag_bloom_bits > 0) {
			nlh.filter_tag_bloom_hi = htonl(tag_bloom_bits >> 32);
			nlh.filter_tag_bloom_lo = htonl(tag_bloom_bits & 0xffffffff);
		}

		/* add properties list */
		nlh.properties_off = iov[0].iov_len;
		nlh.properties_len = blen;
		iov[1].iov_base = (char *)buf;
		iov[1].iov_len = blen;

		memset(&smsg, 0x00, sizeof(struct msghdr));
		smsg.msg_iov = iov;
		smsg.msg_iovlen = 2;
		/*
		 * Use custom address for target, or the default one.
		 *
		 * If we send to a multicast group, we will get
		 * ECONNREFUSED, which is expected.
		 */
		if (destination != NULL)
			smsg.msg_name = &destination->snl;
		else
			smsg.msg_name = &udev_monitor->snl_destination;
		smsg.msg_namelen = sizeof(struct sockaddr_nl);
		count = sendmsg(udev_monitor->sock, &smsg, 0);
		info(udev_monitor->udev, "passed %zi bytes to netlink monitor %p\n", count, udev_monitor);
		return count;
	}

	return -EINVAL;
}

/**
 * udev_monitor_filter_add_match_subsystem_devtype:
 * @udev_monitor: the monitor
 * @subsystem: the subsystem value to match the incoming devices against
 * @devtype: the devtype value to match the incoming devices against
 *
 * This filer is efficiently executed inside the kernel, and libudev subscribers
 * will usually not be woken up for devices which do not match.
 *
 * The filter must be installed before the monitor is switched to listening mode.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
int udev_monitor_filter_add_match_subsystem_devtype(struct udev_monitor *udev_monitor, const char *subsystem, const char *devtype)
{
	if (udev_monitor == NULL)
		return -EINVAL;
	if (subsystem == NULL)
		return -EINVAL;
	if (udev_list_entry_add(udev_monitor->udev,
				&udev_monitor->filter_subsystem_list, subsystem, devtype, 0, 0) == NULL)
		return -ENOMEM;
	return 0;
}

/**
 * udev_monitor_filter_add_match_tag:
 * @udev_monitor: the monitor
 * @tag: the name of a tag
 *
 * This filer is efficiently executed inside the kernel, and libudev subscribers
 * will usually not be woken up for devices which do not match.
 *
 * The filter must be installed before the monitor is switched to listening mode.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
int udev_monitor_filter_add_match_tag(struct udev_monitor *udev_monitor, const char *tag)
{
	if (udev_monitor == NULL)
		return -EINVAL;
	if (tag == NULL)
		return -EINVAL;
	if (udev_list_entry_add(udev_monitor->udev,
				&udev_monitor->filter_tag_list, tag, NULL, 0, 0) == NULL)
		return -ENOMEM;
	return 0;
}

/**
 * udev_monitor_filter_remove:
 * @udev_monitor: monitor
 *
 * Remove all filters from monitor.
 *
 * Returns: 0 on success, otherwise a negative error value.
 */
int udev_monitor_filter_remove(struct udev_monitor *udev_monitor)
{
	static struct sock_fprog filter = { 0, NULL };

	udev_list_cleanup_entries(udev_monitor->udev, &udev_monitor->filter_subsystem_list);
	return setsockopt(udev_monitor->sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
}
