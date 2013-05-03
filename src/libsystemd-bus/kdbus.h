/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
 * Copyright (C) 2013 Lennart Poettering
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef _KDBUS_H_
#define _KDBUS_H_

#ifndef __KERNEL__
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/types.h>
#endif

#define KDBUS_IOC_MAGIC			0x95

/* Message sent from kernel to userspace, when the owner or starter of
 * a well-known name changes */
struct kdbus_manager_msg_name_change {
	__u64 old_id;
	__u64 new_id;
	__u64 flags;			/* 0 or (possibly?) KDBUS_NAME_IN_QUEUE */
	char name[0];
};

struct kdbus_manager_msg_id_change {
	__u64 id;
	__u64 flags;			/* The kernel flags field from KDBUS_HELLO */
};

struct kdbus_creds {
	__u64 uid;
	__u64 gid;
	__u64 pid;
	__u64 tid;

	/* The starttime of the process PID. This is useful to detect
	PID overruns from the client side. i.e. if you use the PID to
	look something up in /proc/$PID/ you can afterwards check the
	starttime field of it to ensure you didn't run into a PID
	ovretun. */
	__u64 starttime;
};

struct kdbus_audit {
	__u64 sessionid;
	__u64 loginuid;
};

struct kdbus_timestamp {
	__u64 monotonic_ns;
	__u64 realtime_ns;
};

#define KDBUS_SRC_ID_KERNEL		(0)
#define KDBUS_DST_ID_WELL_KNOWN_NAME	(0)
#define KDBUS_MATCH_SRC_ID_ANY		(~0ULL)
#define KDBUS_DST_ID_BROADCAST		(~0ULL)

/* Message Item Types */
enum {
	KDBUS_MSG_NULL,

	/* Filled in by userspace */
	KDBUS_MSG_PAYLOAD,		/* .data, inline memory */
	KDBUS_MSG_PAYLOAD_VEC,		/* .data_vec, reference to memory area */
	KDBUS_MSG_UNIX_FDS,		/* .data_fds of file descriptors */
	KDBUS_MSG_BLOOM,		/* for broadcasts, carries bloom filter blob in .data */
	KDBUS_MSG_DST_NAME,		/* destination's well-known name, in .str */

	/* Filled in by kernelspace */
	KDBUS_MSG_SRC_NAMES	= 0x200,/* NUL separated string list with well-known names of source */
	KDBUS_MSG_TIMESTAMP,		/* .timestamp */
	KDBUS_MSG_SRC_CREDS,		/* .creds */
	KDBUS_MSG_SRC_PID_COMM,		/* optional, in .str */
	KDBUS_MSG_SRC_TID_COMM,		/* optional, in .str */
	KDBUS_MSG_SRC_EXE,		/* optional, in .str */
	KDBUS_MSG_SRC_CMDLINE,		/* optional, in .str (a chain of NUL str) */
	KDBUS_MSG_SRC_CGROUP,		/* optional, in .str */
	KDBUS_MSG_SRC_CAPS,		/* caps data blob, in .data */
	KDBUS_MSG_SRC_SECLABEL,		/* NUL terminated string, in .str */
	KDBUS_MSG_SRC_AUDIT,		/* .audit */

	/* Special messages from kernel, consisting of one and only one of these data blocks */
	KDBUS_MSG_NAME_ADD	= 0x400,/* .name_change */
	KDBUS_MSG_NAME_REMOVE,		/* .name_change */
	KDBUS_MSG_NAME_CHANGE,		/* .name_change */
	KDBUS_MSG_ID_ADD,		/* .id_change */
	KDBUS_MSG_ID_REMOVE,		/* .id_change */
	KDBUS_MSG_REPLY_TIMEOUT,	/* empty, but .reply_cookie in .kdbus_msg is filled in */
	KDBUS_MSG_REPLY_DEAD,		/* dito */
};

enum {
	KDBUS_VEC_ALIGNED		= 1 <<  0,
};

struct kdbus_vec {
	__u64 address;
	__u64 size;
	__u64 flags;
};

/**
 * struct  kdbus_item - chain of data blocks
 *
 * size: overall data record size
 * type: kdbus_item type of data
 */
struct kdbus_item {
	__u64 size;
	__u64 type;
	union {
		/* inline data */
		__u8 data[0];
		__u32 data32[0];
		__u64 data64[0];
		char str[0];

		/* connection */
		__u64 id;

		/* data vector */
		struct kdbus_vec vec;

		/* process credentials and properties*/
		struct kdbus_creds creds;
		struct kdbus_audit audit;
		struct kdbus_timestamp timestamp;

		/* specific fields */
		int fds[0];
		struct kdbus_manager_msg_name_change name_change;
		struct kdbus_manager_msg_id_change id_change;
	};
};

enum {
	KDBUS_MSG_FLAGS_EXPECT_REPLY	= 1 << 0,
	KDBUS_MSG_FLAGS_NO_AUTO_START	= 1 << 1,
};

enum {
	KDBUS_PAYLOAD_NULL,
	KDBUS_PAYLOAD_DBUS1	= 0x4442757356657231ULL, /* 'DBusVer1' */
	KDBUS_PAYLOAD_GVARIANT	= 0x4756617269616e74ULL, /* 'GVariant' */
};

/**
 * struct kdbus_msg
 *
 * set by userspace:
 * dst_id: destination id
 * flags: KDBUS_MSG_FLAGS_*
 * items: data records
 *
 * set by kernel:
 * src_id: who sent the message
 */
struct kdbus_msg {
	__u64 size;
	__u64 flags;
	__u64 dst_id;			/* connection, 0 == name in data, ~0 broadcast */
	__u64 src_id;			/* connection, 0 == kernel */
	__u64 payload_type;		/* 'DBusVer1', 'GVariant', ... */
	__u64 cookie;			/* userspace-supplied cookie */
	union {
		__u64 cookie_reply;	/* cookie we reply to */
		__u64 timeout_ns;	/* timespan to wait for reply */
	};
	struct kdbus_item items[0];
};

enum {
	KDBUS_POLICY_NULL,
	KDBUS_POLICY_NAME,
	KDBUS_POLICY_ACCESS,
};

enum {
	KDBUS_POLICY_ACCESS_NULL,
	KDBUS_POLICY_ACCESS_USER,
	KDBUS_POLICY_ACCESS_GROUP,
	KDBUS_POLICY_ACCESS_WORLD,
};

enum {
	KDBUS_POLICY_RECV		= 1 <<  2,
	KDBUS_POLICY_SEND		= 1 <<  1,
	KDBUS_POLICY_OWN		= 1 <<  0,
};

struct kdbus_policy {
	__u64 size;
	__u64 type; /* NAME or ACCESS */
	union {
		char name[0];
		struct {
			__u32 type;	/* USER, GROUP, WORLD */
			__u32 bits;	/* RECV, SEND, OWN */
			__u64 id;	/* uid, gid, 0 */
		} access;
	};
};

struct kdbus_cmd_policy {
	__u64 size;
	__u8 buffer[0];		/* a series of KDBUS_POLICY_NAME plus one or
				 * more KDBUS_POLICY_ACCESS each. */
};

/* Flags for struct kdbus_cmd_hello */
enum {
	KDBUS_HELLO_STARTER		=  1 <<  0,
	KDBUS_HELLO_ACCEPT_FD		=  1 <<  1,

	/* The following have an effect on directed messages only --
	 * not for broadcasts */
	KDBUS_HELLO_ATTACH_COMM		=  1 << 10,
	KDBUS_HELLO_ATTACH_EXE		=  1 << 11,
	KDBUS_HELLO_ATTACH_CMDLINE	=  1 << 12,
	KDBUS_HELLO_ATTACH_CGROUP	=  1 << 13,
	KDBUS_HELLO_ATTACH_CAPS		=  1 << 14,
	KDBUS_HELLO_ATTACH_SECLABEL	=  1 << 15,
	KDBUS_HELLO_ATTACH_AUDIT	=  1 << 16,
};

/* Items to append to struct kdbus_cmd_hello */
enum {
	KDBUS_HELLO_NULL,
};

struct kdbus_cmd_hello {
	__u64 size;

	/* userspace → kernel, kernel → userspace */
	__u64 conn_flags;	/* userspace specifies its
				 * capabilities and more, kernel
				 * returns its capabilites and
				 * more. Kernel might refuse client's
				 * capabilities by returning an error
				 * from KDBUS_HELLO */

	/* kernel → userspace */
	__u64 bus_flags;	/* this is .flags copied verbatim from
				 * from original KDBUS_CMD_BUS_MAKE
				 * ioctl. It's intended to be useful
				 * to do negotiation of features of
				 * the payload that is transfreted. */
	__u64 id;		/* id assigned to this connection */
	__u64 bloom_size;	/* The bloom filter size chosen by the
				 * bus owner */
	struct kdbus_item items[0];
};

/* Flags for kdbus_cmd_{bus,ep,ns}_make */
enum {
	KDBUS_MAKE_ACCESS_GROUP		= 1 <<  0,
	KDBUS_MAKE_ACCESS_WORLD		= 1 <<  1,
	KDBUS_MAKE_POLICY_OPEN		= 1 <<  2,
};

/* Items to append to kdbus_cmd_{bus,ep,ns}_make */
enum {
	KDBUS_MAKE_NULL,
	KDBUS_MAKE_NAME,
	KDBUS_MAKE_CGROUP,	/* the cgroup hierarchy ID for which to attach
				 * cgroup membership paths * to messages. */
	KDBUS_MAKE_CRED,	/* allow translator services which connect
				 * to the bus on behalf of somebody else,
				 * allow specifying the credentials of the
				 * client to connect on behalf on. Needs
				 * privileges */
};

struct kdbus_cmd_bus_make {
	__u64 size;
	__u64 flags;		/* userspace → kernel, kernel → userspace
				 * When creating a bus feature
				 * kernel negotiation. */
	__u64 bus_flags;	/* userspace → kernel
				 * When a bus is created this value is
				 * copied verbatim into the bus
				 * structure and returned from
				 * KDBUS_CMD_HELLO, later */
	__u64 bloom_size;	/* size of the bloom filter for this bus */
	struct kdbus_item items[0];

};

struct kdbus_cmd_ep_make {
	__u64 size;
	__u64 flags;		/* userspace → kernel, kernel → userspace
				 * When creating an entry point
				 * feature kernel negotiation done the
				 * same way as for
				 * KDBUS_CMD_BUS_MAKE. Unused for
				 * now. */
	struct kdbus_item items[0];
};

struct kdbus_cmd_ns_make {
	__u64 size;
	__u64 flags;		/* userspace → kernel, kernel → userspace
				 * When creating an entry point
				 * feature kernel negotiation done the
				 * same way as for
				 * KDBUS_CMD_BUS_MAKE. Unused for
				 * now. */
	struct kdbus_item items[0];
};

enum {
	/* userspace → kernel */
	KDBUS_NAME_REPLACE_EXISTING		= 1 <<  0,
	KDBUS_NAME_QUEUE			= 1 <<  1,
	KDBUS_NAME_ALLOW_REPLACEMENT		= 1 <<  2,

	/* kernel → userspace */
	KDBUS_NAME_IN_QUEUE			= 1 << 16,
};

struct kdbus_cmd_name {
	__u64 size;
	__u64 name_flags;
	__u64 id;		/* We allow registration/deregestration of names of other peers */
	__u64 conn_flags;
	char name[0];
};

struct kdbus_cmd_names {
	__u64 size;
	struct kdbus_cmd_name names[0];
};

enum {
	KDBUS_NAME_INFO_ITEM_NULL,
	KDBUS_NAME_INFO_ITEM_NAME,	/* userspace → kernel */
	KDBUS_NAME_INFO_ITEM_SECLABEL,	/* kernel → userspace */
	KDBUS_NAME_INFO_ITEM_AUDIT,	/* kernel → userspace */
};

struct kdbus_cmd_name_info {
	__u64 size;			/* overall size of info */
	__u64 flags;
	__u64 id;			/* either ID, or 0 and _ITEM_NAME follows */
	struct kdbus_creds creds;
	struct kdbus_item items[0];	/* list of item records */
};

enum {
	KDBUS_MATCH_NULL,
	KDBUS_MATCH_BLOOM,		/* Matches a mask blob against KDBUS_MSG_BLOOM */
	KDBUS_MATCH_SRC_NAME,		/* Matches a name string against KDBUS_MSG_SRC_NAMES */
	KDBUS_MATCH_NAME_ADD,		/* Matches a name string against KDBUS_MSG_NAME_ADD */
	KDBUS_MATCH_NAME_REMOVE,	/* Matches a name string against KDBUS_MSG_NAME_REMOVE */
	KDBUS_MATCH_NAME_CHANGE,	/* Matches a name string against KDBUS_MSG_NAME_CHANGE */
	KDBUS_MATCH_ID_ADD,		/* Matches an ID against KDBUS_MSG_ID_ADD */
	KDBUS_MATCH_ID_REMOVE,		/* Matches an ID against KDBUS_MSG_ID_REMOVE */
};

struct kdbus_cmd_match {
	__u64 size;
	__u64 id;	/* We allow registration/deregestration of matches for other peers */
	__u64 cookie;	/* userspace supplied cookie; when removing; kernel deletes everything with same cookie */
	__u64 src_id;	/* ~0: any. other: exact unique match */
	struct kdbus_item items[0];
};

struct kdbus_cmd_monitor {
	__u64 id;		/* We allow setting the monitor flag of other peers */
	unsigned int enabled;	/* A boolean to enable/disable monitoring */
};

/* FD states:
 * control nodes: unset
 *   bus owner  (via KDBUS_CMD_BUS_MAKE)
 *   ns owner   (via KDBUS_CMD_NS_MAKE)
 *
 * ep nodes: unset
 *   connected  (via KDBUS_CMD_HELLO)
 *   starter    (via KDBUS_CMD_HELLO with KDBUS_CMD_HELLO_STARTER)
 *   ep owner   (via KDBUS_CMD_EP_MAKE)
 */
enum kdbus_cmd {
	/* kdbus control node commands: require unset state */
	KDBUS_CMD_BUS_MAKE =		_IOWR(KDBUS_IOC_MAGIC, 0x00, struct kdbus_cmd_bus_make),
	KDBUS_CMD_NS_MAKE =		_IOWR(KDBUS_IOC_MAGIC, 0x10, struct kdbus_cmd_ns_make),

	/* kdbus ep node commands: require unset state */
	KDBUS_CMD_EP_MAKE =		_IOWR(KDBUS_IOC_MAGIC, 0x20, struct kdbus_cmd_ep_make),
	KDBUS_CMD_HELLO =		_IOWR(KDBUS_IOC_MAGIC, 0x30, struct kdbus_cmd_hello),

	/* kdbus ep node commands: require connected state */
	KDBUS_CMD_MSG_SEND =		_IOWR(KDBUS_IOC_MAGIC, 0x40, struct kdbus_msg),
	KDBUS_CMD_MSG_RECV =		_IOWR(KDBUS_IOC_MAGIC, 0x41, struct kdbus_msg),

	KDBUS_CMD_NAME_ACQUIRE =	_IOWR(KDBUS_IOC_MAGIC, 0x50, struct kdbus_cmd_name),
	KDBUS_CMD_NAME_RELEASE =	_IOWR(KDBUS_IOC_MAGIC, 0x51, struct kdbus_cmd_name),
	KDBUS_CMD_NAME_LIST =		_IOWR(KDBUS_IOC_MAGIC, 0x52, struct kdbus_cmd_names),
	KDBUS_CMD_NAME_QUERY =		_IOWR(KDBUS_IOC_MAGIC, 0x53, struct kdbus_cmd_name_info),

	KDBUS_CMD_MATCH_ADD =		_IOWR(KDBUS_IOC_MAGIC, 0x60, struct kdbus_cmd_match),
	KDBUS_CMD_MATCH_REMOVE =	_IOWR(KDBUS_IOC_MAGIC, 0x61, struct kdbus_cmd_match),
	KDBUS_CMD_MONITOR =		_IOWR(KDBUS_IOC_MAGIC, 0x62, struct kdbus_cmd_monitor),

	/* kdbus ep node commands: require ep owner state */
	KDBUS_CMD_EP_POLICY_SET =	_IOWR(KDBUS_IOC_MAGIC, 0x70, struct kdbus_cmd_policy),
};
#endif
