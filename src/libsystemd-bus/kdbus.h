/*
 * Copyright (C) 2013 Kay Sievers
 * Copyright (C) 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013 Linux Foundation
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
	__u64 flags;		/* 0 or (possibly?) KDBUS_CMD_NAME_IN_QUEUE */
	char name[0];
};

struct kdbus_manager_msg_id_change {
	__u64 id;
	__u64 flags; /* The kernel flags field from KDBUS_CMD_HELLO */
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

#define KDBUS_SRC_ID_KERNEL		(0)
#define KDBUS_DST_ID_WELL_KNOWN_NAME	(0)
#define KDBUS_MATCH_SRC_ID_ANY		(~0ULL)
#define KDBUS_DST_ID_BROADCAST		(~0ULL)

/* Message Data Types */
enum {
	/* Filled in by userspace */
	KDBUS_MSG_NULL,			/* empty record */
	KDBUS_MSG_PAYLOAD,		/* .data */
	KDBUS_MSG_PAYLOAD_VEC,		/* .data_vec, converted into _PAYLOAD at delivery */
	KDBUS_MSG_MMAP,			/* .data_vec */
	KDBUS_MSG_MMAP_DONATE,		/* .data_vec, unmap the memory from the sender */
	KDBUS_MSG_UNIX_FDS,		/* .data_fds of file descriptors */
	KDBUS_MSG_BLOOM,		/* for broadcasts, carries bloom filter blob */
	KDBUS_MSG_DST_NAME,		/* destination's well-known name */

	/* Filled in by kernelspace */
	KDBUS_MSG_SRC_NAMES	= 0x200,/* NUL separated string list with well-known names of source */
	KDBUS_MSG_TIMESTAMP,		/* .ts_ns of CLOCK_MONOTONIC */
	KDBUS_MSG_SRC_CREDS,		/* .creds */
	KDBUS_MSG_SRC_COMM,		/* optional */
	KDBUS_MSG_SRC_THREAD_COMM,	/* optional */
	KDBUS_MSG_SRC_EXE,		/* optional */
	KDBUS_MSG_SRC_CMDLINE,		/* optional */
	KDBUS_MSG_SRC_CGROUP,		/* optional, specified which one */
	KDBUS_MSG_SRC_CAPS,		/* caps data blob */
	KDBUS_MSG_SRC_SECLABEL,		/* NUL terminated string */
	KDBUS_MSG_SRC_AUDIT,		/* array of two uint64_t of audit loginuid + sessiond */

	/* Special messages from kernel, consisting of one and only one of these data blocks */
	KDBUS_MSG_NAME_ADD	= 0x400,/* .name_change */
	KDBUS_MSG_NAME_REMOVE,		/* .name_change */
	KDBUS_MSG_NAME_CHANGE,		/* .name_change */
	KDBUS_MSG_ID_ADD,		/* .id_change */
	KDBUS_MSG_ID_REMOVE,		/* .id_change */
	KDBUS_MSG_ID_CHANGE,		/* .id_change */
	KDBUS_MSG_REPLY_TIMEOUT,	/* empty, but .reply_cookie in .kdbus_msg is filled in */
	KDBUS_MSG_REPLY_DEAD,		/* dito */
};

struct kdbus_vec {
	__u64 address;
	__u64 size;
};

/**
 * struct  kdbus_msg_data - chain of data blocks
 *
 * size: overall data record size
 * type: kdbus_msg_data_type of data
 */
struct kdbus_msg_data {
	__u64 size;
	__u64 type;
	union {
		/* inline data */
		__u8 data[0];
                char str[0];
		__u32 data_u32[0];
		__u64 data_u64[0];

		/* data vector */
		struct kdbus_vec vec;

		/* specific fields */
		int fds[0];				/* int array of file descriptors */
		__u64 ts_ns;				/* timestamp in nanoseconds */
		struct kdbus_creds creds;
		struct kdbus_manager_msg_name_change name_change;
		struct kdbus_manager_msg_id_change id_change;
	};
};

enum {
	KDBUS_MSG_FLAGS_EXPECT_REPLY	= 1,
	KDBUS_MSG_FLAGS_NO_AUTO_START	= 2, /* possibly? */
};

enum {
	KDBUS_PAYLOAD_NONE	= 0,
	KDBUS_PAYLOAD_DBUS1	= 0x4442757356657231ULL, /* 'DBusVer1' */
	KDBUS_PAYLOAD_GVARIANT	= 0x4756617269616e74ULL, /* 'GVariant' */
};

/**
 * struct kdbus_msg
 *
 * set by userspace:
 * dst_id: destination id
 * flags: KDBUS_MSG_FLAGS_*
 * data_size: overall message size
 * data: data records
 *
 * set by kernel:
 * src_id: who sent the message
 */
struct kdbus_msg {
	__u64 size;
	__u64 flags;
	__u64 dst_id;		/* connection, 0 == name in data, ~0 broadcast */
	__u64 src_id;		/* connection, 0 == kernel */
	__u64 payload_type;	/* 'DBusVer1', 'GVariant', ... */
	__u64 cookie;		/* userspace-supplied cookie */
	union {
		__u64 cookie_reply;	/* cookie we reply to */
		__u64 timeout_ns;	/* timespan to wait for reply */
	};
	struct kdbus_msg_data data[0];
};

enum {
	KDBUS_POLICY_NAME,
	KDBUS_POLICY_ACCESS,
};

enum {
	KDBUS_POLICY_USER,
	KDBUS_POLICY_GROUP,
	KDBUS_POLICY_WORLD,
};

enum {
	KDBUS_POLICY_RECV	= 4,
	KDBUS_POLICY_SEND	= 2,
	KDBUS_POLICY_OWN	= 1,
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
	__u8 buffer[0];	/* a series of KDBUS_POLICY_NAME plus one or more KDBUS_POLICY_ACCESS each. */
};

enum {
	KDBUS_CMD_HELLO_STARTER		=  1,
	KDBUS_CMD_HELLO_ACCEPT_FD	=  2,
	KDBUS_CMD_HELLO_ACCEPT_MMAP	=  4,
};

enum {
	KDBUS_CMD_FNAME_ACCESS_GROUP	=  1,
	KDBUS_CMD_FNAME_ACCESS_WORLD	=  2,
	KDBUS_CMD_FNAME_POLICY_OPEN	=  4,
};

struct kdbus_cmd_hello {
	/* userspace → kernel, kernel → userspace */
	__u64 kernel_flags;	/* userspace specifies its
				 * capabilities and more, kernel
				 * returns its capabilites and
				 * more. Kernel might refuse client's
				 * capabilities by returning an error
				 * from KDBUS_CMD_HELLO */

	/* userspace → kernel */
	__u64 pid;		/* To allow translator services which
				 * connect to the bus on behalf of
				 * somebody else, allow specifiying
				 * the PID of the client to connect on
				 * behalf on. Normal clients should
				 * pass this as 0 (i.e. to do things
				 * under their own PID). Priviliged
				 * clients can pass != 0, to operate
				 * on behalf of somebody else. */

	/* kernel → userspace */
	__u64 bus_flags;	/* this is .flags copied verbatim from
				 * from original KDBUS_CMD_BUS_MAKE
				 * ioctl. It's intended to be useful
				 * to do negotiation of features of
				 * the payload that is transfreted. */
	__u64 id;		/* peer id */
};

struct kdbus_cmd_fname {
	__u64 size;
	__u64 kernel_flags;	/* userspace → kernel, kernel → userspace
				 * When creating a bus/ns/ep feature
				 * kernel negotiation done the same
				 * way as for KDBUS_CMD_BUS_MAKE. */
	__u64 user_flags;	/* userspace → kernel
				 * When a bus is created this value is
				 * copied verbatim into the bus
				 * structure and returned from
				 * KDBUS_CMD_HELLO, later */
	char name[0];
};

enum {
	/* userspace → kernel */
	KDBUS_CMD_NAME_REPLACE_EXISTING		=  1,
	KDBUS_CMD_NAME_QUEUE			=  2,
	KDBUS_CMD_NAME_ALLOW_REPLACEMENT	=  4,
	KDBUS_CMD_NAME_STEAL_MESSAGES		=  8,

	/* kernel → userspace */
	KDBUS_CMD_NAME_IN_QUEUE = 0x200,
};

struct kdbus_cmd_name {
	__u64 size;
	__u64 flags;
	__u64 id;		/* We allow registration/deregestration of names of other peers */
	char name[0];
};

struct kdbus_cmd_names {
	__u64 size;
	struct kdbus_cmd_name names[0];
};

enum {
	KDBUS_CMD_NAME_INFO_ITEM_NAME,
	KDBUS_CMD_NAME_INFO_ITEM_SECLABEL,
	KDBUS_CMD_NAME_INFO_ITEM_AUDIT,
};

struct kdbus_cmd_name_info_item {
	__u64 size;
	__u64 type;
	__u8 data[0];
};

struct kdbus_cmd_name_info {
	__u64 size;			/* overall size of info */
	__u64 flags;
	__u64 id;			/* either ID, or 0 and _ITEM_NAME follows */
	struct kdbus_creds creds;
	struct kdbus_cmd_name_info_item item[0]; /* list of item records */
};

enum {
	KDBUS_CMD_MATCH_BLOOM,		/* Matches a mask blob against KDBUS_MSG_BLOOM */
	KDBUS_CMD_MATCH_SRC_NAME,	/* Matches a name string against KDBUS_MSG_SRC_NAMES */
	KDBUS_CMD_MATCH_NAME_ADD,	/* Matches a name string against KDBUS_MSG_NAME_ADD */
	KDBUS_CMD_MATCH_NAME_REMOVE,	/* Matches a name string against KDBUS_MSG_NAME_REMOVE */
	KDBUS_CMD_MATCH_NAME_CHANGE,	/* Matches a name string against KDBUS_MSG_NAME_CHANGE */
	KDBUS_CMD_MATCH_ID_ADD,		/* Matches an ID against KDBUS_MSG_ID_ADD */
	KDBUS_CMD_MATCH_ID_REMOVE,	/* Matches an ID against KDBUS_MSG_ID_REMOVE */
	KDBUS_CMD_MATCH_ID_CHANGE,	/* Matches an ID against KDBUS_MSG_ID_CHANGE */
};

struct kdbus_cmd_match_item {
	__u64 size;
	__u64 type;
	__u8 data[0];
};

struct kdbus_cmd_match {
	__u64 size;
	__u64 id;	/* We allow registration/deregestration of matches for other peers */
	__u64 cookie;	/* userspace supplied cookie; when removing; kernel deletes everything with same cookie */
	__u64 src_id;	/* ~0: any. other: exact unique match */
	struct kdbus_cmd_match_item items[0];
};

struct kdbus_cmd_monitor {
	__u64 id;		/* We allow setting the monitor flag of other peers */
	int enabled;		/* A boolean to enable/disable monitoring */
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
	KDBUS_CMD_BUS_MAKE =		_IOWR(KDBUS_IOC_MAGIC, 0x00, struct kdbus_cmd_fname),
	KDBUS_CMD_NS_MAKE =		_IOWR(KDBUS_IOC_MAGIC, 0x10, struct kdbus_cmd_fname),

	/* kdbus control node commands: require bus owner state */
	KDBUS_CMD_BUS_POLICY_SET =	_IOWR(KDBUS_IOC_MAGIC, 0x20, struct kdbus_cmd_policy),

	/* kdbus ep node commands: require unset state */
	KDBUS_CMD_EP_MAKE =		_IOWR(KDBUS_IOC_MAGIC, 0x30, struct kdbus_cmd_fname),
	KDBUS_CMD_HELLO =		_IOWR(KDBUS_IOC_MAGIC, 0x31, struct kdbus_cmd_hello),

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

/* Think about:
 *
 * - allow HELLO to change unique names
 * - allow HELLO without assigning a unique name at all
 * - when receive fails due to too small buffer return real size
 * - when receiving maybe allow read-only mmaping into reciving process memory space or so?
 */
