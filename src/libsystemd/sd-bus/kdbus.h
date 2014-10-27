/*
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef _KDBUS_UAPI_H_
#define _KDBUS_UAPI_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#define KDBUS_IOCTL_MAGIC		0x95
#define KDBUS_SRC_ID_KERNEL		(0)
#define KDBUS_DST_ID_NAME		(0)
#define KDBUS_MATCH_ID_ANY		(~0ULL)
#define KDBUS_DST_ID_BROADCAST		(~0ULL)
#define KDBUS_FLAG_KERNEL		(1ULL << 63)

/**
 * struct kdbus_notify_id_change - name registry change message
 * @id:			New or former owner of the name
 * @flags:		flags field from KDBUS_HELLO_*
 *
 * Sent from kernel to userspace when the owner or activator of
 * a well-known name changes.
 *
 * Attached to:
 *   KDBUS_ITEM_ID_ADD
 *   KDBUS_ITEM_ID_REMOVE
 */
struct kdbus_notify_id_change {
	__u64 id;
	__u64 flags;
};

/**
 * struct kdbus_notify_name_change - name registry change message
 * @old_id:		ID and flags of former owner of a name
 * @new_id:		ID and flags of new owner of a name
 * @name:		Well-known name
 *
 * Sent from kernel to userspace when the owner or activator of
 * a well-known name changes.
 *
 * Attached to:
 *   KDBUS_ITEM_NAME_ADD
 *   KDBUS_ITEM_NAME_REMOVE
 *   KDBUS_ITEM_NAME_CHANGE
 */
struct kdbus_notify_name_change {
	struct kdbus_notify_id_change old_id;
	struct kdbus_notify_id_change new_id;
	char name[0];
};

/**
 * struct kdbus_creds - process credentials
 * @uid:		User ID
 * @gid:		Group ID
 * @pid:		Process ID
 * @tid:		Thread ID
 * @starttime:		Starttime of the process
 *
 * The starttime of the process PID. This is useful to detect PID overruns
 * from the client side. i.e. if you use the PID to look something up in
 * /proc/$PID/ you can afterwards check the starttime field of it, to ensure
 * you didn't run into a PID overrun.
 *
 * Attached to:
 *   KDBUS_ITEM_CREDS
 */
struct kdbus_creds {
	__u64 uid;
	__u64 gid;
	__u64 pid;
	__u64 tid;
	__u64 starttime;
};

/**
 * struct kdbus_caps - process capabilities
 * @last_cap:	Highest currently known capability bit
 * @caps:	Variable number of 32-bit capabilities flags
 *
 * Contains a variable number of 32-bit capabilities flags.
 *
 * Attached to:
 *   KDBUS_ITEM_CAPS
 */
struct kdbus_caps {
	__u32 last_cap;
	__u32 caps[0];
};

/**
 * struct kdbus_audit - audit information
 * @sessionid:		The audit session ID
 * @loginuid:		The audit login uid
 *
 * Attached to:
 *   KDBUS_ITEM_AUDIT
 */
struct kdbus_audit {
	__u64 sessionid;
	__u64 loginuid;
};

/**
 * struct kdbus_timestamp
 * @seqnum:		Global per-domain message sequence number
 * @monotonic_ns:	Monotonic timestamp, in nanoseconds
 * @realtime_ns:	Realtime timestamp, in nanoseconds
 *
 * Attached to:
 *   KDBUS_ITEM_TIMESTAMP
 */
struct kdbus_timestamp {
	__u64 seqnum;
	__u64 monotonic_ns;
	__u64 realtime_ns;
};

/**
 * struct kdbus_vec - I/O vector for kdbus payload items
 * @size:		The size of the vector
 * @address:		Memory address of data buffer
 * @offset:		Offset in the in-message payload memory,
 *			relative to the message head
 *
 * Attached to:
 *   KDBUS_ITEM_PAYLOAD_VEC, KDBUS_ITEM_PAYLOAD_OFF
 */
struct kdbus_vec {
	__u64 size;
	union {
		__u64 address;
		__u64 offset;
	};
};

/**
 * struct kdbus_bloom_parameter - bus-wide bloom parameters
 * @size:		Size of the bit field in bytes (m / 8)
 * @n_hash:		Number of hash functions used (k)
 */
struct kdbus_bloom_parameter {
	__u64 size;
	__u64 n_hash;
};

/**
 * struct kdbus_bloom_filter - bloom filter containing n elements
 * @generation:		Generation of the element set in the filter
 * @data:		Bit field, multiple of 8 bytes
 */
struct kdbus_bloom_filter {
	__u64 generation;
	__u64 data[0];
};

/**
 * struct kdbus_memfd - a kdbus memfd
 * @size:		The memfd's size
 * @fd:			The file descriptor number
 * @__pad:		Padding to ensure proper alignment and size
 *
 * Attached to:
 *   KDBUS_ITEM_PAYLOAD_MEMFD
 */
struct kdbus_memfd {
	__u64 size;
	int fd;
	__u32 __pad;
};

/**
 * struct kdbus_name - a registered well-known name with its flags
 * @flags:		Flags from KDBUS_NAME_*
 * @name:		Well-known name
 *
 * Attached to:
 *   KDBUS_ITEM_NAME
 */
struct kdbus_name {
	__u64 flags;
	char name[0];
};

/**
 * struct kdbus_policy_access - policy access item
 * @type:		One of KDBUS_POLICY_ACCESS_* types
 * @access:		Access to grant
 * @id:			For KDBUS_POLICY_ACCESS_USER, the uid
 *			For KDBUS_POLICY_ACCESS_GROUP, the gid
 */
struct kdbus_policy_access {
	__u64 type;	/* USER, GROUP, WORLD */
	__u64 access;	/* OWN, TALK, SEE */
	__u64 id;	/* uid, gid, 0 */
};

/**
 * enum kdbus_item_type - item types to chain data in a list
 * @_KDBUS_ITEM_NULL:		Uninitialized/invalid
 * @_KDBUS_ITEM_USER_BASE:	Start of user items
 * @KDBUS_ITEM_PAYLOAD_VEC:	Vector to data
 * @KDBUS_ITEM_PAYLOAD_OFF:	Data at returned offset to message head
 * @KDBUS_ITEM_PAYLOAD_MEMFD:	Data as sealed memfd
 * @KDBUS_ITEM_FDS:		Attached file descriptors
 * @KDBUS_ITEM_BLOOM_PARAMETER:	Bus-wide bloom parameters, used with
 *				KDBUS_CMD_BUS_MAKE, carries a
 *				struct kdbus_bloom_parameter
 * @KDBUS_ITEM_BLOOM_FILTER:	Bloom filter carried with a message, used to
 *				match against a bloom mask of a connection,
 *				carries a struct kdbus_bloom_filter
 * @KDBUS_ITEM_BLOOM_MASK:	Bloom mask used to match against a message's
 *				bloom filter
 * @KDBUS_ITEM_DST_NAME:	Destination's well-known name
 * @KDBUS_ITEM_MAKE_NAME:	Name of domain, bus, endpoint
 * @KDBUS_ITEM_ATTACH_FLAGS:	Attach-flags, used for updating which metadata
 *				a connection subscribes to
 * @_KDBUS_ITEM_ATTACH_BASE:	Start of metadata attach items
 * @KDBUS_ITEM_NAME:		Well-know name with flags
 * @KDBUS_ITEM_ID:		Connection ID
 * @KDBUS_ITEM_TIMESTAMP:	Timestamp
 * @KDBUS_ITEM_CREDS:		Process credential
 * @KDBUS_ITEM_AUXGROUPS:	Auxiliary process groups
 * @KDBUS_ITEM_PID_COMM:	Process ID "comm" identifier
 * @KDBUS_ITEM_TID_COMM:	Thread ID "comm" identifier
 * @KDBUS_ITEM_EXE:		The path of the executable
 * @KDBUS_ITEM_CMDLINE:		The process command line
 * @KDBUS_ITEM_CGROUP:		The croup membership
 * @KDBUS_ITEM_CAPS:		The process capabilities
 * @KDBUS_ITEM_SECLABEL:	The security label
 * @KDBUS_ITEM_AUDIT:		The audit IDs
 * @KDBUS_ITEM_CONN_NAME:	The connection's human-readable name (debugging)
 * @_KDBUS_ITEM_POLICY_BASE:	Start of policy items
 * @KDBUS_ITEM_POLICY_ACCESS:	Policy access block
 * @_KDBUS_ITEM_KERNEL_BASE:	Start of kernel-generated message items
 * @KDBUS_ITEM_NAME_ADD:	Notify in struct kdbus_notify_name_change
 * @KDBUS_ITEM_NAME_REMOVE:	Notify in struct kdbus_notify_name_change
 * @KDBUS_ITEM_NAME_CHANGE:	Notify in struct kdbus_notify_name_change
 * @KDBUS_ITEM_ID_ADD:		Notify in struct kdbus_notify_id_change
 * @KDBUS_ITEM_ID_REMOVE:	Notify in struct kdbus_notify_id_change
 * @KDBUS_ITEM_REPLY_TIMEOUT:	Timeout has been reached
 * @KDBUS_ITEM_REPLY_DEAD:	Destination died
 */
enum kdbus_item_type {
	_KDBUS_ITEM_NULL,
	_KDBUS_ITEM_USER_BASE,
	KDBUS_ITEM_PAYLOAD_VEC	= _KDBUS_ITEM_USER_BASE,
	KDBUS_ITEM_PAYLOAD_OFF,
	KDBUS_ITEM_PAYLOAD_MEMFD,
	KDBUS_ITEM_FDS,
	KDBUS_ITEM_BLOOM_PARAMETER,
	KDBUS_ITEM_BLOOM_FILTER,
	KDBUS_ITEM_BLOOM_MASK,
	KDBUS_ITEM_DST_NAME,
	KDBUS_ITEM_MAKE_NAME,
	KDBUS_ITEM_ATTACH_FLAGS,

	_KDBUS_ITEM_ATTACH_BASE	= 0x1000,
	KDBUS_ITEM_NAME		= _KDBUS_ITEM_ATTACH_BASE,
	KDBUS_ITEM_ID,
	KDBUS_ITEM_TIMESTAMP,
	KDBUS_ITEM_CREDS,
	KDBUS_ITEM_AUXGROUPS,
	KDBUS_ITEM_PID_COMM,
	KDBUS_ITEM_TID_COMM,
	KDBUS_ITEM_EXE,
	KDBUS_ITEM_CMDLINE,
	KDBUS_ITEM_CGROUP,
	KDBUS_ITEM_CAPS,
	KDBUS_ITEM_SECLABEL,
	KDBUS_ITEM_AUDIT,
	KDBUS_ITEM_CONN_NAME,

	_KDBUS_ITEM_POLICY_BASE	= 0x2000,
	KDBUS_ITEM_POLICY_ACCESS = _KDBUS_ITEM_POLICY_BASE,

	_KDBUS_ITEM_KERNEL_BASE	= 0x8000,
	KDBUS_ITEM_NAME_ADD	= _KDBUS_ITEM_KERNEL_BASE,
	KDBUS_ITEM_NAME_REMOVE,
	KDBUS_ITEM_NAME_CHANGE,
	KDBUS_ITEM_ID_ADD,
	KDBUS_ITEM_ID_REMOVE,
	KDBUS_ITEM_REPLY_TIMEOUT,
	KDBUS_ITEM_REPLY_DEAD,
};

/**
 * struct kdbus_item - chain of data blocks
 * @size:		Overall data record size
 * @type:		Kdbus_item type of data
 * @data:		Generic bytes
 * @data32:		Generic 32 bit array
 * @data64:		Generic 64 bit array
 * @str:		Generic string
 * @id:			Connection ID
 * @vec:		KDBUS_ITEM_PAYLOAD_VEC
 * @creds:		KDBUS_ITEM_CREDS
 * @audit:		KDBUS_ITEM_AUDIT
 * @timestamp:		KDBUS_ITEM_TIMESTAMP
 * @name:		KDBUS_ITEM_NAME
 * @bloom_parameter:	KDBUS_ITEM_BLOOM_PARAMETER
 * @bloom_filter:	KDBUS_ITEM_BLOOM_FILTER
 * @memfd:		KDBUS_ITEM_PAYLOAD_MEMFD
 * @name_change:	KDBUS_ITEM_NAME_ADD
 *			KDBUS_ITEM_NAME_REMOVE
 *			KDBUS_ITEM_NAME_CHANGE
 * @id_change:		KDBUS_ITEM_ID_ADD
 *			KDBUS_ITEM_ID_REMOVE
 * @policy:		KDBUS_ITEM_POLICY_ACCESS
 */
struct kdbus_item {
	__u64 size;
	__u64 type;
	union {
		__u8 data[0];
		__u32 data32[0];
		__u64 data64[0];
		char str[0];

		__u64 id;
		struct kdbus_vec vec;
		struct kdbus_creds creds;
		struct kdbus_audit audit;
		struct kdbus_caps caps;
		struct kdbus_timestamp timestamp;
		struct kdbus_name name;
		struct kdbus_bloom_parameter bloom_parameter;
		struct kdbus_bloom_filter bloom_filter;
		struct kdbus_memfd memfd;
		int fds[0];
		struct kdbus_notify_name_change name_change;
		struct kdbus_notify_id_change id_change;
		struct kdbus_policy_access policy_access;
	};
};

/**
 * enum kdbus_msg_flags - type of message
 * @KDBUS_MSG_FLAGS_EXPECT_REPLY:	Expect a reply message, used for
 *					method calls. The userspace-supplied
 *					cookie identifies the message and the
 *					respective reply carries the cookie
 *					in cookie_reply
 * @KDBUS_MSG_FLAGS_SYNC_REPLY:		Wait for destination connection to
 *					reply to this message. The
 *					KDBUS_CMD_MSG_SEND ioctl() will block
 *					until the reply is received, and
 *					offset_reply in struct kdbus_msg will
 *					yield the offset in the sender's pool
 *					where the reply can be found.
 *					This flag is only valid if
 *					@KDBUS_MSG_FLAGS_EXPECT_REPLY is set as
 *					well.
 * @KDBUS_MSG_FLAGS_NO_AUTO_START:	Do not start a service, if the addressed
 *					name is not currently active
 */
enum kdbus_msg_flags {
	KDBUS_MSG_FLAGS_EXPECT_REPLY	= 1ULL << 0,
	KDBUS_MSG_FLAGS_SYNC_REPLY	= 1ULL << 1,
	KDBUS_MSG_FLAGS_NO_AUTO_START	= 1ULL << 2,
};

/**
 * enum kdbus_payload_type - type of payload carried by message
 * @KDBUS_PAYLOAD_KERNEL:	Kernel-generated simple message
 * @KDBUS_PAYLOAD_DBUS:		D-Bus marshalling "DBusDBus"
 */
enum kdbus_payload_type {
	KDBUS_PAYLOAD_KERNEL,
	KDBUS_PAYLOAD_DBUS	= 0x4442757344427573ULL,
};

/**
 * struct kdbus_msg - the representation of a kdbus message
 * @size:		Total size of the message
 * @flags:		Message flags (KDBUS_MSG_FLAGS_*), userspace → kernel
 * @kernel_flags:	Supported message flags, kernel → userspace
 * @priority:		Message queue priority value
 * @dst_id:		64-bit ID of the destination connection
 * @src_id:		64-bit ID of the source connection
 * @payload_type:	Payload type (KDBUS_PAYLOAD_*)
 * @cookie:		Userspace-supplied cookie, for the connection
 *			to identify its messages
 * @timeout_ns:		The time to wait for a message reply from the peer.
 *			If there is no reply, a kernel-generated message
 *			with an attached KDBUS_ITEM_REPLY_TIMEOUT item
 *			is sent to @src_id. The timeout is expected in
 *			nanoseconds and as absolute CLOCK_MONOTONIC value.
 * @cookie_reply:	A reply to the requesting message with the same
 *			cookie. The requesting connection can match its
 *			request and the reply with this value
 * @offset_reply:	If KDBUS_MSG_FLAGS_EXPECT_REPLY, this field will
 *			contain the offset in the sender's pool where the
 *			reply is stored.
 * @items:		A list of kdbus_items containing the message payload
 */
struct kdbus_msg {
	__u64 size;
	__u64 flags;
	__u64 kernel_flags;
	__s64 priority;
	__u64 dst_id;
	__u64 src_id;
	__u64 payload_type;
	__u64 cookie;
	union {
		__u64 timeout_ns;
		__u64 cookie_reply;
		__u64 offset_reply;
	};
	struct kdbus_item items[0];
} __attribute__((aligned(8)));

/**
 * enum kdbus_recv_flags - flags for de-queuing messages
 * @KDBUS_RECV_PEEK:		Return the next queued message without
 *				actually de-queuing it, and without installing
 *				any file descriptors or other resources. It is
 *				usually used to determine the activating
 *				connection of a bus name.
 * @KDBUS_RECV_DROP:		Drop and free the next queued message and all
 *				its resources without actually receiving it.
 * @KDBUS_RECV_USE_PRIORITY:	Only de-queue messages with the specified or
 *				higher priority (lowest values); if not set,
 *				the priority value is ignored.
 */
enum kdbus_recv_flags {
	KDBUS_RECV_PEEK		= 1ULL <<  0,
	KDBUS_RECV_DROP		= 1ULL <<  1,
	KDBUS_RECV_USE_PRIORITY	= 1ULL <<  2,
};

/**
 * struct kdbus_cmd_recv - struct to de-queue a buffered message
 * @flags:		KDBUS_RECV_* flags, userspace → kernel
 * @kernel_flags:	Supported KDBUS_RECV_* flags, kernel → userspace
 * @priority:		Minimum priority of the messages to de-queue. Lowest
 *			values have the highest priority.
 * @offset:		Returned offset in the pool where the message is
 *			stored. The user must use KDBUS_CMD_FREE to free
 *			the allocated memory.
 *
 * This struct is used with the KDBUS_CMD_MSG_RECV ioctl.
 */
struct kdbus_cmd_recv {
	__u64 flags;
	__u64 kernel_flags;
	__s64 priority;
	__u64 offset;
} __attribute__((aligned(8)));

/**
 * struct kdbus_cmd_cancel - struct to cancel a synchronously pending message
 * @cookie		The cookie of the pending message
 * @flags		Flags for the free command. Currently unused.
 *
 * This struct is used with the KDBUS_CMD_CANCEL ioctl.
 */
struct kdbus_cmd_cancel {
	__u64 cookie;
	__u64 flags;
} __attribute__((aligned(8)));

/**
 * struct kdbus_cmd_free - struct to free a slice of memory in the pool
 * @offset:		The offset of the memory slice, as returned by other
 *			ioctls
 * @flags:		Flags for the free command, userspace → kernel
 * @kernel_flags:	Supported flags of the free command, userspace → kernel
 *
 * This struct is used with the KDBUS_CMD_FREE ioctl.
 */
struct kdbus_cmd_free {
	__u64 offset;
	__u64 flags;
	__u64 kernel_flags;
} __attribute__((aligned(8)));

/**
 * enum kdbus_policy_access_type - permissions of a policy record
 * @_KDBUS_POLICY_ACCESS_NULL:	Uninitialized/invalid
 * @KDBUS_POLICY_ACCESS_USER:	Grant access to a uid
 * @KDBUS_POLICY_ACCESS_GROUP:	Grant access to gid
 * @KDBUS_POLICY_ACCESS_WORLD:	World-accessible
 */
enum kdbus_policy_access_type {
	_KDBUS_POLICY_ACCESS_NULL,
	KDBUS_POLICY_ACCESS_USER,
	KDBUS_POLICY_ACCESS_GROUP,
	KDBUS_POLICY_ACCESS_WORLD,
};

/**
 * enum kdbus_policy_access_flags - mode flags
 * @KDBUS_POLICY_OWN:		Allow to own a well-known name
 *				Implies KDBUS_POLICY_TALK and KDBUS_POLICY_SEE
 * @KDBUS_POLICY_TALK:		Allow communication to a well-known name
 *				Implies KDBUS_POLICY_SEE
 * @KDBUS_POLICY_SEE:		Allow to see a well-known name
 */
enum kdbus_policy_type {
	KDBUS_POLICY_SEE	= 0,
	KDBUS_POLICY_TALK,
	KDBUS_POLICY_OWN,
};

/**
 * enum kdbus_hello_flags - flags for struct kdbus_cmd_hello
 * @KDBUS_HELLO_ACCEPT_FD:	The connection allows the reception of
 *				any passed file descriptors
 * @KDBUS_HELLO_ACTIVATOR:	Special-purpose connection which registers
 *				a well-know name for a process to be started
 *				when traffic arrives
 * @KDBUS_HELLO_POLICY_HOLDER:	Special-purpose connection which registers
 *				policy entries for a name. The provided name
 *				is not activated and not registered with the
 *				name database, it only allows unprivileged
 *				connections to aquire a name, talk or discover
 *				a service
 * @KDBUS_HELLO_MONITOR:	Special-purpose connection to monitor
 *				bus traffic
 */
enum kdbus_hello_flags {
	KDBUS_HELLO_ACCEPT_FD		=  1ULL <<  0,
	KDBUS_HELLO_ACTIVATOR		=  1ULL <<  1,
	KDBUS_HELLO_POLICY_HOLDER	=  1ULL <<  2,
	KDBUS_HELLO_MONITOR		=  1ULL <<  3,
};

/**
 * enum kdbus_attach_flags - flags for metadata attachments
 * @KDBUS_ATTACH_TIMESTAMP:	Timestamp
 * @KDBUS_ATTACH_CREDS:		Credentials
 * @KDBUS_ATTACH_AUXGROUPS:	Auxiliary groups
 * @KDBUS_ATTACH_NAMES:		Well-known names
 * @KDBUS_ATTACH_COMM_TID:	The "comm" process identifier of the TID
 * @KDBUS_ATTACH_COMM_PID:	The "comm" process identifier of the PID
 * @KDBUS_ATTACH_EXE:		The path of the executable
 * @KDBUS_ATTACH_CMDLINE:	The process command line
 * @KDBUS_ATTACH_CGROUP:	The croup membership
 * @KDBUS_ATTACH_CAPS:		The process capabilities
 * @KDBUS_ATTACH_SECLABEL:	The security label
 * @KDBUS_ATTACH_AUDIT:		The audit IDs
 * @KDBUS_ATTACH_CONN_NAME:	The human-readable connection name
 * @_KDBUS_ATTACH_ALL:		All of the above
 */
enum kdbus_attach_flags {
	KDBUS_ATTACH_TIMESTAMP		=  1ULL <<  0,
	KDBUS_ATTACH_CREDS		=  1ULL <<  1,
	KDBUS_ATTACH_AUXGROUPS		=  1ULL <<  2,
	KDBUS_ATTACH_NAMES		=  1ULL <<  3,
	KDBUS_ATTACH_TID_COMM		=  1ULL <<  4,
	KDBUS_ATTACH_PID_COMM		=  1ULL <<  5,
	KDBUS_ATTACH_EXE		=  1ULL <<  6,
	KDBUS_ATTACH_CMDLINE		=  1ULL <<  7,
	KDBUS_ATTACH_CGROUP		=  1ULL <<  8,
	KDBUS_ATTACH_CAPS		=  1ULL <<  9,
	KDBUS_ATTACH_SECLABEL		=  1ULL << 10,
	KDBUS_ATTACH_AUDIT		=  1ULL << 11,
	KDBUS_ATTACH_CONN_NAME		=  1ULL << 12,
	_KDBUS_ATTACH_ALL		=  (1ULL << 13) - 1,
};

/**
 * struct kdbus_cmd_hello - struct to say hello to kdbus
 * @size:		The total size of the structure
 * @flags:		Connection flags (KDBUS_HELLO_*), userspace → kernel
 * @kernel_flags:	Supported connection flags, kernel → userspace
 * @attach_flags:	Mask of metadata to attach to each message sent
 *			(KDBUS_ATTACH_*)
 * @bus_flags:		The flags field copied verbatim from the original
 *			KDBUS_CMD_BUS_MAKE ioctl. It's intended to be useful
 *			to do negotiation of features of the payload that is
 *			transferred (kernel → userspace)
 * @id:			The ID of this connection (kernel → userspace)
 * @pool_size:		Size of the connection's buffer where the received
 *			messages are placed
 * @bloom:		The bloom properties of the bus, specified
 *			by the bus creator (kernel → userspace)
 * @id128:		Unique 128-bit ID of the bus (kernel → userspace)
 * @items:		A list of items
 *
 * This struct is used with the KDBUS_CMD_HELLO ioctl.
 */
struct kdbus_cmd_hello {
	__u64 size;
	__u64 flags;
	__u64 kernel_flags;
	__u64 attach_flags;
	__u64 bus_flags;
	__u64 id;
	__u64 pool_size;
	struct kdbus_bloom_parameter bloom;
	__u8 id128[16];
	struct kdbus_item items[0];
} __attribute__((aligned(8)));

/**
 * enum kdbus_make_flags - Flags for KDBUS_CMD_{BUS,EP,NS}_MAKE
 * @KDBUS_MAKE_ACCESS_GROUP:	Make the device node group-accessible
 * @KDBUS_MAKE_ACCESS_WORLD:	Make the device node world-accessible
 */
enum kdbus_make_flags {
	KDBUS_MAKE_ACCESS_GROUP		= 1ULL <<  0,
	KDBUS_MAKE_ACCESS_WORLD		= 1ULL <<  1,
};

/**
 * struct kdbus_cmd_make - struct to make a bus, an endpoint or a domain
 * @size:		The total size of the struct
 * @flags:		Properties for the bus/ep/domain to create,
 *			userspace → kernel
 * @kernel_flags:	Supported flags for the used command, kernel → userspace
 * @items:		Items describing details
 *
 * This structure is used with the KDBUS_CMD_BUS_MAKE, KDBUS_CMD_ENDPOINT_MAKE
 * and KDBUS_CMD_DOMAIN_MAKE ioctls.
 */
struct kdbus_cmd_make {
	__u64 size;
	__u64 flags;
	__u64 kernel_flags;
	struct kdbus_item items[0];
} __attribute__((aligned(8)));

/**
 * enum kdbus_name_flags - properties of a well-known name
 * @KDBUS_NAME_REPLACE_EXISTING:	Try to replace name of other connections
 * @KDBUS_NAME_ALLOW_REPLACEMENT:	Allow the replacement of the name
 * @KDBUS_NAME_QUEUE:			Name should be queued if busy
 * @KDBUS_NAME_IN_QUEUE:		Name is queued
 * @KDBUS_NAME_ACTIVATOR:		Name is owned by a activator connection
 */
enum kdbus_name_flags {
	KDBUS_NAME_REPLACE_EXISTING	= 1ULL <<  0,
	KDBUS_NAME_ALLOW_REPLACEMENT	= 1ULL <<  1,
	KDBUS_NAME_QUEUE		= 1ULL <<  2,
	KDBUS_NAME_IN_QUEUE		= 1ULL <<  3,
	KDBUS_NAME_ACTIVATOR		= 1ULL <<  4,
};

/**
 * struct kdbus_cmd_name - struct to describe a well-known name
 * @size:		The total size of the struct
 * @flags:		Flags for a name entry (KDBUS_NAME_*),
 *			userspace → kernel, kernel → userspace
 * @kernel_flags:	Supported flags for a name entry, kernel → userspace
 * @items:		Item list, containing the well-known name as
 *			KDBUS_ITEM_NAME
 *
 * This structure is used with the KDBUS_CMD_NAME_ACQUIRE ioctl.
 */
struct kdbus_cmd_name {
	__u64 size;
	__u64 flags;
	__u64 kernel_flags;
	struct kdbus_item items[0];
} __attribute__((aligned(8)));

/**
 * struct kdbus_name_info - struct to describe a well-known name
 * @size:		The total size of the struct
 * @flags:		Flags for a name entry (KDBUS_NAME_*),
 * @conn_flags:		The flags of the owning connection (KDBUS_HELLO_*)
 * @owner_id:		The current owner of the name
 * @items:		Item list, containing the well-known name as
 *			KDBUS_ITEM_NAME
 *
 * This structure is used as return struct for the KDBUS_CMD_NAME_LIST ioctl.
 */
struct kdbus_name_info {
	__u64 size;
	__u64 flags;
	__u64 conn_flags;
	__u64 owner_id;
	struct kdbus_item items[0];
} __attribute__((aligned(8)));

/**
 * enum kdbus_name_list_flags - what to include into the returned list
 * @KDBUS_NAME_LIST_UNIQUE:	All active connections
 * @KDBUS_NAME_LIST_NAMES:	All known well-known names
 * @KDBUS_NAME_LIST_ACTIVATORS:	All activator connections
 * @KDBUS_NAME_LIST_QUEUED:	All queued-up names
 */
enum kdbus_name_list_flags {
	KDBUS_NAME_LIST_UNIQUE		= 1ULL <<  0,
	KDBUS_NAME_LIST_NAMES		= 1ULL <<  1,
	KDBUS_NAME_LIST_ACTIVATORS	= 1ULL <<  2,
	KDBUS_NAME_LIST_QUEUED		= 1ULL <<  3,
};

/**
 * struct kdbus_cmd_name_list - request a list of name entries
 * @flags:		Flags for the query (KDBUS_NAME_LIST_*),
 * 			userspace → kernel
 * @kernel_flags:	Supported flags for queries, kernel → userspace
 * @offset:		The returned offset in the caller's pool buffer.
 *			The user must use KDBUS_CMD_FREE to free the
 *			allocated memory.
 *
 * This structure is used with the KDBUS_CMD_NAME_LIST ioctl.
 */
struct kdbus_cmd_name_list {
	__u64 flags;
	__u64 kernel_flags;
	__u64 offset;
} __attribute__((aligned(8)));

/**
 * struct kdbus_name_list - information returned by KDBUS_CMD_NAME_LIST
 * @size:		The total size of the structure
 * @names:		A list of names
 *
 * Note that the user is responsible for freeing the allocated memory with
 * the KDBUS_CMD_FREE ioctl.
 */
struct kdbus_name_list {
	__u64 size;
	struct kdbus_name_info names[0];
};

/**
 * struct kdbus_cmd_info - struct used for KDBUS_CMD_CONN_INFO ioctl
 * @size:		The total size of the struct
 * @flags:		KDBUS_ATTACH_* flags, userspace → kernel
 * @kernel_flags:	Supported KDBUS_ATTACH_* flags, kernel → userspace
 * @id:			The 64-bit ID of the connection. If set to zero, passing
 *			@name is required. kdbus will look up the name to
 *			determine the ID in this case.
 * @offset:		Returned offset in the caller's pool buffer where the
 *			kdbus_info struct result is stored. The user must
 *			use KDBUS_CMD_FREE to free the allocated memory.
 * @items:		The optional item list, containing the
 *			well-known name to look up as a KDBUS_ITEM_NAME.
 *			Only needed in case @id is zero.
 *
 * On success, the KDBUS_CMD_CONN_INFO ioctl will return 0 and @offset will
 * tell the user the offset in the connection pool buffer at which to find the
 * result in a struct kdbus_info.
 */
struct kdbus_cmd_info {
	__u64 size;
	__u64 flags;
	__u64 kernel_flags;
	__u64 id;
	__u64 offset;
	struct kdbus_item items[0];
} __attribute__((aligned(8)));

/**
 * struct kdbus_info - information returned by KDBUS_CMD_*_INFO
 * @size:		The total size of the struct
 * @id:			The connection's or bus' 64-bit ID
 * @flags:		The connection's or bus' flags
 * @items:		A list of struct kdbus_item
 *
 * Note that the user is responsible for freeing the allocated memory with
 * the KDBUS_CMD_FREE ioctl.
 */
struct kdbus_info {
	__u64 size;
	__u64 id;
	__u64 flags;
	struct kdbus_item items[0];
};

/**
 * struct kdbus_cmd_update - update flags of a connection
 * @size:		The total size of the struct
 * @flags:		Flags for the update command, userspace → kernel
 * @kernel_flags:	Supported flags for this command, kernel → userspace
 * @items:		A list of struct kdbus_item
 *
 * This struct is used with the KDBUS_CMD_CONN_UPDATE ioctl.
 */
struct kdbus_cmd_update {
	__u64 size;
	__u64 flags;
	__u64 kernel_flags;
	struct kdbus_item items[0];
} __attribute__((aligned(8)));

/**
 * enum kdbus_cmd_match_flags - flags to control the KDBUS_CMD_MATCH_ADD ioctl
 * @KDBUS_MATCH_REPLACE:	If entries with the supplied cookie already
 *				exists, remove them before installing the new
 *				matches.
 */
enum kdbus_cmd_match_flags {
	KDBUS_MATCH_REPLACE	= 1ULL <<  0,
};

/**
 * struct kdbus_cmd_match - struct to add or remove matches
 * @size:		The total size of the struct
 * @cookie:		Userspace supplied cookie. When removing, the cookie
 *			identifies the match to remove
 * @flags:		Flags for match command (KDBUS_MATCH_*),
 *			userspace → kernel
 * @kernel_flags:	Supported flags of the used command, kernel → userspace
 * @items:		A list of items for additional information
 *
 * This structure is used with the KDBUS_CMD_MATCH_ADD and
 * KDBUS_CMD_MATCH_REMOVE ioctl.
 */
struct kdbus_cmd_match {
	__u64 size;
	__u64 cookie;
	__u64 flags;
	__u64 kernel_flags;
	struct kdbus_item items[0];
} __attribute__((aligned(8)));

/**
 * enum kdbus_ioctl_type - Ioctl API
 * @KDBUS_CMD_BUS_MAKE:		After opening the "control" device node, this
 *				command creates a new bus with the specified
 *				name. The bus is immediately shut down and
 *				cleaned up when the opened "control" device node
 *				is closed.
 * @KDBUS_CMD_DOMAIN_MAKE:	Similar to KDBUS_CMD_BUS_MAKE, but it creates a
 *				new kdbus domain.
 * @KDBUS_CMD_ENDPOINT_MAKE:	Creates a new named special endpoint to talk to
 *				the bus. Such endpoints usually carry a more
 *				restrictive policy and grant restricted access
 *				to specific applications.
 * @KDBUS_CMD_HELLO:		By opening the bus device node a connection is
 *				created. After a HELLO the opened connection
 *				becomes an active peer on the bus.
 * @KDBUS_CMD_BYEBYE:		Disconnect a connection. If there are no
 *				messages queued up in the connection's pool,
 *				the call succeeds, and the handle is rendered
 *				unusable. Otherwise, -EBUSY is returned without
 *				any further side-effects.
 * @KDBUS_CMD_MSG_SEND:		Send a message and pass data from userspace to
 *				the kernel.
 * @KDBUS_CMD_MSG_RECV:		Receive a message from the kernel which is
 *				placed in the receiver's pool.
 * @KDBUS_CMD_MSG_CANCEL:	Cancel a pending request of a message that
 *				blocks while waiting for a reply. The parameter
 *				denotes the cookie of the message in flight.
 * @KDBUS_CMD_FREE:		Release the allocated memory in the receiver's
 *				pool.
 * @KDBUS_CMD_NAME_ACQUIRE:	Request a well-known bus name to associate with
 *				the connection. Well-known names are used to
 *				address a peer on the bus.
 * @KDBUS_CMD_NAME_RELEASE:	Release a well-known name the connection
 *				currently owns.
 * @KDBUS_CMD_NAME_LIST:	Retrieve the list of all currently registered
 *				well-known and unique names.
 * @KDBUS_CMD_CONN_INFO:	Retrieve credentials and properties of the
 *				initial creator of the connection. The data was
 *				stored at registration time and does not
 *				necessarily represent the connected process or
 *				the actual state of the process.
 * @KDBUS_CMD_CONN_UPDATE:	Update the properties of a connection. Used to
 *				update the metadata subscription mask and
 *				policy.
 * @KDBUS_CMD_BUS_CREATOR_INFO:	Retrieve information of the creator of the bus
 *				a connection is attached to.
 * @KDBUS_CMD_ENDPOINT_UPDATE:	Update the properties of a custom enpoint. Used
 *				to update the policy.
 * @KDBUS_CMD_MATCH_ADD:	Install a match which broadcast messages should
 *				be delivered to the connection.
 * @KDBUS_CMD_MATCH_REMOVE:	Remove a current match for broadcast messages.
 */
enum kdbus_ioctl_type {
	KDBUS_CMD_BUS_MAKE =		_IOW(KDBUS_IOCTL_MAGIC, 0x00,
					     struct kdbus_cmd_make),
	KDBUS_CMD_DOMAIN_MAKE =		_IOW(KDBUS_IOCTL_MAGIC, 0x10,
					     struct kdbus_cmd_make),
	KDBUS_CMD_ENDPOINT_MAKE =	_IOW(KDBUS_IOCTL_MAGIC, 0x20,
					     struct kdbus_cmd_make),

	KDBUS_CMD_HELLO =		_IOWR(KDBUS_IOCTL_MAGIC, 0x30,
					      struct kdbus_cmd_hello),
	KDBUS_CMD_BYEBYE =		_IO(KDBUS_IOCTL_MAGIC, 0x31),

	KDBUS_CMD_MSG_SEND =		_IOWR(KDBUS_IOCTL_MAGIC, 0x40,
					      struct kdbus_msg),
	KDBUS_CMD_MSG_RECV =		_IOWR(KDBUS_IOCTL_MAGIC, 0x41,
					      struct kdbus_cmd_recv),
	KDBUS_CMD_MSG_CANCEL =		_IOW(KDBUS_IOCTL_MAGIC, 0x42,
					     struct kdbus_cmd_cancel),
	KDBUS_CMD_FREE =		_IOW(KDBUS_IOCTL_MAGIC, 0x43,
					     struct kdbus_cmd_free),

	KDBUS_CMD_NAME_ACQUIRE =	_IOWR(KDBUS_IOCTL_MAGIC, 0x50,
					      struct kdbus_cmd_name),
	KDBUS_CMD_NAME_RELEASE =	_IOW(KDBUS_IOCTL_MAGIC, 0x51,
					     struct kdbus_cmd_name),
	KDBUS_CMD_NAME_LIST =		_IOWR(KDBUS_IOCTL_MAGIC, 0x52,
					      struct kdbus_cmd_name_list),

	KDBUS_CMD_CONN_INFO =		_IOWR(KDBUS_IOCTL_MAGIC, 0x60,
					      struct kdbus_cmd_info),
	KDBUS_CMD_CONN_UPDATE =		_IOW(KDBUS_IOCTL_MAGIC, 0x61,
					     struct kdbus_cmd_update),
	KDBUS_CMD_BUS_CREATOR_INFO =	_IOWR(KDBUS_IOCTL_MAGIC, 0x62,
					      struct kdbus_cmd_info),

	KDBUS_CMD_ENDPOINT_UPDATE =	_IOW(KDBUS_IOCTL_MAGIC, 0x71,
					     struct kdbus_cmd_update),

	KDBUS_CMD_MATCH_ADD =		_IOW(KDBUS_IOCTL_MAGIC, 0x80,
					     struct kdbus_cmd_match),
	KDBUS_CMD_MATCH_REMOVE =	_IOW(KDBUS_IOCTL_MAGIC, 0x81,
					     struct kdbus_cmd_match),
};

#endif /* _KDBUS_UAPI_H_ */
