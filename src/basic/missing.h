#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

/* Missing glibc definitions to access certain kernel APIs */

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/if_link.h>
#include <linux/input.h>
#include <linux/loop.h>
#include <linux/neighbour.h>
#include <linux/oom.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <uchar.h>
#include <unistd.h>

#ifdef HAVE_AUDIT
#include <libaudit.h>
#endif

#ifdef ARCH_MIPS
#include <asm/sgidefs.h>
#endif

#ifdef HAVE_LINUX_BTRFS_H
#include <linux/btrfs.h>
#endif

#include "macro.h"

#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME 15
#endif

/* If RLIMIT_RTTIME is not defined, then we cannot use RLIMIT_NLIMITS as is */
#define _RLIMIT_MAX (RLIMIT_RTTIME+1 > RLIMIT_NLIMITS ? RLIMIT_RTTIME+1 : RLIMIT_NLIMITS)

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 7)
#endif

#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 8)
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_SEAL_SEAL     0x0001  /* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002  /* prevent file from shrinking */
#define F_SEAL_GROW     0x0004  /* prevent file from growing */
#define F_SEAL_WRITE    0x0008  /* prevent writes */
#endif

#ifndef F_OFD_GETLK
#define F_OFD_GETLK     36
#define F_OFD_SETLK     37
#define F_OFD_SETLKW    38
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif

#ifndef OOM_SCORE_ADJ_MIN
#define OOM_SCORE_ADJ_MIN (-1000)
#endif

#ifndef OOM_SCORE_ADJ_MAX
#define OOM_SCORE_ADJ_MAX 1000
#endif

#ifndef AUDIT_SERVICE_START
#define AUDIT_SERVICE_START 1130 /* Service (daemon) start */
#endif

#ifndef AUDIT_SERVICE_STOP
#define AUDIT_SERVICE_STOP 1131 /* Service (daemon) stop */
#endif

#ifndef TIOCVHANGUP
#define TIOCVHANGUP 0x5437
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef NETLINK_LIST_MEMBERSHIPS
#define NETLINK_LIST_MEMBERSHIPS 9
#endif

#ifndef SOL_SCTP
#define SOL_SCTP 132
#endif

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#endif

#ifndef GRND_RANDOM
#define GRND_RANDOM 0x0002
#endif

#ifndef BTRFS_IOCTL_MAGIC
#define BTRFS_IOCTL_MAGIC 0x94
#endif

#ifndef BTRFS_PATH_NAME_MAX
#define BTRFS_PATH_NAME_MAX 4087
#endif

#ifndef BTRFS_DEVICE_PATH_NAME_MAX
#define BTRFS_DEVICE_PATH_NAME_MAX 1024
#endif

#ifndef BTRFS_FSID_SIZE
#define BTRFS_FSID_SIZE 16
#endif

#ifndef BTRFS_UUID_SIZE
#define BTRFS_UUID_SIZE 16
#endif

#ifndef BTRFS_SUBVOL_RDONLY
#define BTRFS_SUBVOL_RDONLY (1ULL << 1)
#endif

#ifndef BTRFS_SUBVOL_NAME_MAX
#define BTRFS_SUBVOL_NAME_MAX 4039
#endif

#ifndef BTRFS_INO_LOOKUP_PATH_MAX
#define BTRFS_INO_LOOKUP_PATH_MAX 4080
#endif

#ifndef BTRFS_SEARCH_ARGS_BUFSIZE
#define BTRFS_SEARCH_ARGS_BUFSIZE (4096 - sizeof(struct btrfs_ioctl_search_key))
#endif

#ifndef BTRFS_QGROUP_LEVEL_SHIFT
#define BTRFS_QGROUP_LEVEL_SHIFT 48
#endif

#ifndef HAVE_LINUX_BTRFS_H
struct btrfs_ioctl_vol_args {
        int64_t fd;
        char name[BTRFS_PATH_NAME_MAX + 1];
};

struct btrfs_qgroup_limit {
        __u64 flags;
        __u64 max_rfer;
        __u64 max_excl;
        __u64 rsv_rfer;
        __u64 rsv_excl;
};

struct btrfs_qgroup_inherit {
        __u64 flags;
        __u64 num_qgroups;
        __u64 num_ref_copies;
        __u64 num_excl_copies;
        struct btrfs_qgroup_limit lim;
        __u64 qgroups[0];
};

struct btrfs_ioctl_qgroup_limit_args {
        __u64 qgroupid;
        struct btrfs_qgroup_limit lim;
};

struct btrfs_ioctl_vol_args_v2 {
        __s64 fd;
        __u64 transid;
        __u64 flags;
        union {
                struct {
                        __u64 size;
                        struct btrfs_qgroup_inherit *qgroup_inherit;
                };
                __u64 unused[4];
        };
        char name[BTRFS_SUBVOL_NAME_MAX + 1];
};

struct btrfs_ioctl_dev_info_args {
        uint64_t devid;                         /* in/out */
        uint8_t uuid[BTRFS_UUID_SIZE];          /* in/out */
        uint64_t bytes_used;                    /* out */
        uint64_t total_bytes;                   /* out */
        uint64_t unused[379];                   /* pad to 4k */
        char path[BTRFS_DEVICE_PATH_NAME_MAX];  /* out */
};

struct btrfs_ioctl_fs_info_args {
        uint64_t max_id;                        /* out */
        uint64_t num_devices;                   /* out */
        uint8_t fsid[BTRFS_FSID_SIZE];          /* out */
        uint64_t reserved[124];                 /* pad to 1k */
};

struct btrfs_ioctl_ino_lookup_args {
        __u64 treeid;
        __u64 objectid;
        char name[BTRFS_INO_LOOKUP_PATH_MAX];
};

struct btrfs_ioctl_search_key {
        /* which root are we searching.  0 is the tree of tree roots */
        __u64 tree_id;

        /* keys returned will be >= min and <= max */
        __u64 min_objectid;
        __u64 max_objectid;

        /* keys returned will be >= min and <= max */
        __u64 min_offset;
        __u64 max_offset;

        /* max and min transids to search for */
        __u64 min_transid;
        __u64 max_transid;

        /* keys returned will be >= min and <= max */
        __u32 min_type;
        __u32 max_type;

        /*
         * how many items did userland ask for, and how many are we
         * returning
         */
        __u32 nr_items;

        /* align to 64 bits */
        __u32 unused;

        /* some extra for later */
        __u64 unused1;
        __u64 unused2;
        __u64 unused3;
        __u64 unused4;
};

struct btrfs_ioctl_search_header {
        __u64 transid;
        __u64 objectid;
        __u64 offset;
        __u32 type;
        __u32 len;
};


struct btrfs_ioctl_search_args {
        struct btrfs_ioctl_search_key key;
        char buf[BTRFS_SEARCH_ARGS_BUFSIZE];
};

struct btrfs_ioctl_clone_range_args {
        __s64 src_fd;
        __u64 src_offset, src_length;
        __u64 dest_offset;
};

#define BTRFS_QUOTA_CTL_ENABLE  1
#define BTRFS_QUOTA_CTL_DISABLE 2
#define BTRFS_QUOTA_CTL_RESCAN__NOTUSED 3
struct btrfs_ioctl_quota_ctl_args {
        __u64 cmd;
        __u64 status;
};
#endif

#ifndef BTRFS_IOC_DEFRAG
#define BTRFS_IOC_DEFRAG _IOW(BTRFS_IOCTL_MAGIC, 2, \
                                 struct btrfs_ioctl_vol_args)
#endif

#ifndef BTRFS_IOC_RESIZE
#define BTRFS_IOC_RESIZE _IOW(BTRFS_IOCTL_MAGIC, 3, \
                                 struct btrfs_ioctl_vol_args)
#endif

#ifndef BTRFS_IOC_CLONE
#define BTRFS_IOC_CLONE _IOW(BTRFS_IOCTL_MAGIC, 9, int)
#endif

#ifndef BTRFS_IOC_CLONE_RANGE
#define BTRFS_IOC_CLONE_RANGE _IOW(BTRFS_IOCTL_MAGIC, 13, \
                                 struct btrfs_ioctl_clone_range_args)
#endif

#ifndef BTRFS_IOC_SUBVOL_CREATE
#define BTRFS_IOC_SUBVOL_CREATE _IOW(BTRFS_IOCTL_MAGIC, 14, \
                                 struct btrfs_ioctl_vol_args)
#endif

#ifndef BTRFS_IOC_SNAP_DESTROY
#define BTRFS_IOC_SNAP_DESTROY _IOW(BTRFS_IOCTL_MAGIC, 15, \
                                 struct btrfs_ioctl_vol_args)
#endif

#ifndef BTRFS_IOC_TREE_SEARCH
#define BTRFS_IOC_TREE_SEARCH _IOWR(BTRFS_IOCTL_MAGIC, 17, \
                                 struct btrfs_ioctl_search_args)
#endif

#ifndef BTRFS_IOC_INO_LOOKUP
#define BTRFS_IOC_INO_LOOKUP _IOWR(BTRFS_IOCTL_MAGIC, 18, \
                                 struct btrfs_ioctl_ino_lookup_args)
#endif

#ifndef BTRFS_IOC_SNAP_CREATE_V2
#define BTRFS_IOC_SNAP_CREATE_V2 _IOW(BTRFS_IOCTL_MAGIC, 23, \
                                 struct btrfs_ioctl_vol_args_v2)
#endif

#ifndef BTRFS_IOC_SUBVOL_GETFLAGS
#define BTRFS_IOC_SUBVOL_GETFLAGS _IOR(BTRFS_IOCTL_MAGIC, 25, __u64)
#endif

#ifndef BTRFS_IOC_SUBVOL_SETFLAGS
#define BTRFS_IOC_SUBVOL_SETFLAGS _IOW(BTRFS_IOCTL_MAGIC, 26, __u64)
#endif

#ifndef BTRFS_IOC_DEV_INFO
#define BTRFS_IOC_DEV_INFO _IOWR(BTRFS_IOCTL_MAGIC, 30, \
                                 struct btrfs_ioctl_dev_info_args)
#endif

#ifndef BTRFS_IOC_FS_INFO
#define BTRFS_IOC_FS_INFO _IOR(BTRFS_IOCTL_MAGIC, 31, \
                                 struct btrfs_ioctl_fs_info_args)
#endif

#ifndef BTRFS_IOC_DEVICES_READY
#define BTRFS_IOC_DEVICES_READY _IOR(BTRFS_IOCTL_MAGIC, 39, \
                                 struct btrfs_ioctl_vol_args)
#endif

#ifndef BTRFS_IOC_QUOTA_CTL
#define BTRFS_IOC_QUOTA_CTL _IOWR(BTRFS_IOCTL_MAGIC, 40, \
                               struct btrfs_ioctl_quota_ctl_args)
#endif

#ifndef BTRFS_IOC_QGROUP_LIMIT
#define BTRFS_IOC_QGROUP_LIMIT _IOR(BTRFS_IOCTL_MAGIC, 43, \
                               struct btrfs_ioctl_qgroup_limit_args)
#endif

#ifndef BTRFS_IOC_QUOTA_RESCAN_WAIT
#define BTRFS_IOC_QUOTA_RESCAN_WAIT _IO(BTRFS_IOCTL_MAGIC, 46)
#endif

#ifndef BTRFS_FIRST_FREE_OBJECTID
#define BTRFS_FIRST_FREE_OBJECTID 256
#endif

#ifndef BTRFS_LAST_FREE_OBJECTID
#define BTRFS_LAST_FREE_OBJECTID -256ULL
#endif

#ifndef BTRFS_ROOT_TREE_OBJECTID
#define BTRFS_ROOT_TREE_OBJECTID 1
#endif

#ifndef BTRFS_QUOTA_TREE_OBJECTID
#define BTRFS_QUOTA_TREE_OBJECTID 8ULL
#endif

#ifndef BTRFS_ROOT_ITEM_KEY
#define BTRFS_ROOT_ITEM_KEY 132
#endif

#ifndef BTRFS_QGROUP_STATUS_KEY
#define BTRFS_QGROUP_STATUS_KEY 240
#endif

#ifndef BTRFS_QGROUP_INFO_KEY
#define BTRFS_QGROUP_INFO_KEY 242
#endif

#ifndef BTRFS_QGROUP_LIMIT_KEY
#define BTRFS_QGROUP_LIMIT_KEY 244
#endif

#ifndef BTRFS_QGROUP_RELATION_KEY
#define BTRFS_QGROUP_RELATION_KEY 246
#endif

#ifndef BTRFS_ROOT_BACKREF_KEY
#define BTRFS_ROOT_BACKREF_KEY 144
#endif

#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC 0x9123683E
#endif

#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC 0x27e0eb
#endif

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

#ifndef MQUEUE_MAGIC
#define MQUEUE_MAGIC 0x19800202
#endif

#ifndef SECURITYFS_MAGIC
#define SECURITYFS_MAGIC 0x73636673
#endif

#ifndef TRACEFS_MAGIC
#define TRACEFS_MAGIC 0x74726163
#endif

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

#ifndef MS_MOVE
#define MS_MOVE 8192
#endif

#ifndef MS_PRIVATE
#define MS_PRIVATE  (1 << 18)
#endif

#ifndef SCM_SECURITY
#define SCM_SECURITY 0x03
#endif

#ifndef MS_STRICTATIME
#define MS_STRICTATIME (1<<24)
#endif

#ifndef MS_REC
#define MS_REC 16384
#endif

#ifndef MS_SHARED
#define MS_SHARED (1<<20)
#endif

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef PR_SET_CHILD_SUBREAPER
#define PR_SET_CHILD_SUBREAPER 36
#endif

#ifndef MAX_HANDLE_SZ
#define MAX_HANDLE_SZ 128
#endif

#ifndef HAVE_SECURE_GETENV
#  ifdef HAVE___SECURE_GETENV
#    define secure_getenv __secure_getenv
#  else
#    error "neither secure_getenv nor __secure_getenv are available"
#  endif
#endif

#ifndef CIFS_MAGIC_NUMBER
#  define CIFS_MAGIC_NUMBER 0xFF534D42
#endif

#ifndef TFD_TIMER_CANCEL_ON_SET
#  define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#endif

#ifndef SO_REUSEPORT
#  define SO_REUSEPORT 15
#endif

#ifndef EVIOCREVOKE
#  define EVIOCREVOKE _IOW('E', 0x91, int)
#endif

#ifndef DRM_IOCTL_SET_MASTER
#  define DRM_IOCTL_SET_MASTER _IO('d', 0x1e)
#endif

#ifndef DRM_IOCTL_DROP_MASTER
#  define DRM_IOCTL_DROP_MASTER _IO('d', 0x1f)
#endif

#if defined(__i386__) || defined(__x86_64__)

/* The precise definition of __O_TMPFILE is arch specific, so let's
 * just define this on x86 where we know the value. */

#ifndef __O_TMPFILE
#define __O_TMPFILE     020000000
#endif

/* a horrid kludge trying to make sure that this will fail on old kernels */
#ifndef O_TMPFILE
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#endif

#endif

#if !HAVE_DECL_LO_FLAGS_PARTSCAN
#define LO_FLAGS_PARTSCAN 8
#endif

#ifndef LOOP_CTL_REMOVE
#define LOOP_CTL_REMOVE 0x4C81
#endif

#ifndef LOOP_CTL_GET_FREE
#define LOOP_CTL_GET_FREE 0x4C82
#endif

#if !HAVE_DECL_IFLA_INET6_ADDR_GEN_MODE
#define IFLA_INET6_UNSPEC 0
#define IFLA_INET6_FLAGS 1
#define IFLA_INET6_CONF 2
#define IFLA_INET6_STATS 3
#define IFLA_INET6_MCAST 4
#define IFLA_INET6_CACHEINFO 5
#define IFLA_INET6_ICMP6STATS 6
#define IFLA_INET6_TOKEN 7
#define IFLA_INET6_ADDR_GEN_MODE 8
#define __IFLA_INET6_MAX 9

#define IFLA_INET6_MAX (__IFLA_INET6_MAX - 1)

#define IN6_ADDR_GEN_MODE_EUI64 0
#define IN6_ADDR_GEN_MODE_NONE 1
#endif

#if !HAVE_DECL_IN6_ADDR_GEN_MODE_STABLE_PRIVACY
#define IN6_ADDR_GEN_MODE_STABLE_PRIVACY 2
#endif

#if !HAVE_DECL_IFLA_MACVLAN_FLAGS
#define IFLA_MACVLAN_UNSPEC 0
#define IFLA_MACVLAN_MODE 1
#define IFLA_MACVLAN_FLAGS 2
#define __IFLA_MACVLAN_MAX 3

#define IFLA_MACVLAN_MAX (__IFLA_MACVLAN_MAX - 1)
#endif

#if !HAVE_DECL_IFLA_IPVLAN_MODE
#define IFLA_IPVLAN_UNSPEC 0
#define IFLA_IPVLAN_MODE 1
#define __IFLA_IPVLAN_MAX 2

#define IFLA_IPVLAN_MAX (__IFLA_IPVLAN_MAX - 1)

#define IPVLAN_MODE_L2 0
#define IPVLAN_MODE_L3 1
#define IPVLAN_MAX 2
#endif

#if !HAVE_DECL_IFLA_VTI_REMOTE
#define IFLA_VTI_UNSPEC 0
#define IFLA_VTI_LINK 1
#define IFLA_VTI_IKEY 2
#define IFLA_VTI_OKEY 3
#define IFLA_VTI_LOCAL 4
#define IFLA_VTI_REMOTE 5
#define __IFLA_VTI_MAX 6

#define IFLA_VTI_MAX (__IFLA_VTI_MAX - 1)
#endif

#if !HAVE_DECL_IFLA_PHYS_PORT_ID
#define IFLA_EXT_MASK 29
#undef IFLA_PROMISCUITY
#define IFLA_PROMISCUITY 30
#define IFLA_NUM_TX_QUEUES 31
#define IFLA_NUM_RX_QUEUES 32
#define IFLA_CARRIER 33
#define IFLA_PHYS_PORT_ID 34
#define __IFLA_MAX 35

#define IFLA_MAX (__IFLA_MAX - 1)
#endif

#if !HAVE_DECL_IFLA_BOND_AD_INFO
#define IFLA_BOND_UNSPEC 0
#define IFLA_BOND_MODE 1
#define IFLA_BOND_ACTIVE_SLAVE 2
#define IFLA_BOND_MIIMON 3
#define IFLA_BOND_UPDELAY 4
#define IFLA_BOND_DOWNDELAY 5
#define IFLA_BOND_USE_CARRIER 6
#define IFLA_BOND_ARP_INTERVAL 7
#define IFLA_BOND_ARP_IP_TARGET 8
#define IFLA_BOND_ARP_VALIDATE 9
#define IFLA_BOND_ARP_ALL_TARGETS 10
#define IFLA_BOND_PRIMARY 11
#define IFLA_BOND_PRIMARY_RESELECT 12
#define IFLA_BOND_FAIL_OVER_MAC 13
#define IFLA_BOND_XMIT_HASH_POLICY 14
#define IFLA_BOND_RESEND_IGMP 15
#define IFLA_BOND_NUM_PEER_NOTIF 16
#define IFLA_BOND_ALL_SLAVES_ACTIVE 17
#define IFLA_BOND_MIN_LINKS 18
#define IFLA_BOND_LP_INTERVAL 19
#define IFLA_BOND_PACKETS_PER_SLAVE 20
#define IFLA_BOND_AD_LACP_RATE 21
#define IFLA_BOND_AD_SELECT 22
#define IFLA_BOND_AD_INFO 23
#define __IFLA_BOND_MAX 24

#define IFLA_BOND_MAX   (__IFLA_BOND_MAX - 1)
#endif

#if !HAVE_DECL_IFLA_VLAN_PROTOCOL
#define IFLA_VLAN_UNSPEC 0
#define IFLA_VLAN_ID 1
#define IFLA_VLAN_FLAGS 2
#define IFLA_VLAN_EGRESS_QOS 3
#define IFLA_VLAN_INGRESS_QOS 4
#define IFLA_VLAN_PROTOCOL 5
#define __IFLA_VLAN_MAX 6

#define IFLA_VLAN_MAX   (__IFLA_VLAN_MAX - 1)
#endif

#if !HAVE_DECL_IFLA_VXLAN_REMCSUM_NOPARTIAL
#define IFLA_VXLAN_UNSPEC 0
#define IFLA_VXLAN_ID 1
#define IFLA_VXLAN_GROUP 2
#define IFLA_VXLAN_LINK 3
#define IFLA_VXLAN_LOCAL 4
#define IFLA_VXLAN_TTL 5
#define IFLA_VXLAN_TOS 6
#define IFLA_VXLAN_LEARNING 7
#define IFLA_VXLAN_AGEING 8
#define IFLA_VXLAN_LIMIT 9
#define IFLA_VXLAN_PORT_RANGE 10
#define IFLA_VXLAN_PROXY 11
#define IFLA_VXLAN_RSC 12
#define IFLA_VXLAN_L2MISS 13
#define IFLA_VXLAN_L3MISS 14
#define IFLA_VXLAN_PORT 15
#define IFLA_VXLAN_GROUP6 16
#define IFLA_VXLAN_LOCAL6 17
#define IFLA_VXLAN_UDP_CSUM 18
#define IFLA_VXLAN_UDP_ZERO_CSUM6_TX 19
#define IFLA_VXLAN_UDP_ZERO_CSUM6_RX 20
#define IFLA_VXLAN_REMCSUM_TX 21
#define IFLA_VXLAN_REMCSUM_RX 22
#define IFLA_VXLAN_GBP 23
#define IFLA_VXLAN_REMCSUM_NOPARTIAL 24
#define __IFLA_VXLAN_MAX 25

#define IFLA_VXLAN_MAX  (__IFLA_VXLAN_MAX - 1)
#endif

#if !HAVE_DECL_IFLA_IPTUN_ENCAP_DPORT
#define IFLA_IPTUN_UNSPEC 0
#define IFLA_IPTUN_LINK 1
#define IFLA_IPTUN_LOCAL 2
#define IFLA_IPTUN_REMOTE 3
#define IFLA_IPTUN_TTL 4
#define IFLA_IPTUN_TOS 5
#define IFLA_IPTUN_ENCAP_LIMIT 6
#define IFLA_IPTUN_FLOWINFO 7
#define IFLA_IPTUN_FLAGS 8
#define IFLA_IPTUN_PROTO 9
#define IFLA_IPTUN_PMTUDISC 10
#define IFLA_IPTUN_6RD_PREFIX 11
#define IFLA_IPTUN_6RD_RELAY_PREFIX 12
#define IFLA_IPTUN_6RD_PREFIXLEN 13
#define IFLA_IPTUN_6RD_RELAY_PREFIXLEN 14
#define IFLA_IPTUN_ENCAP_TYPE 15
#define IFLA_IPTUN_ENCAP_FLAGS 16
#define IFLA_IPTUN_ENCAP_SPORT 17
#define IFLA_IPTUN_ENCAP_DPORT 18

#define __IFLA_IPTUN_MAX 19

#define IFLA_IPTUN_MAX  (__IFLA_IPTUN_MAX - 1)
#endif

#if !HAVE_DECL_IFLA_GRE_ENCAP_DPORT
#define IFLA_GRE_UNSPEC 0
#define IFLA_GRE_LINK 1
#define IFLA_GRE_IFLAGS 2
#define IFLA_GRE_OFLAGS 3
#define IFLA_GRE_IKEY 4
#define IFLA_GRE_OKEY 5
#define IFLA_GRE_LOCAL 6
#define IFLA_GRE_REMOTE 7
#define IFLA_GRE_TTL 8
#define IFLA_GRE_TOS 9
#define IFLA_GRE_PMTUDISC 10
#define IFLA_GRE_ENCAP_LIMIT 11
#define IFLA_GRE_FLOWINFO 12
#define IFLA_GRE_FLAGS 13
#define IFLA_GRE_ENCAP_TYPE 14
#define IFLA_GRE_ENCAP_FLAGS 15
#define IFLA_GRE_ENCAP_SPORT 16
#define IFLA_GRE_ENCAP_DPORT 17

#define __IFLA_GRE_MAX 18

#define IFLA_GRE_MAX  (__IFLA_GRE_MAX - 1)
#endif

#if !HAVE_DECL_IFLA_BRIDGE_VLAN_INFO
#define IFLA_BRIDGE_FLAGS 0
#define IFLA_BRIDGE_MODE 1
#define IFLA_BRIDGE_VLAN_INFO 2
#define __IFLA_BRIDGE_MAX 3

#define IFLA_BRIDGE_MAX (__IFLA_BRIDGE_MAX - 1)
#endif

#ifndef BRIDGE_VLAN_INFO_RANGE_BEGIN
#define BRIDGE_VLAN_INFO_RANGE_BEGIN (1<<3) /* VLAN is start of vlan range */
#endif

#ifndef BRIDGE_VLAN_INFO_RANGE_END
#define BRIDGE_VLAN_INFO_RANGE_END (1<<4) /* VLAN is end of vlan range */
#endif

#if !HAVE_DECL_IFLA_BR_VLAN_DEFAULT_PVID
#define IFLA_BR_UNSPEC 0
#define IFLA_BR_FORWARD_DELAY 1
#define IFLA_BR_HELLO_TIME 2
#define IFLA_BR_MAX_AGE 3
#define IFLA_BR_AGEING_TIME 4
#define IFLA_BR_STP_STATE 5
#define IFLA_BR_PRIORITY 6
#define IFLA_BR_VLAN_FILTERING 7
#define IFLA_BR_VLAN_PROTOCOL 8
#define IFLA_BR_GROUP_FWD_MASK 9
#define IFLA_BR_ROOT_ID 10
#define IFLA_BR_BRIDGE_ID 11
#define IFLA_BR_ROOT_PORT 12
#define IFLA_BR_ROOT_PATH_COST 13
#define IFLA_BR_TOPOLOGY_CHANGE 14
#define IFLA_BR_TOPOLOGY_CHANGE_DETECTED 15
#define IFLA_BR_HELLO_TIMER 16
#define IFLA_BR_TCN_TIMER 17
#define IFLA_BR_TOPOLOGY_CHANGE_TIMER 18
#define IFLA_BR_GC_TIMER 19
#define IFLA_BR_GROUP_ADDR 20
#define IFLA_BR_FDB_FLUSH 21
#define IFLA_BR_MCAST_ROUTER 22
#define IFLA_BR_MCAST_SNOOPING 23
#define IFLA_BR_MCAST_QUERY_USE_IFADDR 24
#define IFLA_BR_MCAST_QUERIER 25
#define IFLA_BR_MCAST_HASH_ELASTICITY 26
#define IFLA_BR_MCAST_HASH_MAX 27
#define IFLA_BR_MCAST_LAST_MEMBER_CNT 28
#define IFLA_BR_MCAST_STARTUP_QUERY_CNT 29
#define IFLA_BR_MCAST_LAST_MEMBER_INTVL 30
#define IFLA_BR_MCAST_MEMBERSHIP_INTVL 31
#define IFLA_BR_MCAST_QUERIER_INTVL 32
#define IFLA_BR_MCAST_QUERY_INTVL 33
#define IFLA_BR_MCAST_QUERY_RESPONSE_INTVL 34
#define IFLA_BR_MCAST_STARTUP_QUERY_INTVL 35
#define IFLA_BR_NF_CALL_IPTABLES 36
#define IFLA_BR_NF_CALL_IP6TABLES 37
#define IFLA_BR_NF_CALL_ARPTABLES 38
#define IFLA_BR_VLAN_DEFAULT_PVID 39
#define __IFLA_BR_MAX 40

#define IFLA_BR_MAX (__IFLA_BR_MAX - 1)
#endif

#if !HAVE_DECL_IFLA_BRPORT_LEARNING_SYNC
#define IFLA_BRPORT_UNSPEC 0
#define IFLA_BRPORT_STATE 1
#define IFLA_BRPORT_PRIORITY 2
#define IFLA_BRPORT_COST 3
#define IFLA_BRPORT_MODE 4
#define IFLA_BRPORT_GUARD 5
#define IFLA_BRPORT_PROTECT 6
#define IFLA_BRPORT_FAST_LEAVE 7
#define IFLA_BRPORT_LEARNING 8
#define IFLA_BRPORT_UNICAST_FLOOD 9
#define IFLA_BRPORT_LEARNING_SYNC 11
#define __IFLA_BRPORT_MAX 12

#define IFLA_BRPORT_MAX (__IFLA_BRPORT_MAX - 1)
#endif

#if !HAVE_DECL_IFLA_BRPORT_PROXYARP
#define IFLA_BRPORT_PROXYARP 10
#endif

#if !HAVE_DECL_IFLA_VRF_TABLE
#define IFLA_VRF_TABLE 1
#endif

#if !HAVE_DECL_NDA_IFINDEX
#define NDA_UNSPEC 0
#define NDA_DST 1
#define NDA_LLADDR 2
#define NDA_CACHEINFO 3
#define NDA_PROBES 4
#define NDA_VLAN 5
#define NDA_PORT 6
#define NDA_VNI 7
#define NDA_IFINDEX 8
#define __NDA_MAX 9

#define NDA_MAX (__NDA_MAX - 1)
#endif

#ifndef RTA_PREF
#define RTA_PREF 20
#endif

#ifndef IPV6_UNICAST_IF
#define IPV6_UNICAST_IF 76
#endif

#ifndef IPV6_MIN_MTU
#define IPV6_MIN_MTU 1280
#endif

#ifndef IFF_MULTI_QUEUE
#define IFF_MULTI_QUEUE 0x100
#endif

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif

#ifndef IFF_DORMANT
#define IFF_DORMANT 0x20000
#endif

#ifndef BOND_XMIT_POLICY_ENCAP23
#define BOND_XMIT_POLICY_ENCAP23 3
#endif

#ifndef BOND_XMIT_POLICY_ENCAP34
#define BOND_XMIT_POLICY_ENCAP34 4
#endif

#ifndef NET_ADDR_RANDOM
#  define NET_ADDR_RANDOM 1
#endif

#ifndef NET_NAME_UNKNOWN
#  define NET_NAME_UNKNOWN 0
#endif

#ifndef NET_NAME_ENUM
#  define NET_NAME_ENUM 1
#endif

#ifndef NET_NAME_PREDICTABLE
#  define NET_NAME_PREDICTABLE 2
#endif

#ifndef NET_NAME_USER
#  define NET_NAME_USER 3
#endif

#ifndef NET_NAME_RENAMED
#  define NET_NAME_RENAMED 4
#endif

#ifndef BPF_XOR
#  define BPF_XOR 0xa0
#endif

/* Note that LOOPBACK_IFINDEX is currently not exported by the
 * kernel/glibc, but hardcoded internally by the kernel.  However, as
 * it is exported to userspace indirectly via rtnetlink and the
 * ioctls, and made use of widely we define it here too, in a way that
 * is compatible with the kernel's internal definition. */
#ifndef LOOPBACK_IFINDEX
#define LOOPBACK_IFINDEX 1
#endif

#if !HAVE_DECL_IFA_FLAGS
#define IFA_FLAGS 8
#endif

#ifndef IFA_F_MANAGETEMPADDR
#define IFA_F_MANAGETEMPADDR 0x100
#endif

#ifndef IFA_F_NOPREFIXROUTE
#define IFA_F_NOPREFIXROUTE 0x200
#endif

#ifndef MAX_AUDIT_MESSAGE_LENGTH
#define MAX_AUDIT_MESSAGE_LENGTH 8970
#endif

#ifndef AUDIT_NLGRP_MAX
#define AUDIT_NLGRP_READLOG 1
#endif

#ifndef CAP_MAC_OVERRIDE
#define CAP_MAC_OVERRIDE 32
#endif

#ifndef CAP_MAC_ADMIN
#define CAP_MAC_ADMIN 33
#endif

#ifndef CAP_SYSLOG
#define CAP_SYSLOG 34
#endif

#ifndef CAP_WAKE_ALARM
#define CAP_WAKE_ALARM 35
#endif

#ifndef CAP_BLOCK_SUSPEND
#define CAP_BLOCK_SUSPEND 36
#endif

#ifndef CAP_AUDIT_READ
#define CAP_AUDIT_READ 37
#endif

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif

#ifndef KCMP_FILE
#define KCMP_FILE 0
#endif

#ifndef INPUT_PROP_POINTING_STICK
#define INPUT_PROP_POINTING_STICK 0x05
#endif

#ifndef INPUT_PROP_ACCELEROMETER
#define INPUT_PROP_ACCELEROMETER  0x06
#endif

#ifndef HAVE_KEY_SERIAL_T
typedef int32_t key_serial_t;
#endif

#ifndef KEYCTL_READ
#define KEYCTL_READ 11
#endif

#ifndef KEYCTL_SET_TIMEOUT
#define KEYCTL_SET_TIMEOUT 15
#endif

#ifndef KEY_SPEC_USER_KEYRING
#define KEY_SPEC_USER_KEYRING -4
#endif

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif

#ifndef PR_CAP_AMBIENT_IS_SET
#define PR_CAP_AMBIENT_IS_SET 1
#endif

#ifndef PR_CAP_AMBIENT_RAISE
#define PR_CAP_AMBIENT_RAISE 2
#endif

#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

/* The following two defines are actually available in the kernel headers for longer, but we define them here anyway,
 * since that makes it easier to use them in conjunction with the glibc net/if.h header which conflicts with
 * linux/if.h. */
#ifndef IF_OPER_UNKNOWN
#define IF_OPER_UNKNOWN 0
#endif

#ifndef IF_OPER_UP
#define IF_OPER_UP 6

#ifndef HAVE_CHAR32_T
#define char32_t uint32_t
#endif

#ifndef HAVE_CHAR16_T
#define char16_t uint16_t
#endif

#ifndef ETHERTYPE_LLDP
#define ETHERTYPE_LLDP 0x88cc
#endif

#endif

#include "missing_syscall.h"
