/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <sys/resource.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <linux/oom.h>
#include <linux/input.h>
#include <linux/if_link.h>
#include <linux/loop.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/neighbour.h>

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

#if !HAVE_DECL_PIVOT_ROOT
static inline int pivot_root(const char *new_root, const char *put_old) {
        return syscall(SYS_pivot_root, new_root, put_old);
}
#endif

#ifndef __NR_memfd_create
#  if defined __x86_64__
#    define __NR_memfd_create 319
#  elif defined __arm__
#    define __NR_memfd_create 385
#  elif defined __aarch64__
#    define __NR_memfd_create 279
#  elif defined _MIPS_SIM
#    if _MIPS_SIM == _MIPS_SIM_ABI32
#      define __NR_memfd_create 4354
#    endif
#    if _MIPS_SIM == _MIPS_SIM_NABI32
#      define __NR_memfd_create 6318
#    endif
#    if _MIPS_SIM == _MIPS_SIM_ABI64
#      define __NR_memfd_create 5314
#    endif
#  elif defined __i386__
#    define __NR_memfd_create 356
#  else
#    warning "__NR_memfd_create unknown for your architecture"
#    define __NR_memfd_create 0xffffffff
#  endif
#endif

#ifndef HAVE_MEMFD_CREATE
static inline int memfd_create(const char *name, unsigned int flags) {
        return syscall(__NR_memfd_create, name, flags);
}
#endif

#ifndef __NR_getrandom
#  if defined __x86_64__
#    define __NR_getrandom 318
#  elif defined(__i386__)
#    define __NR_getrandom 355
#  elif defined(__arm__)
#    define __NR_getrandom 384
# elif defined(__aarch64__)
#    define __NR_getrandom 278
#  elif defined(__ia64__)
#    define __NR_getrandom 1339
#  elif defined(__m68k__)
#    define __NR_getrandom 352
#  elif defined(__s390x__)
#    define __NR_getrandom 349
#  elif defined(__powerpc__)
#    define __NR_getrandom 359
#  elif defined _MIPS_SIM
#    if _MIPS_SIM == _MIPS_SIM_ABI32
#      define __NR_getrandom 4353
#    endif
#    if _MIPS_SIM == _MIPS_SIM_NABI32
#      define __NR_getrandom 6317
#    endif
#    if _MIPS_SIM == _MIPS_SIM_ABI64
#      define __NR_getrandom 5313
#    endif
#  else
#    warning "__NR_getrandom unknown for your architecture"
#    define __NR_getrandom 0xffffffff
#  endif
#endif

#if !HAVE_DECL_GETRANDOM
static inline int getrandom(void *buffer, size_t count, unsigned flags) {
        return syscall(__NR_getrandom, buffer, count, flags);
}
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

#ifndef BTRFS_ROOT_BACKREF_KEY
#define BTRFS_ROOT_BACKREF_KEY 144
#endif

#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC 0x9123683E
#endif

#ifndef MS_MOVE
#define MS_MOVE 8192
#endif

#ifndef MS_PRIVATE
#define MS_PRIVATE  (1 << 18)
#endif

#if !HAVE_DECL_GETTID
static inline pid_t gettid(void) {
        return (pid_t) syscall(SYS_gettid);
}
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

#ifndef __NR_name_to_handle_at
#  if defined(__x86_64__)
#    define __NR_name_to_handle_at 303
#  elif defined(__i386__)
#    define __NR_name_to_handle_at 341
#  elif defined(__arm__)
#    define __NR_name_to_handle_at 370
#  elif defined(__powerpc__)
#    define __NR_name_to_handle_at 345
#  else
#    error "__NR_name_to_handle_at is not defined"
#  endif
#endif

#if !HAVE_DECL_NAME_TO_HANDLE_AT
struct file_handle {
        unsigned int handle_bytes;
        int handle_type;
        unsigned char f_handle[0];
};

static inline int name_to_handle_at(int fd, const char *name, struct file_handle *handle, int *mnt_id, int flags) {
        return syscall(__NR_name_to_handle_at, fd, name, handle, mnt_id, flags);
}
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

#ifndef __NR_setns
#  if defined(__x86_64__)
#    define __NR_setns 308
#  elif defined(__i386__)
#    define __NR_setns 346
#  else
#    error "__NR_setns is not defined"
#  endif
#endif

#if !HAVE_DECL_SETNS
static inline int setns(int fd, int nstype) {
        return syscall(__NR_setns, fd, nstype);
}
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

#define IFLA_INET6_MAX	(__IFLA_INET6_MAX - 1)

#define IN6_ADDR_GEN_MODE_EUI64 0
#define IN6_ADDR_GEN_MODE_NONE 1
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

#if !HAVE_DECL_IFLA_IPTUN_6RD_RELAY_PREFIXLEN
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
#define __IFLA_IPTUN_MAX 15

#define IFLA_IPTUN_MAX  (__IFLA_IPTUN_MAX - 1)
#endif

#if !HAVE_DECL_IFLA_BRIDGE_VLAN_INFO
#define IFLA_BRIDGE_FLAGS 0
#define IFLA_BRIDGE_MODE 1
#define IFLA_BRIDGE_VLAN_INFO 2
#define __IFLA_BRIDGE_MAX 3

#define IFLA_BRIDGE_MAX (__IFLA_BRIDGE_MAX - 1)
#endif

#if !HAVE_DECL_IFLA_BRPORT_UNICAST_FLOOD
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
#define __IFLA_BRPORT_MAX 10

#define IFLA_BRPORT_MAX (__IFLA_BRPORT_MAX - 1)
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

#ifndef IPV6_UNICAST_IF
#define IPV6_UNICAST_IF 76
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

static inline int raw_clone(unsigned long flags, void *child_stack) {
#if defined(__s390__) || defined(__CRIS__)
        /* On s390 and cris the order of the first and second arguments
         * of the raw clone() system call is reversed. */
        return (int) syscall(__NR_clone, child_stack, flags);
#else
        return (int) syscall(__NR_clone, flags, child_stack);
#endif
}

static inline pid_t raw_getpid(void) {
        return (pid_t) syscall(__NR_getpid);
}

#if !HAVE_DECL_RENAMEAT2

#ifndef __NR_renameat2
#  if defined __x86_64__
#    define __NR_renameat2 316
#  elif defined __arm__
#    define __NR_renameat2 382
#  elif defined _MIPS_SIM
#    if _MIPS_SIM == _MIPS_SIM_ABI32
#      define __NR_renameat2 4351
#    endif
#    if _MIPS_SIM == _MIPS_SIM_NABI32
#      define __NR_renameat2 6315
#    endif
#    if _MIPS_SIM == _MIPS_SIM_ABI64
#      define __NR_renameat2 5311
#    endif
#  elif defined __i386__
#    define __NR_renameat2 353
#  else
#    warning "__NR_renameat2 unknown for your architecture"
#    define __NR_renameat2 0xffffffff
#  endif
#endif

static inline int renameat2(int oldfd, const char *oldname, int newfd, const char *newname, unsigned flags) {
        return syscall(__NR_renameat2, oldfd, oldname, newfd, newname, flags);
}
#endif

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif

#if !HAVE_DECL_KCMP
static inline int kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2) {
        return syscall(__NR_kcmp, pid1, pid2, type, idx1, idx2);
}
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
