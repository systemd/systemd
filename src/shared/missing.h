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
#include <linux/if_link.h>

#ifdef HAVE_AUDIT
#include <libaudit.h>
#endif

#include "macro.h"

#ifdef ARCH_MIPS
#include <asm/sgidefs.h>
#endif

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

#ifdef __x86_64__
#  ifndef __NR_fanotify_init
#    define __NR_fanotify_init 300
#  endif
#  ifndef __NR_fanotify_mark
#    define __NR_fanotify_mark 301
#  endif
#elif defined _MIPS_SIM
#  if _MIPS_SIM == _MIPS_SIM_ABI32
#    ifndef __NR_fanotify_init
#      define __NR_fanotify_init 4336
#    endif
#    ifndef __NR_fanotify_mark
#      define __NR_fanotify_mark 4337
#    endif
#  elif _MIPS_SIM == _MIPS_SIM_NABI32
#    ifndef __NR_fanotify_init
#      define __NR_fanotify_init 6300
#    endif
#    ifndef __NR_fanotify_mark
#      define __NR_fanotify_mark 6301
#    endif
#  elif _MIPS_SIM == _MIPS_SIM_ABI64
#    ifndef __NR_fanotify_init
#      define __NR_fanotify_init 5295
#    endif
#    ifndef __NR_fanotify_mark
#      define __NR_fanotify_mark 5296
#    endif
#  endif
#else
#  ifndef __NR_fanotify_init
#    define __NR_fanotify_init 338
#  endif
#  ifndef __NR_fanotify_mark
#    define __NR_fanotify_mark 339
#  endif
#endif

#ifndef HAVE_FANOTIFY_INIT
static inline int fanotify_init(unsigned int flags, unsigned int event_f_flags) {
        return syscall(__NR_fanotify_init, flags, event_f_flags);
}
#endif

#ifndef HAVE_FANOTIFY_MARK
static inline int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask,
                                int dfd, const char *pathname) {
#if defined _MIPS_SIM && _MIPS_SIM == _MIPS_SIM_ABI32 || defined __powerpc__ && !defined __powerpc64__ \
    || defined __arm__ && !defined __aarch64__
        union {
                uint64_t _64;
                uint32_t _32[2];
        } _mask;
        _mask._64 = mask;

        return syscall(__NR_fanotify_mark, fanotify_fd, flags,
                       _mask._32[0], _mask._32[1], dfd, pathname);
#else
        return syscall(__NR_fanotify_mark, fanotify_fd, flags, mask, dfd, pathname);
#endif
}
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

#ifndef HAVE_LINUX_BTRFS_H
struct btrfs_ioctl_vol_args {
        int64_t fd;
        char name[BTRFS_PATH_NAME_MAX + 1];
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
#endif

#ifndef BTRFS_IOC_DEFRAG
#define BTRFS_IOC_DEFRAG _IOW(BTRFS_IOCTL_MAGIC, 2, struct btrfs_ioctl_vol_args)
#endif

#ifndef BTRFS_IOC_DEV_INFO
#define BTRFS_IOC_DEV_INFO _IOWR(BTRFS_IOCTL_MAGIC, 30, \
                                 struct btrfs_ioctl_dev_info_args)
#endif

#ifndef BTRFS_IOC_FS_INFO
#define BTRFS_IOC_FS_INFO _IOR(BTRFS_IOCTL_MAGIC, 31, \
                               struct btrfs_ioctl_fs_info_args)
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

#define IFLA_BOND_MAX	(__IFLA_BOND_MAX - 1)
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

#if !HAVE_DECL_IFLA_VXLAN_LOCAL6
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
#define __IFLA_VXLAN_MAX 18

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
