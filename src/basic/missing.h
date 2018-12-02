/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/* Missing glibc definitions to access certain kernel APIs */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/falloc.h>
#include <linux/input.h>
#include <linux/oom.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <uchar.h>
#include <unistd.h>

#if WANT_LINUX_STAT_H
#include <linux/stat.h>
#endif

#if HAVE_AUDIT
#include <libaudit.h>
#endif

#ifdef ARCH_MIPS
#include <asm/sgidefs.h>
#endif

#if HAVE_LINUX_BTRFS_H
#include <linux/btrfs.h>
#endif

#if HAVE_LINUX_VM_SOCKETS_H
#include <linux/vm_sockets.h>
#else
#define VMADDR_CID_ANY -1U
struct sockaddr_vm {
        unsigned short svm_family;
        unsigned short svm_reserved1;
        unsigned int svm_port;
        unsigned int svm_cid;
        unsigned char svm_zero[sizeof(struct sockaddr) -
                               sizeof(unsigned short) -
                               sizeof(unsigned short) -
                               sizeof(unsigned int) -
                               sizeof(unsigned int)];
};
#endif /* !HAVE_LINUX_VM_SOCKETS_H */

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

#ifndef FS_NOCOW_FL
#define FS_NOCOW_FL 0x00800000
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

#if !HAVE_LINUX_BTRFS_H
#define BTRFS_IOC_QGROUP_ASSIGN _IOW(BTRFS_IOCTL_MAGIC, 41, \
                               struct btrfs_ioctl_qgroup_assign_args)
#define BTRFS_IOC_QGROUP_CREATE _IOW(BTRFS_IOCTL_MAGIC, 42, \
                               struct btrfs_ioctl_qgroup_create_args)
#define BTRFS_IOC_QUOTA_RESCAN _IOW(BTRFS_IOCTL_MAGIC, 44, \
                               struct btrfs_ioctl_quota_rescan_args)
#define BTRFS_IOC_QUOTA_RESCAN_STATUS _IOR(BTRFS_IOCTL_MAGIC, 45, \
                               struct btrfs_ioctl_quota_rescan_args)

struct btrfs_ioctl_quota_rescan_args {
        __u64   flags;
        __u64   progress;
        __u64   reserved[6];
};

struct btrfs_ioctl_qgroup_assign_args {
        __u64 assign;
        __u64 src;
        __u64 dst;
};

struct btrfs_ioctl_qgroup_create_args {
        __u64 create;
        __u64 qgroupid;
};

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
#endif /* !HAVE_LINUX_BTRFS_H */

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

#ifndef OCFS2_SUPER_MAGIC
#define OCFS2_SUPER_MAGIC 0x7461636f
#endif

#ifndef MS_MOVE
#define MS_MOVE 8192
#endif

#ifndef MS_REC
#define MS_REC 16384
#endif

#ifndef MS_PRIVATE
#define MS_PRIVATE      (1<<18)
#endif

#ifndef MS_REC
#define MS_REC          (1<<19)
#endif

#ifndef MS_SHARED
#define MS_SHARED       (1<<20)
#endif

#ifndef MS_RELATIME
#define MS_RELATIME     (1<<21)
#endif

#ifndef MS_KERNMOUNT
#define MS_KERNMOUNT    (1<<22)
#endif

#ifndef MS_I_VERSION
#define MS_I_VERSION    (1<<23)
#endif

#ifndef MS_STRICTATIME
#define MS_STRICTATIME  (1<<24)
#endif

#ifndef MS_LAZYTIME
#define MS_LAZYTIME     (1<<25)
#endif

#ifndef SCM_SECURITY
#define SCM_SECURITY 0x03
#endif

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef PR_SET_CHILD_SUBREAPER
#define PR_SET_CHILD_SUBREAPER 36
#endif

#ifndef PR_SET_MM_ARG_START
#define PR_SET_MM_ARG_START 8
#endif

#ifndef PR_SET_MM_ARG_END
#define PR_SET_MM_ARG_END 9
#endif

#ifndef PR_SET_MM_ENV_START
#define PR_SET_MM_ENV_START 10
#endif

#ifndef PR_SET_MM_ENV_END
#define PR_SET_MM_ENV_END 11
#endif

#ifndef EFIVARFS_MAGIC
#define EFIVARFS_MAGIC 0xde5e81e4
#endif

#ifndef SMACK_MAGIC
#define SMACK_MAGIC 0x43415d53
#endif

#ifndef DM_DEFERRED_REMOVE
#define DM_DEFERRED_REMOVE (1 << 17)
#endif

#ifndef MAX_HANDLE_SZ
#define MAX_HANDLE_SZ 128
#endif

#if ! HAVE_SECURE_GETENV
#  if HAVE___SECURE_GETENV
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

#ifndef SO_PEERGROUPS
#  define SO_PEERGROUPS 59
#endif

#ifndef EVIOCREVOKE
#  define EVIOCREVOKE _IOW('E', 0x91, int)
#endif

#ifndef EVIOCSMASK

struct input_mask {
        uint32_t type;
        uint32_t codes_size;
        uint64_t codes_ptr;
};

#define EVIOCSMASK _IOW('E', 0x93, struct input_mask)
#endif

#ifndef DRM_IOCTL_SET_MASTER
#  define DRM_IOCTL_SET_MASTER _IO('d', 0x1e)
#endif

#ifndef DRM_IOCTL_DROP_MASTER
#  define DRM_IOCTL_DROP_MASTER _IO('d', 0x1f)
#endif

/* The precise definition of __O_TMPFILE is arch specific; use the
 * values defined by the kernel (note: some are hexa, some are octal,
 * duplicated as-is from the kernel definitions):
 * - alpha, parisc, sparc: each has a specific value;
 * - others: they use the "generic" value.
 */

#ifndef __O_TMPFILE
#if defined(__alpha__)
#define __O_TMPFILE     0100000000
#elif defined(__parisc__) || defined(__hppa__)
#define __O_TMPFILE     0400000000
#elif defined(__sparc__) || defined(__sparc64__)
#define __O_TMPFILE     0x2000000
#else
#define __O_TMPFILE     020000000
#endif
#endif

/* a horrid kludge trying to make sure that this will fail on old kernels */
#ifndef O_TMPFILE
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#endif

#ifndef BPF_XOR
#define BPF_XOR 0xa0
#endif

/* Note that LOOPBACK_IFINDEX is currently not exported by the
 * kernel/glibc, but hardcoded internally by the kernel.  However, as
 * it is exported to userspace indirectly via rtnetlink and the
 * ioctls, and made use of widely we define it here too, in a way that
 * is compatible with the kernel's internal definition. */
#ifndef LOOPBACK_IFINDEX
#define LOOPBACK_IFINDEX 1
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

#ifndef BTN_DPAD_UP
#define BTN_DPAD_UP 0x220
#define BTN_DPAD_RIGHT 0x223
#endif

#ifndef KEY_ALS_TOGGLE
#define KEY_ALS_TOGGLE 0x230
#endif

typedef int32_t key_serial_t;

#ifndef KEYCTL_JOIN_SESSION_KEYRING
#define KEYCTL_JOIN_SESSION_KEYRING 1
#endif

#ifndef KEYCTL_CHOWN
#define KEYCTL_CHOWN 4
#endif

#ifndef KEYCTL_SETPERM
#define KEYCTL_SETPERM 5
#endif

#ifndef KEYCTL_DESCRIBE
#define KEYCTL_DESCRIBE 6
#endif

#ifndef KEYCTL_LINK
#define KEYCTL_LINK 8
#endif

#ifndef KEYCTL_READ
#define KEYCTL_READ 11
#endif

#ifndef KEYCTL_SET_TIMEOUT
#define KEYCTL_SET_TIMEOUT 15
#endif

#ifndef KEY_POS_VIEW
#define KEY_POS_VIEW    0x01000000
#define KEY_POS_READ    0x02000000
#define KEY_POS_WRITE   0x04000000
#define KEY_POS_SEARCH  0x08000000
#define KEY_POS_LINK    0x10000000
#define KEY_POS_SETATTR 0x20000000

#define KEY_USR_VIEW    0x00010000
#define KEY_USR_READ    0x00020000
#define KEY_USR_WRITE   0x00040000
#define KEY_USR_SEARCH  0x00080000
#define KEY_USR_LINK    0x00100000
#define KEY_USR_SETATTR 0x00200000

#define KEY_GRP_VIEW    0x00000100
#define KEY_GRP_READ    0x00000200
#define KEY_GRP_WRITE   0x00000400
#define KEY_GRP_SEARCH  0x00000800
#define KEY_GRP_LINK    0x00001000
#define KEY_GRP_SETATTR 0x00002000

#define KEY_OTH_VIEW    0x00000001
#define KEY_OTH_READ    0x00000002
#define KEY_OTH_WRITE   0x00000004
#define KEY_OTH_SEARCH  0x00000008
#define KEY_OTH_LINK    0x00000010
#define KEY_OTH_SETATTR 0x00000020
#endif

#ifndef KEY_SPEC_USER_KEYRING
#define KEY_SPEC_USER_KEYRING -4
#endif

#ifndef KEY_SPEC_SESSION_KEYRING
#define KEY_SPEC_SESSION_KEYRING -3
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

#if !HAVE_CHAR32_T
#define char32_t uint32_t
#endif

#if !HAVE_CHAR16_T
#define char16_t uint16_t
#endif

#ifndef ETHERTYPE_LLDP
#define ETHERTYPE_LLDP 0x88cc
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

#ifndef EXT4_IOC_RESIZE_FS
#  define EXT4_IOC_RESIZE_FS              _IOW('f', 16, __u64)
#endif

#ifndef NSFS_MAGIC
#define NSFS_MAGIC 0x6e736673
#endif

#ifndef NS_GET_NSTYPE
#define NS_GET_NSTYPE _IO(0xb7, 0x3)
#endif

#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE 0x01
#endif

#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE 0x02
#endif

#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000
#endif

#if ! HAVE_STRUCT_STATX
struct statx_timestamp {
        int64_t tv_sec;
        uint32_t tv_nsec;
        uint32_t __reserved;
};
struct statx {
        uint32_t stx_mask;
        uint32_t stx_blksize;
        uint64_t stx_attributes;
        uint32_t stx_nlink;
        uint32_t stx_uid;
        uint32_t stx_gid;
        uint16_t stx_mode;
        uint16_t __spare0[1];
        uint64_t stx_ino;
        uint64_t stx_size;
        uint64_t stx_blocks;
        uint64_t stx_attributes_mask;
        struct statx_timestamp stx_atime;
        struct statx_timestamp stx_btime;
        struct statx_timestamp stx_ctime;
        struct statx_timestamp stx_mtime;
        uint32_t stx_rdev_major;
        uint32_t stx_rdev_minor;
        uint32_t stx_dev_major;
        uint32_t stx_dev_minor;
        uint64_t __spare2[14];
};
#endif

#ifndef STATX_BTIME
#define STATX_BTIME 0x00000800U
#endif

#ifndef AT_STATX_DONT_SYNC
#define AT_STATX_DONT_SYNC 0x4000
#endif

/* The maximum thread/process name length including trailing NUL byte. This mimics the kernel definition of the same
 * name, which we need in userspace at various places but is not defined in userspace currently, neither under this
 * name nor any other. */
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#include "missing_network.h"
#include "missing_syscall.h"
