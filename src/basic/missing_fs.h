/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* temporary undef definitions in bits/uio-ext.h, which is included by sys/uio.h */
#include <sys/uio.h>

#define __RWF_HIPRI_SAVED__     RWF_HIPRI
#undef RWF_HIPRI
#define __RWF_DSYNC_SAVED__     RWF_DSYNC
#undef RWF_DSYNC
#define __RWF_SYNC_SAVED__      RWF_SYNC
#undef RWF_SYNC
#define __RWF_NOWAIT_SAVED__    RWF_NOWAIT
#undef RWF_NOWAIT
#define __RWF_APPEND_SAVED__    RWF_APPEND
#undef RWF_APPEND
#define __RWF_NOAPPEND_SAVED__  RWF_NOAPPEND
#undef RWF_NOAPPEND
#if defined(RWF_ATOMIC)
#define __RWF_ATOMIC_SAVED__    RWF_ATOMIC
#undef RWF_ATOMIC
#else
#define __RWF_ATOMIC_SAVED__    0x00000040
#endif
#if defined(RWF_DONTCACHE)
#define __RWF_DONTCACHE_SAVED__ RWF_DONTCACHE
#undef RWF_DONTCACHE
#else
#define __RWF_DONTCACHE_SAVED__ 0x00000080
#endif

#include <linux/btrfs.h>
#include <linux/btrfs_tree.h>
#include <linux/fs.h>

#include "macro.h"

/* check RWF_xyz are redefined by linux/fs.h */
assert_cc(RWF_HIPRI     == __RWF_HIPRI_SAVED__);
assert_cc(RWF_DSYNC     == __RWF_DSYNC_SAVED__);
assert_cc(RWF_SYNC      == __RWF_SYNC_SAVED__);
assert_cc(RWF_NOWAIT    == __RWF_NOWAIT_SAVED__);
assert_cc(RWF_APPEND    == __RWF_APPEND_SAVED__);
assert_cc(RWF_NOAPPEND  == __RWF_NOAPPEND_SAVED__);
assert_cc(RWF_ATOMIC    == __RWF_ATOMIC_SAVED__);
assert_cc(RWF_DONTCACHE == __RWF_DONTCACHE_SAVED__);

/* Not exposed yet. Defined at fs/ext4/ext4.h */
#ifndef EXT4_IOC_RESIZE_FS
#define EXT4_IOC_RESIZE_FS _IOW('f', 16, __u64)
#endif

/* linux/fscrypt.h */
#ifndef FS_KEY_DESCRIPTOR_SIZE
#  define FS_KEY_DESCRIPTOR_SIZE 8
#else
assert_cc(FS_KEY_DESCRIPTOR_SIZE == 8);
#endif

/* linux/exportfs.h */
#ifndef FILEID_KERNFS
#define FILEID_KERNFS 0xfe
#endif
