/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/stat.h>

#include <assert.h>
#include <stddef.h>

/* musl's sys/stat.h does not include linux/stat.h, and unfortunately they conflict with each other.
 * Hence, some relatively new macros need to be explicitly defined here. */

/* Before 23ab04a8630225371455d5f4538fd078665bb646, statx.stx_mnt_id is not defined. */
#ifndef STATX_MNT_ID
static_assert(offsetof(struct statx, __pad1) == offsetof(struct statx, stx_dev_minor) + sizeof(uint32_t), "");
#define stx_mnt_id __pad1[0]
#endif

#ifndef STATX_MNT_ID
#define STATX_MNT_ID            0x00001000U
#endif
#ifndef STATX_DIOALIGN
#define STATX_DIOALIGN          0x00002000U
#endif
#ifndef STATX_MNT_ID_UNIQUE
#define STATX_MNT_ID_UNIQUE     0x00004000U
#endif
#ifndef STATX_SUBVOL
#define STATX_SUBVOL            0x00008000U
#endif
#ifndef STATX_WRITE_ATOMIC
#define STATX_WRITE_ATOMIC      0x00010000U
#endif
#ifndef STATX_DIO_READ_ALIGN
#define STATX_DIO_READ_ALIGN    0x00020000U
#endif

#ifndef STATX_ATTR_COMPRESSED
#define STATX_ATTR_COMPRESSED   0x00000004
#endif
#ifndef STATX_ATTR_IMMUTABLE
#define STATX_ATTR_IMMUTABLE    0x00000010
#endif
#ifndef STATX_ATTR_APPEND
#define STATX_ATTR_APPEND       0x00000020
#endif
#ifndef STATX_ATTR_NODUMP
#define STATX_ATTR_NODUMP       0x00000040
#endif
#ifndef STATX_ATTR_ENCRYPTED
#define STATX_ATTR_ENCRYPTED    0x00000800
#endif
#ifndef STATX_ATTR_AUTOMOUNT
#define STATX_ATTR_AUTOMOUNT    0x00001000
#endif
#ifndef STATX_ATTR_MOUNT_ROOT
#define STATX_ATTR_MOUNT_ROOT   0x00002000
#endif
#ifndef STATX_ATTR_VERITY
#define STATX_ATTR_VERITY       0x00100000
#endif
#ifndef STATX_ATTR_DAX
#define STATX_ATTR_DAX          0x00200000
#endif
#ifndef STATX_ATTR_WRITE_ATOMIC
#define STATX_ATTR_WRITE_ATOMIC 0x00400000
#endif
