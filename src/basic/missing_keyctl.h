/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <linux/keyctl.h>

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

#ifndef KEY_SPEC_USER_KEYRING
#define KEY_SPEC_USER_KEYRING -4
#endif

#ifndef KEY_SPEC_SESSION_KEYRING
#define KEY_SPEC_SESSION_KEYRING -3
#endif

/* From linux/key.h */
#ifndef KEY_POS_VIEW

typedef int32_t key_serial_t;

#define KEY_POS_VIEW    0x01000000
#define KEY_POS_READ    0x02000000
#define KEY_POS_WRITE   0x04000000
#define KEY_POS_SEARCH  0x08000000
#define KEY_POS_LINK    0x10000000
#define KEY_POS_SETATTR 0x20000000
#define KEY_POS_ALL     0x3f000000

#define KEY_USR_VIEW    0x00010000
#define KEY_USR_READ    0x00020000
#define KEY_USR_WRITE   0x00040000
#define KEY_USR_SEARCH  0x00080000
#define KEY_USR_LINK    0x00100000
#define KEY_USR_SETATTR 0x00200000
#define KEY_USR_ALL     0x003f0000

#define KEY_GRP_VIEW    0x00000100
#define KEY_GRP_READ    0x00000200
#define KEY_GRP_WRITE   0x00000400
#define KEY_GRP_SEARCH  0x00000800
#define KEY_GRP_LINK    0x00001000
#define KEY_GRP_SETATTR 0x00002000
#define KEY_GRP_ALL     0x00003f00

#define KEY_OTH_VIEW    0x00000001
#define KEY_OTH_READ    0x00000002
#define KEY_OTH_WRITE   0x00000004
#define KEY_OTH_SEARCH  0x00000008
#define KEY_OTH_LINK    0x00000010
#define KEY_OTH_SETATTR 0x00000020
#define KEY_OTH_ALL     0x0000003f
#endif
