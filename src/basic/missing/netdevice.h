/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/netdevice.h>

#ifndef NET_ADDR_RANDOM /* 339e022396d58f4b4f9b4200ea5309768934bb33 (3.15) */
#define NET_ADDR_RANDOM 1
#endif

#ifndef NET_NAME_UNKNOWN /* 685343fc3ba61a1f6eef361b786601123db16c28 (3.17) */
#define NET_NAME_UNKNOWN     0
#define NET_NAME_ENUM        1
#define NET_NAME_PREDICTABLE 2
#define NET_NAME_USER        3
#define NET_NAME_RENAMED     4
#endif
