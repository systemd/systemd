/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <features.h>

#ifdef __GLIBC__
#include <linux/if_arp.h> /* IWYU pragma: export */
#else
#include_next <net/if_arp.h>
#include <linux/if_ether.h>
#endif
