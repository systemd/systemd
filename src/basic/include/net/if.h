/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <features.h>
#include <linux/if.h>   /* IWYU pragma: export */

#define IF_NAMESIZE       16

extern unsigned int if_nametoindex(const char *__ifname) __THROW;
extern char *if_indextoname(unsigned int __ifindex, char __ifname[IF_NAMESIZE]) __THROW;
