/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/mempolicy.h>    /* IWYU pragma: export */

int set_mempolicy_shim(int mode, const unsigned long *nodemask, unsigned long maxnode);
#define set_mempolicy set_mempolicy_shim

int get_mempolicy_shim(int *mode, unsigned long *nodemask, unsigned long maxnode, void *addr, unsigned long flags);
#define get_mempolicy get_mempolicy_shim
