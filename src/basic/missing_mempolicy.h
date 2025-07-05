/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/mempolicy.h>    /* IWYU pragma: export */

#if !HAVE_SET_MEMPOLICY
int set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode);
#endif

#if !HAVE_GET_MEMPOLICY
int get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode, void *addr, unsigned long flags);
#endif
