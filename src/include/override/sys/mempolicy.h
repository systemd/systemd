/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/mempolicy.h>    /* IWYU pragma: export */

#if !HAVE_SET_MEMPOLICY
int missing_set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode);
#  define set_mempolicy missing_set_mempolicy
#endif

#if !HAVE_GET_MEMPOLICY
int missing_get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode, void *addr, unsigned long flags);
#  define get_mempolicy missing_get_mempolicy
#endif
