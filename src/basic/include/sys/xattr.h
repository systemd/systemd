/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* To make struct sched_attr which is defined in glibc header since glibc-2.41. Note, the kernel header needs
 * to be included before the glibc header, otherwise they conflict with each other. */
#include <linux/xattr.h>

#include_next <sys/xattr.h>
