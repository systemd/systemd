/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* To make struct xattr_args defined, which is used by setxattrat(). Note, the kernel header must be
 * included before the glibc header, otherwise the struct will not be defined. */
#include <linux/xattr.h>

#include_next <sys/xattr.h>
