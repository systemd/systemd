/*
 * Copyright (c) 2014-2015 The OpenRC Authors.
 * See the Authors file at the top-level directory of this distribution and
 * https://github.com/OpenRC/openrc/blob/master/AUTHORS
 *
 * This file is part of OpenRC. It is subject to the license terms in
 * the LICENSE file found in the top-level directory of this
 * distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
 * This file may not be copied, modified, propagated, or distributed
 *    except according to the terms contained in the LICENSE file.
 */

#ifndef RC_SELINUX_UTIL_H
#define RC_SELINUX_UTIL_H

#ifdef HAVE_SELINUX

int selinux_util_open(void);
int selinux_util_label(const char *path);
int selinux_util_close(void);

void selinux_setup(char **argv);

#else

/* always return false for selinux_util_open() */
#define selinux_util_open() (0)
#define selinux_util_label(x) do { } while (0)
#define selinux_util_close() do { } while (0)

#define selinux_setup(x) do { } while (0)

#endif


#endif
