/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/stat.h>

#if !HAVE_FCHMODAT2
int fchmodat2(int dirfd, const char *path, mode_t mode, int flags);
#endif
