/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <stdio.h>

#if !HAVE_RENAMEAT2
#define RENAME_NOREPLACE (1 << 0)
#define RENAME_EXCHANGE  (1 << 1)
#define RENAME_WHITEOUT  (1 << 2)

int renameat2(int __oldfd, const char *__old, int __newfd, const char *__new, unsigned int __flags);
#endif
