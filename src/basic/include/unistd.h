/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* The header defines _MIPS_SIM_ABI32 and friends, which used several places to determine mips architectures,
 * but musl does not include it in unistd.h. Let's include it explicitly. */
#ifdef ARCH_MIPS
#include <asm/sgidefs.h>
#endif

#include_next <unistd.h>

/* since glibc-2.34 */
#if !HAVE_CLOSE_RANGE
int close_range(unsigned first_fd, unsigned end_fd, unsigned flags);
#endif

/* since glibc-2.34 */
#if !HAVE_EXECVEAT
int execveat(int dirfd, const char *pathname,
             char *const argv[], char *const envp[],
             int flags);
#endif

#if !HAVE_PIVOT_ROOT
int pivot_root(const char *new_root, const char *put_old);
#endif
