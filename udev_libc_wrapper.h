/*
 * udev_libc_wrapper - wrapping of functions missing in a specific libc
 *		       or not working in a statically compiled binary
 *
 * Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef _UDEV_LIBC_WRAPPER_H_
#define _UDEV_LIBC_WRAPPER_H_

#undef asmlinkage
#ifdef __i386__
#define asmlinkage	__attribute__((regparm(0)))
#else
#define asmlinkage
#endif

#ifndef __FD_SET
#define __FD_SET(d, set) ((set)->fds_bits[__FDELT(d)] |= __FDMASK(d))
#endif
#ifndef __FD_CLR
#define __FD_CLR(d, set) ((set)->fds_bits[__FDELT(d)] &= ~__FDMASK(d))
#endif
#ifndef __FD_ISSET
#define __FD_ISSET(d, set) (((set)->fds_bits[__FDELT(d)] & __FDMASK(d)) != 0)
#endif
#ifndef __FD_ZERO
#define __FD_ZERO(set) ((void) memset ((void*) (set), 0, sizeof (fd_set)))
#endif

#include <string.h>

#ifdef __KLIBC__
static inline int clearenv(void)
{
	environ[0] = NULL;
	return 0;
}
#endif

extern uid_t lookup_user(const char *user);
extern gid_t lookup_group(const char *group);

extern size_t strlcpy(char *dst, const char *src, size_t size);
extern size_t strlcat(char *dst, const char *src, size_t size);

#endif /* _UDEV_LIBC_WRAPPER_H_ */
