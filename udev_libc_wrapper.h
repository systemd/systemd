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

#ifdef asmlinkage
# undef asmlinkage
#endif
#ifdef __i386__
# define asmlinkage	__attribute__((regparm(0)))
#endif
#ifndef asmlinkage
# define asmlinkage
#endif

#include <string.h>

extern uid_t lookup_user(const char *user);
extern gid_t lookup_group(const char *group);

#ifndef strlcat
extern size_t strlcpy(char *dst, const char *src, size_t size);
#endif

#ifndef strlcat
extern size_t strlcat(char *dst, const char *src, size_t size);
#endif

#endif /* _UDEV_LIBC_WRAPPER_H_ */
