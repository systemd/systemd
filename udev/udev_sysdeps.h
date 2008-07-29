/*
 * wrapping of libc features and kernel interfaces
 *
 * Copyright (C) 2005-2006 Kay Sievers <kay.sievers@vrfy.org>
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
 *	51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#ifndef _UDEV_SYSDEPS_H_
#define _UDEV_SYSDEPS_H_

#include <string.h>
#include <unistd.h>
#include <stdint.h>

/* needed until Inotify! syscalls reach glibc */
#include <sys/syscall.h>
#ifndef __NR_inotify_init
#if defined(__i386__)
# define __NR_inotify_init	291
# define __NR_inotify_add_watch	292
# define __NR_inotify_rm_watch	293
#elif defined(__x86_64__)
# define __NR_inotify_init	253
# define __NR_inotify_add_watch	254
# define __NR_inotify_rm_watch	255
#elif defined(__powerpc__) || defined(__powerpc64__)
# define __NR_inotify_init	275
# define __NR_inotify_add_watch	276
# define __NR_inotify_rm_watch	277
#elif defined (__ia64__)
# define __NR_inotify_init	1277
# define __NR_inotify_add_watch	1278
# define __NR_inotify_rm_watch	1279
#elif defined (__s390__)
# define __NR_inotify_init	284
# define __NR_inotify_add_watch	285
# define __NR_inotify_rm_watch	286
#elif defined (__alpha__)
# define __NR_inotify_init	444
# define __NR_inotify_add_watch	445
# define __NR_inotify_rm_watch	446
#elif defined (__sparc__) || defined (__sparc64__)
# define __NR_inotify_init	151
# define __NR_inotify_add_watch	152
# define __NR_inotify_rm_watch	156
#elif defined (__arm__)
# define __NR_inotify_init	__NR_SYSCALL_BASE+316
# define __NR_inotify_add_watch	__NR_SYSCALL_BASE+317
# define __NR_inotify_rm_watch	__NR_SYSCALL_BASE+318
#elif defined (__sh__)
# define __NR_inotify_init	290
# define __NR_inotify_add_watch	291
# define __NR_inotify_rm_watch	292
#elif defined (__m32r__)
# define __NR_inotify_init	290
# define __NR_inotify_add_watch	291
# define __NR_inotify_rm_watch	292
#elif defined (__hppa__)
# define __NR_inotify_init      269
# define __NR_inotify_add_watch 270
# define __NR_inotify_rm_watch  271
#elif defined (__mips__)
# include <sgidefs.h>
# if _MIPS_SIM == _MIPS_SIM_ABI32
#  define __NR_Linux             4000
#  define __NR_inotify_init      (__NR_Linux + 284)
#  define __NR_inotify_add_watch (__NR_Linux + 285)
#  define __NR_inotify_rm_watch  (__NR_Linux + 286)
# elif _MIPS_SIM == _MIPS_SIM_ABI64
#  define __NR_Linux             5000
#  define __NR_inotify_init      (__NR_Linux + 243)
#  define __NR_inotify_add_watch (__NR_Linux + 244)
#  define __NR_inotify_rm_watch  (__NR_Linux + 245)
# elif _MIPS_SIM == _MIPS_SIM_NABI32
#  define __NR_Linux             6000
#  define __NR_inotify_init      (__NR_Linux + 247)
#  define __NR_inotify_add_watch (__NR_Linux + 248)
#  define __NR_inotify_rm_watch  (__NR_Linux + 249)
# endif
#else
#warning "inotify unsupported on this architecture!"
#endif
#endif /* __NR_inotify_init */

/* dummy if we don't have the syscalls defined */
#ifndef __NR_inotify_init
static inline int inotify_init(void)
{
	return -1;
}

static inline int inotify_add_watch(int fd, const char *name, uint32_t mask)
{
	return -1;
}
#else
/* needed until /usr/include/sys/inotify.h is working */
#ifndef __GLIBC__
#include <sys/inotify.h>
#else
static inline int inotify_init(void)
{
	return syscall(__NR_inotify_init);
}

static inline int inotify_add_watch(int fd, const char *name, uint32_t mask)
{
	return syscall(__NR_inotify_add_watch, fd, name, mask);
}
#endif /* __GLIBC__ */
#endif /* __NR_inotify_init */

#ifndef IN_CREATE
#define IN_CREATE		0x00000100	/* Subfile was created */
#define IN_MOVED_FROM		0x00000040	/* File was moved from X */
#define IN_MOVED_TO		0x00000080	/* File was moved to Y */
#define IN_DELETE		0x00000200	/* Subfile was deleted */
#define IN_CLOSE_WRITE		0x00000008	/* Writtable file was closed */
#define IN_MOVE			(IN_MOVED_FROM | IN_MOVED_TO) /* moves */
#endif /* IN_CREATE */

/* needed for our signal handlers to work */
#undef asmlinkage
#ifdef __i386__
#define asmlinkage	__attribute__((regparm(0)))
#else
#define asmlinkage
#endif /* __i386__ */

/* headers are broken on some architectures */
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

#ifndef NETLINK_KOBJECT_UEVENT
#define NETLINK_KOBJECT_UEVENT	15
#endif

#ifndef SO_RCVBUFFORCE
#if defined(__alpha__) || defined(__hppa__) || defined(__sparc__) || defined(__sparc_v9__)
#define SO_RCVBUFFORCE 0x100b
#else
#define SO_RCVBUFFORCE 33
#endif
#endif

extern size_t strlcpy(char *dst, const char *src, size_t size);
extern size_t strlcat(char *dst, const char *src, size_t size);

#endif
