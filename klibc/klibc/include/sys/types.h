/*
 * sys/types.h
 */

#ifndef _SYS_TYPES_H
#define _SYS_TYPES_H

#include <stddef.h>
#include <stdint.h>

#define _SSIZE_T
typedef ptrdiff_t ssize_t;

#include <linux/posix_types.h>
#include <asm/types.h>

/* Keeps linux/types.h from getting included elsewhere */
#define _LINUX_TYPES_H		

typedef __kernel_fd_set		fd_set;
typedef uint32_t		dev_t;
typedef __kernel_ino_t		ino_t;
typedef __kernel_mode_t		mode_t;
typedef __kernel_nlink_t	nlink_t;
typedef __kernel_off_t		off_t; /* Should become __kernel_loff_t... */
typedef __kernel_pid_t		pid_t;
typedef __kernel_daddr_t	daddr_t;
typedef __kernel_key_t		key_t;
typedef __kernel_suseconds_t	suseconds_t;
typedef __kernel_timer_t	timer_t;

typedef __kernel_uid32_t	uid_t;
typedef __kernel_gid32_t	gid_t;

typedef __kernel_loff_t		loff_t;

/*
 * The following typedefs are also protected by individual ifdefs for
 * historical reasons:
 */
#ifndef _SIZE_T
#define _SIZE_T
typedef __kernel_size_t		size_t;
#endif

#ifndef _SSIZE_T
#define _SSIZE_T
typedef __kernel_ssize_t	ssize_t;
#endif

#ifndef _PTRDIFF_T
#define _PTRDIFF_T
typedef __kernel_ptrdiff_t	ptrdiff_t;
#endif

#ifndef _TIME_T
#define _TIME_T
typedef __kernel_time_t		time_t;
#endif

#ifndef _CLOCK_T
#define _CLOCK_T
typedef __kernel_clock_t	clock_t;
#endif

#ifndef _CADDR_T
#define _CADDR_T
typedef __kernel_caddr_t	caddr_t;
#endif

/* bsd */
typedef unsigned char		u_char;
typedef unsigned short		u_short;
typedef unsigned int		u_int;
typedef unsigned long		u_long;

/* sysv */
typedef unsigned char		unchar;
typedef unsigned short		ushort;
typedef unsigned int		uint;
typedef unsigned long		ulong;

/* Linux-specific? */
typedef uint8_t			u_int8_t;
typedef uint16_t		u_int16_t;
typedef uint32_t 		u_int32_t;
typedef uint64_t		u_int64_t;

/*
 * transition to 64-bit sector_t, possibly making it an option...
 */
#undef BLK_64BIT_SECTOR

#ifdef BLK_64BIT_SECTOR
typedef u64 sector_t;
#else
typedef unsigned long sector_t;
#endif

/*
 * The type of an index into the pagecache.  Use a #define so asm/types.h
 * can override it.
 */
#ifndef pgoff_t
#define pgoff_t unsigned long
#endif

/*
 * Below are truly Linux-specific types that should never collide with
 * any application/library that wants linux/types.h.
 */

struct ustat {
	__kernel_daddr_t	f_tfree;
	__kernel_ino_t		f_tinode;
	char			f_fname[6];
	char			f_fpack[6];
};

/*
 * Some apps want this in <sys/types.h>
 */
#include <sys/sysmacros.h>

#endif
