#ifndef _KLIBC_ARCHSTAT_H
#define _KLIBC_ARCHSTAT_H

#include <endian.h>

#define _STATBUF_ST_NSEC

/* This matches struct stat64 in glibc2.1, hence the absolutely
 * insane amounts of padding around dev_t's.
 */
struct stat64 {
	unsigned long long	st_dev;
	unsigned char	__pad0[4];

	unsigned long	st_ino;
	unsigned int	st_mode;
	unsigned int	st_nlink;

	unsigned long	st_uid;
	unsigned long	st_gid;

	unsigned long long	st_rdev;
	unsigned char	__pad3[4];

	long long	st_size;
	unsigned long	st_blksize;

#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned long	__pad4;		/* Future possible st_blocks hi bits */
	unsigned long	st_blocks;	/* Number 512-byte blocks allocated. */
#else /* Must be little */
	unsigned long	st_blocks;	/* Number 512-byte blocks allocated. */
	unsigned long	__pad4;		/* Future possible st_blocks hi bits */
#endif

	struct timespec	st_atim;
	struct timespec st_mtim;
	struct timespec st_ctim;

	unsigned long	__unused1;
	unsigned long	__unused2;
};

#endif

