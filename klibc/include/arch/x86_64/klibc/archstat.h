#ifndef _KLIBC_ARCHSTAT_H
#define _KLIBC_ARCHSTAT_H

#define _STATBUF_ST_NSEC

struct stat {
	unsigned long	st_dev;
	unsigned long	st_ino;
	unsigned long	st_nlink;

	unsigned int	st_mode;
	unsigned int	st_uid;
	unsigned int	st_gid;
	unsigned int	__pad0;
	unsigned long	st_rdev;
	long		st_size;
	long		st_blksize;
	long		st_blocks;	/* Number 512-byte blocks allocated. */

	struct timespec st_atim;
	struct timespec st_mtim;
	struct timespec st_ctim;
  	long		__unused[3];
};

#endif
