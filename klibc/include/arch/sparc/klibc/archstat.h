#ifndef _KLIBC_ARCHSTAT_H
#define _KLIBC_ARCHSTAT_H

#define _STATBUF_ST_NSEC

struct stat {
	unsigned long long st_dev;

	unsigned long long st_ino;

	unsigned int	st_mode;
	unsigned int	st_nlink;

	unsigned int	st_uid;
	unsigned int	st_gid;

	unsigned long long st_rdev;

	unsigned char	__pad3[8];

	long long	st_size;
	unsigned int	st_blksize;

	unsigned char	__pad4[8];
	unsigned int	st_blocks;

	struct timespec st_atim;
	struct timespec st_mtim;
	struct timespec st_ctim;

	unsigned int	__unused4;
	unsigned int	__unused5;
};

#endif
