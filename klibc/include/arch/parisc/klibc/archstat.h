#ifndef _KLIBC_ARCHSTAT_H
#define _KLIBC_ARCHSTAT_H

#define _STATBUF_ST_NSEC

struct stat {
	unsigned long long	st_dev;
	unsigned int		__pad1;

	unsigned int		__st_ino;	/* Not actually filled in */
	unsigned int		st_mode;
	unsigned int		st_nlink;
	unsigned int		st_uid;
	unsigned int		st_gid;
	unsigned long long	st_rdev;
	unsigned int		__pad2;
	signed long long	st_size;
	signed int		st_blksize;

	signed long long	st_blocks;
	struct timespec		st_atim;
	struct timespec		st_mtim;
	struct timespec		st_ctim;
	unsigned long long	st_ino;
};

#endif
