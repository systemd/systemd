#ifndef _KLIBC_ARCHSTAT_H
#define _KLIBC_ARCHSTAT_H

#define _STATBUF_ST_NSEC

/*
 * This matches struct stat64 in glibc2.1, hence the absolutely insane
 * amounts of padding around dev_t's.  The memory layout is the same as of
 * struct stat of the 64-bit kernel.
 */

struct stat {
	unsigned long	st_dev;
	unsigned long	st_pad0[3];	/* Reserved for st_dev expansion  */

	unsigned long long	st_ino;

	mode_t		st_mode;
	nlink_t		st_nlink;

	uid_t		st_uid;
	gid_t		st_gid;

	unsigned long	st_rdev;
	unsigned long	st_pad1[3];	/* Reserved for st_rdev expansion  */

	long long	st_size;

	struct timespec		st_atim;
	struct timespec		st_mtim;
	struct timespec		st_ctim;

	unsigned long	st_blksize;
	unsigned long	st_pad2;

	long long	st_blocks;
};

#endif
