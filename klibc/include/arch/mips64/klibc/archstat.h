#ifndef _KLIBC_ARCHSTAT_H
#define _KLIBC_ARCHSTAT_H

#define _STATBUF_ST_NSEC

struct stat {
	unsigned int		st_dev;
	unsigned int		st_pad0[3]; /* Reserved for st_dev expansion */

	unsigned long		st_ino;

	mode_t			st_mode;
	nlink_t			st_nlink;

	uid_t			st_uid;
	gid_t			st_gid;

	unsigned int		st_rdev;
	unsigned int		st_pad1[3]; /* Reserved for st_rdev expansion */

	off_t			st_size;
  
	struct timespec		st_atim;
	struct timespec		st_mtim;
	struct timespec		st_ctim;

	unsigned int		st_blksize;
	unsigned int		st_pad2;

	unsigned long		st_blocks;
};

#endif
