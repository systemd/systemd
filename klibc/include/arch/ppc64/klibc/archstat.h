#ifndef _KLIBC_ARCHSTAT_H
#define _KLIBC_ARCHSTAT_H

#define _STATBUF_ST_NSEC

struct stat {
	unsigned long	st_dev;
	ino_t		st_ino;
	nlink_t		st_nlink;
	mode_t		st_mode;
	uid_t 		st_uid;
	gid_t 		st_gid;
	unsigned long	st_rdev;
	off_t		st_size;
	unsigned long  	st_blksize;
	unsigned long  	st_blocks;
	struct timespec st_atim;	/* Time of last access.  */
	struct timespec st_mtim;	/* Time of last modification.  */
	struct timespec st_ctim;	/* Time of last status change.  */
	unsigned long  	__unused4;
	unsigned long  	__unused5;
	unsigned long  	__unused6;
};

#endif
