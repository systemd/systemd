#ifndef _KLIBC_ARCHSTAT_H
#define _KLIBC_ARCHSTAT_H

#define _STATBUF_ST_NSEC

/* This matches struct stat64 in glibc2.1.
 */
struct stat {
	unsigned long long st_dev; 	/* Device.  */
	unsigned long long st_ino;	/* File serial number.  */
	unsigned int st_mode;		/* File mode.  */
	unsigned int st_nlink;		/* Link count.  */
	unsigned int st_uid;		/* User ID of the file's owner.  */
	unsigned int st_gid;		/* Group ID of the file's group. */
	unsigned long long st_rdev; 	/* Device number, if device.  */
	unsigned short int __pad2;
	long long st_size;		/* Size of file, in bytes.  */
	long st_blksize;		/* Optimal block size for I/O.  */

	long long st_blocks;		/* Number 512-byte blocks allocated. */
	struct timespec st_atim;	/* Time of last access.  */
	struct timespec st_mtim;	/* Time of last modification.  */
	struct timespec st_ctim;	/* Time of last status change.  */
	unsigned long int __unused4;
	unsigned long int __unused5;
};

#endif
