/*
 * arch/mips/include/klibc/archfcntl.h
 *
 * On MIPS, <asm/fcntl.h> isn't usable (compiling struct stat with
 * the correct definitions doesn't "just work"), so we need to provide
 * our own definitions.
 */

#ifndef _KLIBC_ARCHFCNTL_H
#define _KLIBC_ARCHFCNTL_H

#ifdef _ASM_FCNTL_H		/* We were too late! */
# error "<asm/fcntl.h> included before <klibc/archfcntl.h>"
#endif
#define _ASM_FCNTL_H		/* Keep <asm/fcntl.h> from getting included */

#define O_ACCMODE	0x0003
#define O_RDONLY	0x0000
#define O_WRONLY	0x0001
#define O_RDWR		0x0002
#define O_APPEND	0x0008
#define O_SYNC		0x0010
#define O_NONBLOCK	0x0080
#define O_CREAT         0x0100
#define O_TRUNC		0x0200
#define O_EXCL		0x0400
#define O_NOCTTY	0x0800
#define FASYNC		0x1000
#define O_LARGEFILE	0x2000
#define O_DIRECT	0x8000
#define O_DIRECTORY	0x10000
#define O_NOFOLLOW	0x20000
#define O_NOATIME	0x40000

#define O_NDELAY	O_NONBLOCK

#define F_DUPFD		0
#define F_GETFD		1
#define F_SETFD		2
#define F_GETFL		3
#define F_SETFL		4
#define F_GETLK		14
#define F_SETLK		6
#define F_SETLKW	7

#define F_SETOWN	24
#define F_GETOWN	23
#define F_SETSIG	10
#define F_GETSIG	11

#define F_GETLK64	33
#define F_SETLK64	34
#define F_SETLKW64	35

#define FD_CLOEXEC	1

#define F_RDLCK		0
#define F_WRLCK		1
#define F_UNLCK		2

#define F_EXLCK		4
#define F_SHLCK		8

#define F_INPROGRESS	16

#define LOCK_SH		1
#define LOCK_EX		2
#define LOCK_NB		4
#define LOCK_UN		8

#define LOCK_MAND	32
#define LOCK_READ	64
#define LOCK_WRITE	128
#define LOCK_RW		192

typedef struct flock {
	short	l_type;
	short	l_whence;
	loff_t	l_start;
	loff_t	l_len;
	pid_t	l_pid;
} flock_t;

#define F_LINUX_SPECIFIC_BASE	1024

#endif /* _KLIBC_ARCHFCNTL_H */

