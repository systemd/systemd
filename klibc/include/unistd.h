/*
 * unistd.h
 */

#ifndef _UNISTD_H
#define _UNISTD_H

#include <klibc/extern.h>
#include <klibc/compiler.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/select.h>

__extern char **environ;
__extern __noreturn _exit(int);

__extern pid_t fork(void);
__extern pid_t vfork(void);
__extern pid_t getpid(void);
__extern pid_t getpgid(pid_t);
__extern int setpgid(pid_t, pid_t);
__extern pid_t getppid(void);
__extern pid_t getpgrp(void);
__extern int setpgrp(void);
__extern pid_t setsid(void);
__extern pid_t getsid(pid_t);
__extern int execv(const char *, char * const *);
__extern int execvp(const char *, char * const *);
__extern int execve(const char *, char * const *, char * const *);
__extern int execvpe(const char *, char * const *, char * const *);
__extern int execl(const char *, const char *, ...);
__extern int execlp(const char *, const char *, ...);
__extern int execle(const char *, const char *, ...);
__extern int execlpe(const char *, const char *, ...);

__extern int setuid(uid_t);
__extern uid_t getuid(void);
__extern int seteuid(uid_t);
__extern uid_t geteuid(void);
__extern int setgid(gid_t);
__extern gid_t getgid(void); 
__extern int setegid(gid_t);
__extern gid_t getegid(void);
__extern int getgroups(int, gid_t *);
__extern int setgroups(size_t, const gid_t *);
__extern int setreuid(uid_t, uid_t);
__extern int setregid(gid_t, gid_t);
__extern int setresuid(uid_t, uid_t, uid_t);
__extern int setresgid(gid_t, gid_t, gid_t);
__extern int getfsuid(uid_t);
__extern int setfsuid(uid_t);

/* Macros for access() */
#define R_OK	4		/* Read */
#define W_OK	2		/* Write */
#define X_OK	1		/* Execute */
#define F_OK	0		/* Existence */

__extern int access(const char *, int);
__extern int link(const char *, const char *);
__extern int unlink(const char *);
__extern int chdir(const char *);
__extern int fchdir(int);
__extern int chmod(const char *, mode_t);
__extern int fchmod(int, mode_t);
__extern int mkdir(const char *, mode_t);
__extern int rmdir(const char *);
__extern int pipe(int *);
__extern int chroot(const char *);
__extern int symlink(const char *, const char *);
__extern int readlink(const char *, char *, size_t);
__extern int chown(const char *, uid_t, gid_t);
__extern int fchown(int, uid_t, gid_t);
__extern int lchown(const char *, uid_t, gid_t);
__extern char *getcwd(char *, size_t);

__extern int sync(void);

/* Also in <fcntl.h> */
#ifndef _KLIBC_IN_OPEN_C
__extern int open(const char *, int, ...);
#endif
__extern int close(int);
__extern off_t lseek(int, off_t, int);
/* off_t is 64 bits now even on 32-bit platforms; see llseek.c */
static __inline__ off_t llseek(int __f, off_t __o, int __w) {
  return lseek(__f, __o, __w);
}

__extern ssize_t read(int, void *, size_t);
__extern ssize_t write(int, const void *, size_t);
__extern ssize_t pread(int, void *, size_t, off_t);
__extern ssize_t pwrite(int, void *, size_t, off_t);

__extern int dup(int);
__extern int dup2(int, int);
__extern int fcntl(int, int, ...);
__extern int ioctl(int, int, void *);
__extern int flock(int, int);
__extern int fsync(int);
__extern int fdatasync(int);
__extern int ftruncate(int, off_t);

__extern int pause(void);
__extern unsigned int alarm(unsigned int);
__extern unsigned int sleep(unsigned int);
__extern void usleep(unsigned long);

__extern int gethostname(char *, size_t);
__extern int sethostname(const char *, size_t);
__extern int getdomainname(char *, size_t);
__extern int setdomainname(const char *, size_t);

__extern void *__brk(void *);
__extern int brk(void *);
__extern void *sbrk(ptrdiff_t);

__extern int getopt(int, char * const *, const char *);
__extern char *optarg;
__extern int optind, opterr, optopt;

__extern int isatty(int);

static __inline__ int getpagesize(void) {
  extern unsigned int __page_size;
  return __page_size;
}
static __inline__ int __getpageshift(void) {
  extern unsigned int __page_shift;
  return __page_shift;
}

__extern int daemon(int, int);

/* Standard file descriptor numbers. */
#define STDIN_FILENO	0
#define STDOUT_FILENO	1
#define STDERR_FILENO	2

#endif /* _UNISTD_H */
