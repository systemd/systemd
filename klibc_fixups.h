#ifdef __KLIBC__

#ifndef KLIBC_FIXUPS_H
#define KLIBC_FIXUPS_H

#include <linux/kernel.h>
#include <linux/unistd.h>

int sysinfo(struct sysinfo *info);

struct passwd {
	char	*pw_name;	/* user name */
	char	*pw_passwd;	/* user password */
	uid_t	pw_uid;		/* user id */
	gid_t	pw_gid;		/* group id */
	char	*pw_gecos;	/* real name */
	char	*pw_dir;	/* home directory */
	char	*pw_shell;	/* shell program */
};

struct group {
	char	*gr_name;	/* group name */
	char	*gr_passwd;	/* group password */
	gid_t	gr_gid;		/* group id */
	char	**gr_mem;	/* group members */
};

struct passwd *getpwnam(const char *name);
struct group *getgrnam(const char *name);


#define UT_LINESIZE		32
#define UT_NAMESIZE		32
#define UT_HOSTSIZE		256
#define USER_PROCESS		7	/* normal process */
#define ut_time			ut_tv.tv_sec


extern int ufd;

struct exit_status {
	short int e_termination;	/* process termination status */
	short int e_exit;		/* process exit status */
};

struct utmp
{
	short int ut_type;		/* type of login */
	pid_t ut_pid;			/* pid of login process */
	char ut_line[UT_LINESIZE];	/* devicename */
	char ut_id[4];			/* Inittab id  */
	char ut_user[UT_NAMESIZE];	/* username  */
	char ut_host[UT_HOSTSIZE];	/* hostname for remote login */
	struct exit_status ut_exit;	/* exit status of a process marked as DEAD_PROCESS */
	/* The ut_session and ut_tv fields must be the same size for 32 and 64-bit */
#if __WORDSIZE == 64 && defined __WORDSIZE_COMPAT32
	int32_t ut_session;		/* sid used for windowing */
	struct {
		int32_t tv_sec;		/* seconds */
		int32_t tv_usec;	/* microseconds */
	} ut_tv;
#else
	long int ut_session;
	struct timeval ut_tv;
#endif
	int32_t ut_addr_v6[4];		/* internet address of remote host */
	char __unused[20];		/* reserved for future use */
};

struct utmp *getutent(void);
void setutent(void);
void endutent(void);


#endif /* KLIBC_FIXUPS_H */
#endif /* __KLIBC__ */
