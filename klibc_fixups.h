#ifdef __KLIBC__

#ifndef KLIBC_FIXUPS_H
#define KLIBC_FIXUPS_H 


#define WTERMSIG(status)	((status) & 0x7f)
#define WEXITSTATUS(status)	(((status) & 0xff00) >> 8)
#define WIFEXITED(status)	(WTERMSIG(status) == 0)


struct group {
	char	*gr_name;	/* group name */
	char	*gr_passwd;	/* group password */
	gid_t	gr_gid;		/* group id */
	char	**gr_mem;	/* group members */
};

static inline struct group *getgrnam(const char *name)
{
	return NULL;
}


struct passwd {
	char	*pw_name;	/* user name */
	char	*pw_passwd;	/* user password */
	uid_t	pw_uid;		/* user id */
	gid_t	pw_gid;		/* group id */
	char	*pw_gecos;	/* real name */
	char	*pw_dir;	/* home directory */
	char	*pw_shell;	/* shell program */
};

static inline struct passwd *getpwnam(const char *name)
{
	return NULL;
}


#endif

#endif
