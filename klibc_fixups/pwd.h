#ifdef __KLIBC__

#ifndef _PWD_H
#define _PWD_H

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

#endif /* _PWD_H */
#endif /* __KLIBC__ */
