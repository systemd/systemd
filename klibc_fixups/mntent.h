#ifdef __KLIBC__

#ifndef _MNTENT_H
#define _MNTENT_H

#include <stdio.h>

struct mntent
{
	char *mnt_fsname;
	char *mnt_dir;
	char *mnt_type;
	char *mnt_opts;
	int mnt_freq;
	int mnt_passno;
};

static inline FILE *setmntent (const char *file, const char *mode)
{
	return (FILE *) 1;
}

static inline struct mntent *getmntent (FILE *stream)
{
	static struct mntent mntent = {
		.mnt_dir	= "/sys",
		.mnt_type	= "sysfs"
	};

	return &mntent;
}

static inline int endmntent (FILE *stream)
{
	return 0;
}

#endif /* _MNTENT_H */
#endif /* __KLIBC__ */
