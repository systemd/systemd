#ifdef __KLIBC__

#ifndef _KLIBC_FIXUPS_H
#define _KLIBC_FIXUPS_H

#include <unistd.h>

#define _SC_PAGESIZE		0x66
static inline long int sysconf(int name)
{
	if (name == _SC_PAGESIZE)
		return getpagesize();

	return -1;
}

struct exit_status {
	short int e_termination;	/* process termination status */
	short int e_exit;		/* process exit status */
};

#endif /* KLIBC_FIXUPS_H */
#endif /* __KLIBC__ */
