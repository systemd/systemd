#ifdef __KLIBC__

#ifndef _KLIBC_FIXUPS_H
#define _KLIBC_FIXUPS_H

struct exit_status {
	short int e_termination;	/* process termination status */
	short int e_exit;		/* process exit status */
};

#endif /* KLIBC_FIXUPS_H */
#endif /* __KLIBC__ */
