/*
 * arch/sparc/include/klibc/archsignal.h
 *
 * Architecture-specific signal definitions
 *
 */

#ifndef _KLIBC_ARCHSIGNAL_H
#define _KLIBC_ARCHSIGNAL_H

/* Hidden definitions */

struct __new_sigaction {
        __sighandler_t  sa_handler;
        unsigned long   sa_flags;
        void            (*sa_restorer)(void);   /* Not used by Linux/SPARC */
        __new_sigset_t  sa_mask;
};

struct k_sigaction {
        struct __new_sigaction  sa;
        void                    __user *ka_restorer;
};

struct __old_sigaction {
        __sighandler_t  sa_handler;
        __old_sigset_t  sa_mask;
        unsigned long   sa_flags;
        void            (*sa_restorer) (void);  /* not used by Linux/SPARC */
};

typedef struct sigaltstack {
        void            __user *ss_sp;
        int             ss_flags;
        size_t          ss_size;
} stack_t;

#endif
