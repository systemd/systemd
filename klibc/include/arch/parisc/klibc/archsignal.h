/*
 * arch/parisc/include/klibc/archsignal.h
 *
 * Architecture-specific signal definitions
 *
 */

#ifndef _KLIBC_ARCHSIGNAL_H
#define _KLIBC_ARCHSIGNAL_H

#define _NSIG    64
#define _NSIG_SZ (_NSIG / LONG_BIT)

typedef struct {
        unsigned long sig[_NSIG_SZ];
} sigset_t;

struct sigaction {
        __sighandler_t sa_handler;
        unsigned long sa_flags;
        sigset_t sa_mask;
};

#endif
