/*
 * arch/x86_64/include/klibc/archsignal.h
 *
 * Architecture-specific signal definitions
 *
 */

#ifndef _KLIBC_ARCHSIGNAL_H
#define _KLIBC_ARCHSIGNAL_H

/* The x86-64 headers defines NSIG 32, but it's actually 64 */
#undef  _NSIG
#undef  NSIG
#define _NSIG 64
#define NSIG  _NSIG

#endif
