/*
 * arch/alpha/include/klibc/archsys.h
 *
 * Architecture-specific syscall definitions
 */

#ifndef _KLIBC_ARCHSYS_H
#define _KLIBC_ARCHSYS_H

/* Alpha has some bizarre Tru64-derived system calls which return two
   different values in $0 and $20(!), respectively.  The standard
   macros can't deal with these; even the ones that give the right
   return value have the wrong clobbers. */

#define _syscall0_dual0(type, name)                                     \
type name(void)                                                         \
{                                                                       \
        long _sc_ret, _sc_err;                                          \
        {                                                               \
                register long _sc_0 __asm__("$0");                      \
                register long _sc_19 __asm__("$19");                    \
                register long _sc_20 __asm__("$20");                    \
                                                                        \
                _sc_0 = __NR_##name;                                    \
                __asm__("callsys"                                       \
                        : "=r"(_sc_0), "=r"(_sc_19), "=r" (_sc_20)      \
                        : "0"(_sc_0)                                    \
                        : _syscall_clobbers);                           \
                _sc_ret = _sc_0, _sc_err = _sc_19; (void)(_sc_20);      \
        }                                                               \
        _syscall_return(type);                                          \
}

#define _syscall0_dual1(type, name)                                     \
type name(void)                                                         \
{                                                                       \
        long _sc_ret, _sc_err;                                          \
        {                                                               \
                register long _sc_0 __asm__("$0");                      \
                register long _sc_19 __asm__("$19");                    \
                register long _sc_20 __asm__("$20");                    \
                                                                        \
                _sc_0 = __NR_##name;                                    \
                __asm__("callsys"                                       \
                        : "=r"(_sc_0), "=r"(_sc_19), "=r" (_sc_20)      \
                        : "0"(_sc_0)                                    \
                        : _syscall_clobbers);                           \
                _sc_ret = _sc_20, _sc_err = _sc_19; (void)(_sc_0);      \
        }                                                               \
        _syscall_return(type);                                          \
}

#endif /* _KLIBC_ARCHSYS_H */
