/*
 * sys/syscall.h
 *
 * Generic system call interface macros
 */
#ifndef _SYS_SYSCALL_H
#define _SYS_SYSCALL_H

#include <errno.h>
#include <sys/types.h>
#include <asm/unistd.h>

/* Many architectures have incomplete, defective or non-applicable
   syscall macros */
#include <klibc/archsys.h>

#endif /* _SYS_SYSCALL_H */
