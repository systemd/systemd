/*
 * sys/syscall.h
 *
 * Generic system call interface macros
 */
#ifndef _SYS_SYSCALL_H
#define _SYS_SYSCALL_H

#include <errno.h>
#include <asm/unistd.h>

/* Many architectures have incomplete or defective syscall macros */
#include <klibc/archsys.h>

#endif /* _SYS_SYSCALL_H */
