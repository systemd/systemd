/*
 * fdatasync.c
 *
 * Some systems don't have this (alpha?) ... this is really a bug,
 * but mimic using fsync()
 */

#include <unistd.h>
#include <sys/syscall.h>

#ifndef __NR_fdatasync
#define __NR_fdatasync __NR_fsync
#endif

_syscall1(int,fdatasync,int,fd);
