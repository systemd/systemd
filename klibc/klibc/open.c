/*
 * open.c
 *
 * The open syscall is weird, because it's defined as a varadic
 * function, but implementing it as such generally sucks for
 * performance.  Thus we generate it as a 3-argument function,
 * but with explicit __cdecl assuming the __cdecl convention is
 * independent of being varadic.
 */

#define __IN_OPEN_C
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

__cdecl _syscall3(int,open,const char *,file,int,flags,mode_t,mode)
