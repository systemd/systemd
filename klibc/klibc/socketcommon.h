/*
 * socketcommon.h
 *
 * Common header file for socketcall stubs
 */

#define __IN_SYS_COMMON
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <linux/net.h>

/*
 * Some architectures have socketcall(), some have real syscalls,
 * and some have both, but the syscall version is always preferred.
 * Look for __NR_<call> to probe for the existence of a syscall.
 */

#ifdef __NR_socketcall
static inline _syscall2(int,socketcall,int,call,unsigned long *,args);
#endif
