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
#include <sys/socketcalls.h>
