/*
 * sys/socket.h
 */

#ifndef _SYS_SOCKET_H
#define _SYS_SOCKET_H

#include <klibc/extern.h>
#include <klibc/compiler.h>
#include <linux/socket.h>

/* For some reason these may be protected by __KERNEL__ in asm/socket.h */
#ifndef SOCK_STREAM
# define SOCK_STREAM    1
# define SOCK_DGRAM     2
# define SOCK_RAW       3
# define SOCK_RDM       4
# define SOCK_SEQPACKET 5
# define SOCK_PACKET    10
#endif

#ifdef __i386__
# define __socketcall __extern __cdecl
#else
# define __socketcall __extern
#endif

typedef int socklen_t;

__socketcall int socket(int, int, int);
__socketcall int bind(int, struct sockaddr *, int);
__socketcall int connect(int, struct sockaddr *, socklen_t);
__socketcall int listen(int, int);
__socketcall int accept(int, struct sockaddr *, socklen_t *);
__socketcall int getsockname(int, struct sockaddr *, socklen_t *);
__socketcall int getpeername(int, struct sockaddr *, socklen_t *);
__socketcall int socketpair(int, int, int, int *);
__extern     int send(int, const void *, size_t, unsigned int);
__socketcall int sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
__extern     int recv(int, void *, size_t, unsigned int);
__socketcall int recvfrom(int, void *, size_t, unsigned int, struct sockaddr *, socklen_t *);
__socketcall int shutdown(int, int);
__socketcall int setsockopt(int, int, int, const void *, socklen_t);
__socketcall int getsockopt(int, int, int, void *, socklen_t *);
__socketcall int sendmsg(int, const struct msghdr *, unsigned int);
__socketcall int recvmsg(int, struct msghdr *, unsigned int);

#undef __socketcall

#endif /* _SYS_SOCKET_H */
