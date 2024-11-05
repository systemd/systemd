/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#ifndef SO_PEERGROUPS
#define SO_PEERGROUPS 59
#endif

#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

#ifndef SO_BINDTOIFINDEX
#define SO_BINDTOIFINDEX 62
#endif

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

/* Not exposed yet. Defined in include/linux/socket.h. */
#ifndef SOL_SCTP
#define SOL_SCTP 132
#endif

#ifndef SCM_SECURITY
#define SCM_SECURITY 0x03
#endif

#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif

/* netinet/in.h */
#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif

#ifndef IPV6_FREEBIND
#define IPV6_FREEBIND 78
#endif

#ifndef IP_RECVFRAGSIZE
#define IP_RECVFRAGSIZE 25
#endif

#ifndef IPV6_RECVFRAGSIZE
#define IPV6_RECVFRAGSIZE 77
#endif

/* The maximum number of fds that SCM_RIGHTS accepts. This is an internal kernel constant, but very much
 * useful for userspace too. It's documented in unix(7) these days, hence should be fairly reliable to define
 * here. */
#ifndef SCM_MAX_FD
#define SCM_MAX_FD 253U
#endif
