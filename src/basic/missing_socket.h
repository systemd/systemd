/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

#if HAVE_LINUX_VM_SOCKETS_H
#include <linux/vm_sockets.h>
#else
#define VMADDR_CID_ANY -1U
struct sockaddr_vm {
        unsigned short svm_family;
        unsigned short svm_reserved1;
        unsigned int svm_port;
        unsigned int svm_cid;
        unsigned char svm_zero[sizeof(struct sockaddr) -
                               sizeof(unsigned short) -
                               sizeof(unsigned short) -
                               sizeof(unsigned int) -
                               sizeof(unsigned int)];
};
#endif /* !HAVE_LINUX_VM_SOCKETS_H */

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#ifndef SO_PEERGROUPS
#define SO_PEERGROUPS 59
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

/* Not exposed yet. Defined in include/linux/socket.h */
#ifndef SCM_SECURITY
#define SCM_SECURITY 0x03
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

/* linux/sockios.h */
#ifndef SIOCGSKNS
#define SIOCGSKNS 0x894C
#endif
