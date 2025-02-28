/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

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

/* Not exposed yet. Defined in include/linux/socket.h. */
#ifndef SOL_SCTP
#define SOL_SCTP 132
#endif

/* since glibc-2.39 */
#ifndef SCM_SECURITY
#define SCM_SECURITY 0x03
#endif

/* since glibc-2.39 */
#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif

/* The maximum number of fds that SCM_RIGHTS accepts. This is an internal kernel constant defined in
 * include/net/scm.h, but very much useful for userspace too. It's documented in unix(7) these days, hence
 * should be fairly reliable to define here. */
#ifndef SCM_MAX_FD
#define SCM_MAX_FD 253U
#endif
