/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/socket.h>

/* Supported since kernel v6.5 (5e2ff6704a275be009be8979af17c52361b79b89) */
#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif

/* Supported since kernel v6.5 (7b26952a91cf65ff1cc867a2382a8964d8c0ee7d) */
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

/* Supported since kernel v6.16 (77cbe1a6d8730a07f99f9263c2d5f2304cf5e830) */
#ifndef SO_PASSRIGHTS
#define SO_PASSRIGHTS 83
#endif

/* Not exposed yet. Defined in include/linux/socket.h. */
#ifndef SOL_SCTP
#define SOL_SCTP 132
#endif

/* Supported since kernel v2.6.17 (2c7946a7bf45ae86736ab3b43d0085e43947945c).
 * Defined since glibc-2.39 */
#ifndef SCM_SECURITY
#define SCM_SECURITY 0x03
#endif

/* Supported since kernel v6.5 (5e2ff6704a275be009be8979af17c52361b79b89).
 * Defined since glibc-2.39 */
#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif

/* The maximum number of fds that SCM_RIGHTS accepts. This is an internal kernel constant defined in
 * include/net/scm.h, but very much useful for userspace too. It's documented in unix(7) these days, hence
 * should be fairly reliable to define here. */
#ifndef SCM_MAX_FD
#define SCM_MAX_FD 253U
#endif
