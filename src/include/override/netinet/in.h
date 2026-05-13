/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/in.h>   /* IWYU pragma: export */
#include <linux/in6.h>  /* IWYU pragma: export */
#include <linux/ipv6.h> /* IWYU pragma: export */
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

extern const struct in6_addr in6addr_any;        /* :: */
extern const struct in6_addr in6addr_loopback;   /* ::1 */
#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#define IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }

typedef uint32_t in_addr_t;
