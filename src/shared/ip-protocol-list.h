/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

const char* ip_protocol_to_name(int id);
int ip_protocol_from_name(const char *name);
int parse_ip_protocol_full(const char *s, bool relaxed);
static inline int parse_ip_protocol(const char *s) {
        return parse_ip_protocol_full(s, /* relaxed= */ false);
}

const char* ip_protocol_to_tcp_udp(int id);
int ip_protocol_from_tcp_udp(const char *ip_protocol);

/* Flag ORed into a protocol id for SocketProtocol= in socket units, indicating "use this protocol if the
 * kernel supports it, otherwise fall back to a related protocol". Currently only valid in combination with
 * IPPROTO_MPTCP, where it means falling back to TCP. IP protocol ids are small (the largest one we know is
 * IPPROTO_MPTCP = 262), hence bit 30 never collides with them, and since it is not the sign bit valid
 * values remain positive. */
#define SOCKET_PROTOCOL_AUTO (INT32_C(1) << 30)

int socket_protocol_from_string(const char *s);
const char* socket_protocol_to_string(int id);
