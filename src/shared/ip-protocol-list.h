/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

const char* ip_protocol_to_name(int id);
int ip_protocol_from_name(const char *name);
int parse_ip_protocol_full(const char *s, bool relaxed);
static inline int parse_ip_protocol(const char *s) {
        return parse_ip_protocol_full(s, false);
}

const char* ip_protocol_to_tcp_udp(int id);
int ip_protocol_from_tcp_udp(const char *ip_protocol);
