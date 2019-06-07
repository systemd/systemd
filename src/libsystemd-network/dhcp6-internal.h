/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.
***/

#include <net/ethernet.h>
#include <netinet/in.h>

#include "sd-event.h"

#include "list.h"
#include "macro.h"
#include "sparse-endian.h"

/* Common option header */
typedef struct DHCP6Option {
        be16_t code;
        be16_t len;
        uint8_t data[];
} _packed_ DHCP6Option;

/* Address option */
struct iaaddr {
        struct in6_addr address;
        be32_t lifetime_preferred;
        be32_t lifetime_valid;
} _packed_;

/* Prefix Delegation Prefix option */
struct iapdprefix {
        be32_t lifetime_preferred;
        be32_t lifetime_valid;
        uint8_t prefixlen;
        struct in6_addr address;
} _packed_;

typedef struct DHCP6Address DHCP6Address;

struct DHCP6Address {
        LIST_FIELDS(DHCP6Address, addresses);

        union {
                struct iaaddr iaaddr;
                struct iapdprefix iapdprefix;
        };
};

/* Non-temporary Address option */
struct ia_na {
        be32_t id;
        be32_t lifetime_t1;
        be32_t lifetime_t2;
} _packed_;

/* Prefix Delegation option */
struct ia_pd {
        be32_t id;
        be32_t lifetime_t1;
        be32_t lifetime_t2;
} _packed_;

/* Temporary Address option */
struct ia_ta {
        be32_t id;
} _packed_;

struct DHCP6IA {
        uint16_t type;
        union {
                struct ia_na ia_na;
                struct ia_pd ia_pd;
                struct ia_ta ia_ta;
        };

        LIST_HEAD(DHCP6Address, addresses);
};

typedef struct DHCP6IA DHCP6IA;

#define log_dhcp6_client_errno(p, error, fmt, ...) log_internal(LOG_DEBUG, error, PROJECT_FILE, __LINE__, __func__, "DHCPv6 CLIENT: " fmt, ##__VA_ARGS__)
#define log_dhcp6_client(p, fmt, ...) log_dhcp6_client_errno(p, 0, fmt, ##__VA_ARGS__)

int dhcp6_option_append(uint8_t **buf, size_t *buflen, uint16_t code,
                        size_t optlen, const void *optval);
int dhcp6_option_append_ia(uint8_t **buf, size_t *buflen, const DHCP6IA *ia);
int dhcp6_option_append_pd(uint8_t *buf, size_t len, const DHCP6IA *pd);
int dhcp6_option_append_fqdn(uint8_t **buf, size_t *buflen, const char *fqdn);
int dhcp6_option_parse(uint8_t **buf, size_t *buflen, uint16_t *optcode,
                       size_t *optlen, uint8_t **optvalue);
int dhcp6_option_parse_status(DHCP6Option *option, size_t len);
int dhcp6_option_parse_ia(DHCP6Option *iaoption, DHCP6IA *ia);
int dhcp6_option_parse_ip6addrs(uint8_t *optval, uint16_t optlen,
                                struct in6_addr **addrs, size_t count,
                                size_t *allocated);
int dhcp6_option_parse_domainname(const uint8_t *optval, uint16_t optlen,
                                  char ***str_arr);

int dhcp6_network_bind_udp_socket(int index, struct in6_addr *address);
int dhcp6_network_send_udp_socket(int s, struct in6_addr *address,
                                  const void *packet, size_t len);

const char *dhcp6_message_type_to_string(int s) _const_;
int dhcp6_message_type_from_string(const char *s) _pure_;
const char *dhcp6_message_status_to_string(int s) _const_;
int dhcp6_message_status_from_string(const char *s) _pure_;
