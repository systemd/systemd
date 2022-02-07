/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.
***/

#include <net/ethernet.h>
#include <netinet/in.h>

#include "sd-event.h"
#include "sd-dhcp6-client.h"

#include "dhcp-identifier.h"
#include "dhcp6-protocol.h"
#include "ether-addr-util.h"
#include "hashmap.h"
#include "list.h"
#include "macro.h"
#include "network-common.h"
#include "ordered-set.h"
#include "sparse-endian.h"

typedef struct sd_dhcp6_option {
        unsigned n_ref;

        uint32_t enterprise_identifier;
        uint16_t option;
        void *data;
        size_t length;
} sd_dhcp6_option;

extern const struct hash_ops dhcp6_option_hash_ops;

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

struct ia_header {
        be32_t id;
        be32_t lifetime_t1;
        be32_t lifetime_t2;
} _packed_;

typedef struct DHCP6IA {
        uint16_t type;
        struct ia_header header;

        LIST_HEAD(DHCP6Address, addresses);
} DHCP6IA;

/* what to request from the server, addresses (IA_NA) and/or prefixes (IA_PD) */
typedef enum DHCP6RequestIA {
        DHCP6_REQUEST_IA_NA = 1 << 0,
        DHCP6_REQUEST_IA_TA = 1 << 1, /* currently not used */
        DHCP6_REQUEST_IA_PD = 1 << 2,
} DHCP6RequestIA;

typedef struct sd_dhcp6_client {
        unsigned n_ref;

        DHCP6State state;
        sd_event *event;
        int event_priority;
        int ifindex;
        char *ifname;
        struct in6_addr local_address;
        struct hw_addr_data hw_addr;
        uint16_t arp_type;
        DHCP6IA ia_na;
        DHCP6IA ia_pd;
        DHCP6RequestIA request_ia;
        be32_t transaction_id;
        usec_t transaction_start;
        struct sd_dhcp6_lease *lease;
        int fd;
        bool information_request;
        bool iaid_set;
        be16_t *req_opts;
        size_t req_opts_len;
        char *fqdn;
        char *mudurl;
        char **user_class;
        char **vendor_class;
        sd_event_source *receive_message;
        usec_t retransmit_time;
        uint8_t retransmit_count;
        sd_event_source *timeout_resend;
        sd_event_source *timeout_expire;
        sd_event_source *timeout_t1;
        sd_event_source *timeout_t2;
        sd_dhcp6_client_callback_t callback;
        void *userdata;
        struct duid duid;
        size_t duid_len;
        usec_t information_request_time_usec;
        usec_t information_refresh_time_usec;
        OrderedHashmap *extra_options;
        OrderedSet *vendor_options;

        /* Ignore ifindex when generating iaid. See dhcp_identifier_set_iaid(). */
        bool test_mode;
} sd_dhcp6_client;

bool dhcp6_option_can_request(uint16_t option);
int dhcp6_option_append(uint8_t **buf, size_t *buflen, uint16_t code,
                        size_t optlen, const void *optval);
int dhcp6_option_append_ia(uint8_t **buf, size_t *buflen, const DHCP6IA *ia);
int dhcp6_option_append_fqdn(uint8_t **buf, size_t *buflen, const char *fqdn);
int dhcp6_option_append_user_class(uint8_t **buf, size_t *buflen, char * const *user_class);
int dhcp6_option_append_vendor_class(uint8_t **buf, size_t *buflen, char * const *user_class);
int dhcp6_option_append_vendor_option(uint8_t **buf, size_t *buflen, OrderedSet *vendor_options);

int dhcp6_option_parse(
                const uint8_t *buf,
                size_t buflen,
                size_t *offset,
                uint16_t *ret_option_code,
                size_t *ret_option_data_len,
                const uint8_t **ret_option_data);
int dhcp6_option_parse_status(const uint8_t *data, size_t data_len, char **ret_status_message);
int dhcp6_option_parse_ia(
                sd_dhcp6_client *client,
                be32_t iaid,
                uint16_t option_code,
                size_t option_data_len,
                const uint8_t *option_data,
                DHCP6IA **ret);
int dhcp6_option_parse_addresses(
                const uint8_t *optval,
                size_t optlen,
                struct in6_addr **addrs,
                size_t *count);
int dhcp6_option_parse_domainname_list(const uint8_t *optval, size_t optlen, char ***ret);
int dhcp6_option_parse_domainname(const uint8_t *optval, size_t optlen, char **ret);

int dhcp6_network_bind_udp_socket(int ifindex, struct in6_addr *address);
int dhcp6_network_send_udp_socket(int s, struct in6_addr *address,
                                  const void *packet, size_t len);

const char *dhcp6_message_type_to_string(DHCP6MessageType t) _const_;
DHCP6MessageType dhcp6_message_type_from_string(const char *s) _pure_;
const char *dhcp6_message_status_to_string(DHCP6Status s) _const_;
DHCP6Status dhcp6_message_status_from_string(const char *s) _pure_;

void dhcp6_client_set_test_mode(sd_dhcp6_client *client, bool test_mode);
int dhcp6_client_set_transaction_id(sd_dhcp6_client *client, uint32_t transaction_id);

#define log_dhcp6_client_errno(client, error, fmt, ...)         \
        log_interface_prefix_full_errno(                        \
                "DHCPv6 client: ",                              \
                sd_dhcp6_client, client,                        \
                error, fmt, ##__VA_ARGS__)
#define log_dhcp6_client(client, fmt, ...)                      \
        log_interface_prefix_full_errno_zerook(                 \
                "DHCPv6 client: ",                              \
                sd_dhcp6_client, client,                        \
                0, fmt, ##__VA_ARGS__)
