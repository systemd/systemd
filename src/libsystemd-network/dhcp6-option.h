/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp6-client.h"

#include "hash-funcs.h"
#include "list.h"
#include "macro.h"
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

void dhcp6_ia_clear_addresses(DHCP6IA *ia);
DHCP6IA *dhcp6_ia_free(DHCP6IA *ia);
DEFINE_TRIVIAL_CLEANUP_FUNC(DHCP6IA*, dhcp6_ia_free);

bool dhcp6_option_can_request(uint16_t option);

int dhcp6_option_append(uint8_t **buf, size_t *offset, uint16_t code,
                        size_t optlen, const void *optval);
int dhcp6_option_append_ia(uint8_t **buf, size_t *offset, const DHCP6IA *ia);
int dhcp6_option_append_fqdn(uint8_t **buf, size_t *offset, const char *fqdn);
int dhcp6_option_append_user_class(uint8_t **buf, size_t *offset, char * const *user_class);
int dhcp6_option_append_vendor_class(uint8_t **buf, size_t *offset, char * const *vendor_class);
int dhcp6_option_append_vendor_option(uint8_t **buf, size_t *offset, OrderedSet *vendor_options);

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
