/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-option.h" /* IWYU pragma: export */
#include "sd-forward.h"

#include "hash-funcs.h"
#include "list.h"

struct sd_dhcp_option {
        unsigned n_ref;

        LIST_FIELDS(struct sd_dhcp_option, option);

        union {
                struct {
                        uint8_t option;
                        uint8_t length;
                        uint8_t data[];
                } _packed_;
                uint8_t tlv[0]; /* this is an array; since we are not allowed to place a variable sized array
                                 * in a union, we just zero-size it, even if it is generally longer. */
        };
};

assert_cc(offsetof(sd_dhcp_option, option) == offsetof(sd_dhcp_option, tlv));

extern const struct hash_ops dhcp_option_hash_ops;

typedef struct DHCPServerData {
        struct in_addr *addr;
        size_t size;
} DHCPServerData;

int dhcp_options_append(Hashmap **options, uint8_t code, size_t length, const void *data);
int dhcp_options_append_many(Hashmap **options, Hashmap *src);
int dhcp_options_parse(Hashmap **options, const struct iovec *iov);
size_t dhcp_options_size(Hashmap *options);
int dhcp_options_build(Hashmap *options, struct iovec *ret);

int dhcp_options_build_json(Hashmap *options, sd_json_variant **ret);
int dhcp_options_parse_json(sd_json_variant *v, Hashmap **ret);
