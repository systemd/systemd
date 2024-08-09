/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

#include "sd-dhcp-option.h"
#include "dns-resolver-internal.h"

#include "dhcp-protocol.h"
#include "hash-funcs.h"

struct sd_dhcp_option {
        unsigned n_ref;

        uint8_t option;
        void *data;
        size_t length;
};

extern const struct hash_ops dhcp_option_hash_ops;

typedef struct DHCPServerData {
        struct in_addr *addr;
        size_t size;
} DHCPServerData;

int dhcp_option_append(
                DHCPMessage *message,
                size_t size,
                size_t *offset,
                uint8_t overload,
                uint8_t code,
                size_t optlen,
                const void *optval);
int dhcp_option_find_option(uint8_t *options, size_t length, uint8_t wanted_code, size_t *ret_offset);
int dhcp_option_remove_option(uint8_t *options, size_t buflen, uint8_t option_code);

typedef int (*dhcp_option_callback_t)(uint8_t code, uint8_t len, const void *option, void *userdata);

int dhcp_option_parse(
                DHCPMessage *message,
                size_t len,
                dhcp_option_callback_t cb,
                void *userdata,
                char **ret_error_message);

int dhcp_option_parse_string(const uint8_t *option, size_t len, char **ret);
int dhcp_option_parse_hostname(const uint8_t *option, size_t len, char **ret);
