/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-client-id.h"

#include "dhcp-duid-internal.h"
#include "macro.h"
#include "siphash24.h"
#include "sparse-endian.h"

/* RFC 2132 section 9.14: its minimum length is 2.
 * Note, its maximum is not mentioend in the RFC. Hence, 255. */
#define MIN_CLIENT_ID_LEN 2
#define MAX_CLIENT_ID_LEN 255
#define MIN_CLIENT_ID_DATA_LEN (MIN_CLIENT_ID_LEN - sizeof(uint8_t))
#define MAX_CLIENT_ID_DATA_LEN (MAX_CLIENT_ID_LEN - sizeof(uint8_t))

typedef struct sd_dhcp_client_id {
        size_t size;
        union {
                struct {
                        uint8_t type;
                        union {
                                struct {
                                        /* 0: Generic (non-LL) (RFC 2132) */
                                        uint8_t data[MAX_CLIENT_ID_DATA_LEN];
                                } _packed_ gen;
                                struct {
                                        /* 1: Ethernet Link-Layer (RFC 2132) */
                                        uint8_t haddr[ETH_ALEN];
                                } _packed_ eth;
                                struct {
                                        /* 2 - 254: ARP/Link-Layer (RFC 2132) */
                                        uint8_t haddr[0];
                                } _packed_ ll;
                                struct {
                                        /* 255: Node-specific (RFC 4361) */
                                        be32_t iaid;
                                        struct duid duid;
                                } _packed_ ns;
                                uint8_t data[MAX_CLIENT_ID_DATA_LEN];
                        };
                } _packed_ id;
                uint8_t raw[MAX_CLIENT_ID_LEN];
        };
} sd_dhcp_client_id;

static inline bool client_id_size_is_valid(size_t size) {
        return size >= MIN_CLIENT_ID_LEN && size <= MAX_CLIENT_ID_LEN;
}

static inline bool client_id_data_size_is_valid(size_t size) {
        return size >= MIN_CLIENT_ID_DATA_LEN && size <= MAX_CLIENT_ID_DATA_LEN;
}

void client_id_hash_func(const sd_dhcp_client_id *client_id, struct siphash *state);
int client_id_compare_func(const sd_dhcp_client_id *a, const sd_dhcp_client_id *b);
