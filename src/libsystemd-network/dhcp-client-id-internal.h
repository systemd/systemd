/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-client-id.h"

#include "dhcp-duid-internal.h"
#include "macro.h"
#include "sparse-endian.h"

#define MAX_CLIENT_ID_DATA_LEN (sizeof(be32_t) + sizeof(struct duid))
#define MAX_CLIENT_ID_LEN      (sizeof(uint8_t) + MAX_CLIENT_ID_DATA_LEN)

typedef struct sd_dhcp_client_id {
        size_t size;
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
                        struct {
                                uint8_t data[MAX_CLIENT_ID_DATA_LEN];
                        } _packed_ raw;
                };
        } _packed_ id;
} sd_dhcp_client_id;
