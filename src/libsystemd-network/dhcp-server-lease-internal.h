/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-server-lease.h"

#include "dhcp-client-id-internal.h"
#include "dhcp-server-internal.h"
#include "time-util.h"

typedef struct sd_dhcp_server_lease {
        unsigned n_ref;

        sd_dhcp_server *server;

        sd_dhcp_client_id client_id;

        uint8_t htype; /* e.g. ARPHRD_ETHER */
        uint8_t hlen;  /* e.g. ETH_ALEN */
        be32_t address;
        be32_t gateway;
        uint8_t chaddr[16];
        usec_t expiration;
        char *hostname;
} sd_dhcp_server_lease;

extern const struct hash_ops dhcp_server_lease_hash_ops;

int dhcp_server_add_lease(sd_dhcp_server *server, sd_dhcp_server_lease *lease, bool is_static);
