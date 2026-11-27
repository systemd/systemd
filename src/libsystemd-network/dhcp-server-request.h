/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dhcp-client-id-internal.h"
#include "dhcp-forward.h"
#include "dhcp-rkap.h"
#include "ether-addr-util.h"
#include "time-util.h"

typedef struct DHCPRequest {
        /* received message */
        sd_dhcp_message *message;
        /* sender hardware address, may not be set for non-ethernet interface */
        struct hw_addr_data hw_addr;
        triple_timestamp timestamp;
        struct in_pktinfo *pktinfo;

        /* options */
        uint8_t type;
        sd_dhcp_client_id client_id;
        sd_dhcp_client_id client_id_by_header;
        size_t max_message_size; /* maximum message size, including IP and UDP headers */
        be32_t server_address;
        usec_t lifetime;
        Set *parameter_request_list;
        bool forcerenew_nonce_capable; /* RFC 6704: the client sent FORCERENEW_NONCE_CAPABLE with HMAC-MD5 */

        /* acquired data */
        sd_dhcp_server_lease *static_lease;
        be32_t address;
        const DHCPRKAPKey *forcerenew_nonce; /* the nonce to include in the DHCPACK, if any */
} DHCPRequest;

int dhcp_request_get_lifetime_timestamp(DHCPRequest *req, clockid_t clock, usec_t *ret);

int dhcp_server_process_message(sd_dhcp_server *server, const struct iovec *iov, struct msghdr *mh);
int dhcp_server_setup_io_event_source(sd_dhcp_server *server);
