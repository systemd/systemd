/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-server-lease.h"

#include "dhcp-client-id-internal.h"
#include "dhcp-message.h"
#include "ether-addr-util.h"
#include "sd-forward.h"
#include "sparse-endian.h"
#include "time-util.h"

typedef struct DHCPRequest {
        /* received message */
        sd_dhcp_message *message;
        /* sender hardware address, may not be set for non-ethernet interface */
        struct hw_addr_data hw_addr;
        triple_timestamp timestamp;

        /* options */
        uint8_t type;
        sd_dhcp_client_id client_id;
        sd_dhcp_client_id client_id_by_header;
        be32_t server_address;
        size_t max_message_size; /* maximum message size, including IP header */
        usec_t lifetime;
        Set *parameter_request_list;

        /* acquired data */
        sd_dhcp_server_lease *static_lease;
        be32_t address;
} DHCPRequest;

int dhcp_request_get_lifetime_timestamp(DHCPRequest *req, clockid_t clock, usec_t *ret);

int dhcp_server_process_message(sd_dhcp_server *server, const struct iovec *iov, const triple_timestamp *timestamp);
int dhcp_server_setup_io_event_source(sd_dhcp_server *server);
