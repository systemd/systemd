/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

#include "dhcp-client-id-internal.h"
#include "dhcp-protocol.h"
#include "ether-addr-util.h"
#include "sparse-endian.h"
#include "time-util.h"

typedef struct DHCPRequest {
        /* received message */
        DHCPMessage *message;
        /* sender hardware address, may not be set for non-ethernet interface */
        struct hw_addr_data hw_addr;

        /* options */
        sd_dhcp_client_id client_id;
        sd_dhcp_client_id client_id_by_header;
        size_t max_optlen;
        be32_t server_id;
        be32_t requested_ip;
        usec_t lifetime;
        const uint8_t *agent_info_option;
        char *hostname;
        const uint8_t *parameter_request_list;
        size_t parameter_request_list_len;
        bool rapid_commit;
        triple_timestamp timestamp;
} DHCPRequest;

int dhcp_server_handle_message(sd_dhcp_server *server, DHCPMessage *message, size_t length, const triple_timestamp *timestamp);
int dhcp_server_setup_io_event_source(sd_dhcp_server *server);
