/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-server-lease.h"
#include "sd-forward.h"

#include "dhcp-client-id-internal.h"
#include "dhcp-message.h"

typedef struct sd_dhcp_request sd_dhcp_request;

struct sd_dhcp_request {
        unsigned n_ref;

        sd_dhcp_message *message; /* received message */
        struct hw_addr_data hw_addr; /* sender hardware address */
        triple_timestamp timestamp;

        /* options */
        uint8_t type;
        sd_dhcp_client_id client_id;
        be32_t server_address;
        size_t max_message_size; /* maximum message size, including IP header */
        be32_t requested_ip;
        usec_t lifetime;
        Set *parameter_request_list;

        /* acquired data */
        sd_dhcp_server_lease *static_lease;
        be32_t address;
};

sd_dhcp_request* sd_dhcp_request_ref(sd_dhcp_request *p);
sd_dhcp_request* sd_dhcp_request_unref(sd_dhcp_request *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_dhcp_request*, sd_dhcp_request_unref);

int dhcp_request_get_lifetime_timestamp(sd_dhcp_request *req, clockid_t clock, usec_t *ret);
int dhcp_server_process_message(sd_dhcp_server *server, const struct iovec *iov, const triple_timestamp *timestamp);
int dhcp_server_relay_message(sd_dhcp_server *server, const struct iovec *iov);
int dhcp_server_receive_message(sd_event_source *s, int fd, uint32_t revents, void *userdata);
