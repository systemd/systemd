/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdint.h>

#include "sd-dhcp-client.h"

#include "dhcp-protocol.h"
#include "ether-addr-util.h"
#include "network-common.h"
#include "socket-util.h"

typedef struct sd_dhcp_option {
        unsigned n_ref;

        uint8_t option;
        void *data;
        size_t length;
} sd_dhcp_option;

typedef struct DHCPServerData {
        struct in_addr *addr;
        size_t size;
} DHCPServerData;

extern const struct hash_ops dhcp_option_hash_ops;

typedef struct sd_dhcp_client sd_dhcp_client;

int dhcp_network_bind_raw_socket(
                int ifindex,
                union sockaddr_union *link,
                uint32_t xid,
                const struct hw_addr_data *hw_addr,
                const struct hw_addr_data *bcast_addr,
                uint16_t arp_type,
                uint16_t port);
int dhcp_network_bind_udp_socket(int ifindex, be32_t address, uint16_t port, int ip_service_type);
int dhcp_network_send_raw_socket(int s, const union sockaddr_union *link,
                                 const void *packet, size_t len);
int dhcp_network_send_udp_socket(int s, be32_t address, uint16_t port,
                                 const void *packet, size_t len);

int dhcp_option_append(DHCPMessage *message, size_t size, size_t *offset, uint8_t overload,
                       uint8_t code, size_t optlen, const void *optval);
int dhcp_option_find_option(uint8_t *options, size_t length, uint8_t wanted_code, size_t *ret_offset);
int dhcp_option_remove_option(uint8_t *options, size_t buflen, uint8_t option_code);

typedef int (*dhcp_option_callback_t)(uint8_t code, uint8_t len,
                                const void *option, void *userdata);

int dhcp_option_parse(DHCPMessage *message, size_t len, dhcp_option_callback_t cb, void *userdata, char **error_message);

int dhcp_message_init(DHCPMessage *message, uint8_t op, uint32_t xid,
                      uint8_t type, uint16_t arp_type, uint8_t hlen, const uint8_t *chaddr,
                      size_t optlen, size_t *optoffset);

uint16_t dhcp_packet_checksum(uint8_t *buf, size_t len);

void dhcp_packet_append_ip_headers(DHCPPacket *packet, be32_t source_addr,
                                   uint16_t source, be32_t destination_addr,
                                   uint16_t destination, uint16_t len, int ip_service_type);

int dhcp_packet_verify_headers(DHCPPacket *packet, size_t len, bool checksum, uint16_t port);

void dhcp_client_set_test_mode(sd_dhcp_client *client, bool test_mode);

/* If we are invoking callbacks of a dhcp-client, ensure unreffing the
 * client from the callback doesn't destroy the object we are working
 * on */
#define DHCP_CLIENT_DONT_DESTROY(client) \
        _cleanup_(sd_dhcp_client_unrefp) _unused_ sd_dhcp_client *_dont_destroy_##client = sd_dhcp_client_ref(client)

#define log_dhcp_client_errno(client, error, fmt, ...)          \
        log_interface_prefix_full_errno(                        \
                "DHCPv4 client: ",                              \
                sd_dhcp_client, client,                         \
                error, fmt, ##__VA_ARGS__)
#define log_dhcp_client(client, fmt, ...)                       \
        log_interface_prefix_full_errno_zerook(                 \
                "DHCPv4 client: ",                              \
                sd_dhcp_client, client,                         \
                0, fmt, ##__VA_ARGS__)
