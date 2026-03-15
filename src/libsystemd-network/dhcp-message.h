/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

#include "dhcp-protocol.h"

typedef struct sd_dhcp_message sd_dhcp_message;

struct sd_dhcp_message {
        unsigned n_ref;

        DHCPMessageHeader header;
        Hashmap *options;
};

sd_dhcp_message* sd_dhcp_message_ref(sd_dhcp_message *p);
sd_dhcp_message* sd_dhcp_message_unref(sd_dhcp_message *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_dhcp_message*, sd_dhcp_message_unref);

int dhcp_message_new(sd_dhcp_message **ret);

int dhcp_message_init_header(
                sd_dhcp_message *message,
                uint8_t op,
                uint32_t xid,
                uint16_t arp_type,
                uint8_t hlen,
                const uint8_t *chaddr);

int dhcp_message_append_option(sd_dhcp_message *message, uint8_t code, uint8_t length, const void *data);
int dhcp_message_append_option_string(sd_dhcp_message *message, uint8_t code, const char *data);
int dhcp_message_append_option_flag(sd_dhcp_message *message, uint8_t code);
int dhcp_message_append_option_u8(sd_dhcp_message *message, uint8_t code, uint8_t data);
int dhcp_message_append_option_u16(sd_dhcp_message *message, uint8_t code, uint16_t data);
int dhcp_message_append_option_be32(sd_dhcp_message *message, uint8_t code, be32_t data);
int dhcp_message_append_option_addresses(sd_dhcp_message *message, uint8_t code, size_t n_addr, const struct in_addr *addr);

int dhcp_message_get_option(sd_dhcp_message *message, uint8_t code, size_t length, void *ret);
int dhcp_message_get_option_alloc(sd_dhcp_message *message, uint8_t code, size_t chunk, size_t *ret_n_chunk, void **ret_data);
int dhcp_message_get_option_string(sd_dhcp_message *message, uint8_t code, char **ret);
int dhcp_message_get_option_u8(sd_dhcp_message *message, uint8_t code, uint8_t *ret);
int dhcp_message_get_option_u16(sd_dhcp_message *message, uint8_t code, uint16_t *ret);
int dhcp_message_get_option_be32(sd_dhcp_message *message, uint8_t code, be32_t *ret);
int dhcp_message_get_option_addresses(sd_dhcp_message *message, uint8_t code, size_t *ret_n_addr, struct in_addr **ret_addr);

int dhcp_message_new_from_payload(const uint8_t *buf, size_t len, sd_dhcp_message **ret);

int dhcp_message_build_payload(const sd_dhcp_message *message, struct iovec *ret);
int dhcp_message_build_packet(
                const sd_dhcp_message *message,
                be32_t source_addr,
                uint16_t source_port,
                be32_t destination_addr,
                uint16_t destination_port,
                int ip_service_type,
                struct iovec_wrapper *ret);

int dhcp_message_send_udp(const sd_dhcp_message *message, int fd, be32_t dest, uint16_t port);
int dhcp_message_send_raw(
                const sd_dhcp_message *message,
                int fd,
                be32_t source_addr,
                uint16_t source_port,
                be32_t destination_addr,
                uint16_t destination_port,
                int ip_service_type);

int dhcp_message_recv_udp(int fd, sd_dhcp_message **ret);
int dhcp_message_recv_raw(int fd, uint16_t port, sd_dhcp_message **ret);
