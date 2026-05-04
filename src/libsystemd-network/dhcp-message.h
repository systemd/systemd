/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-client-id.h"
#include "sd-forward.h"

#include "sparse-endian.h"
#include "tlv-util.h"

typedef struct sd_dhcp_message sd_dhcp_message;

sd_dhcp_message* sd_dhcp_message_ref(sd_dhcp_message *p);
sd_dhcp_message* sd_dhcp_message_unref(sd_dhcp_message *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_dhcp_message*, sd_dhcp_message_unref);

int dhcp_message_new(sd_dhcp_message **ret);

int dhcp_message_init_header(
                sd_dhcp_message *message,
                uint8_t op,
                uint32_t xid,
                uint16_t arp_type,
                const struct hw_addr_data *hw_addr);

void dhcp_message_set_broadcast_flag(sd_dhcp_message *message, bool b);
bool dhcp_message_has_broadcast_flag(sd_dhcp_message *message);
int dhcp_message_get_hw_addr(sd_dhcp_message *message, struct hw_addr_data *ret);

bool dhcp_message_has_option(sd_dhcp_message *message, uint8_t code);
void dhcp_message_remove_option(sd_dhcp_message *message, uint8_t code);

int dhcp_message_append_option(sd_dhcp_message *message, uint8_t code, size_t length, const void *data);
int dhcp_message_append_option_tlv(sd_dhcp_message *message, const TLV *tlv);
int dhcp_message_append_option_flag(sd_dhcp_message *message, uint8_t code);
int dhcp_message_append_option_u8(sd_dhcp_message *message, uint8_t code, uint8_t data);
int dhcp_message_append_option_u16(sd_dhcp_message *message, uint8_t code, uint16_t data);
int dhcp_message_append_option_be32(sd_dhcp_message *message, uint8_t code, be32_t data);
int dhcp_message_append_option_sec(sd_dhcp_message *message, uint8_t code, usec_t usec);
int dhcp_message_append_option_address(sd_dhcp_message *message, uint8_t code, const struct in_addr *addr);
int dhcp_message_append_option_addresses(sd_dhcp_message *message, uint8_t code, size_t n_addr, const struct in_addr *addr);
int dhcp_message_append_option_string(sd_dhcp_message *message, uint8_t code, const char *data);
int dhcp_message_append_option_routes(sd_dhcp_message *message, uint8_t code, size_t n_routes, const sd_dhcp_route *routes);
int dhcp_message_append_option_6rd(
                sd_dhcp_message *message,
                uint8_t ipv4masklen,
                uint8_t prefixlen,
                const struct in6_addr *prefix,
                size_t n_br_addresses,
                const struct in_addr *br_addresses);
int dhcp_message_append_option_client_id(sd_dhcp_message *message, const sd_dhcp_client_id *id);
int dhcp_message_append_option_parameter_request_list(sd_dhcp_message *message, Set *prl);
int dhcp_message_append_option_hostname(sd_dhcp_message *message, uint8_t flags, bool is_client, const char *hostname);
int dhcp_message_append_option_sub_tlv(sd_dhcp_message *message, uint8_t code, const TLV *tlv);
int dhcp_message_append_option_length_prefixed_data(sd_dhcp_message *message, uint8_t code, size_t length_size, const struct iovec_wrapper *iovw);

int dhcp_message_get_option(sd_dhcp_message *message, uint8_t code, size_t length, void *ret);
int dhcp_message_get_option_alloc(sd_dhcp_message *message, uint8_t code, struct iovec *ret);
int dhcp_message_get_option_flag(sd_dhcp_message *message, uint8_t code);
int dhcp_message_get_option_u8(sd_dhcp_message *message, uint8_t code, uint8_t *ret);
int dhcp_message_get_option_u16(sd_dhcp_message *message, uint8_t code, uint16_t *ret);
int dhcp_message_get_option_be32(sd_dhcp_message *message, uint8_t code, be32_t *ret);
int dhcp_message_get_option_sec(sd_dhcp_message *message, uint8_t code, bool max_as_infinity, usec_t *ret);
int dhcp_message_get_option_address(sd_dhcp_message *message, uint8_t code, struct in_addr *ret);
int dhcp_message_get_option_addresses(sd_dhcp_message *message, uint8_t code, size_t *ret_n_addr, struct in_addr **ret_addr);
int dhcp_message_get_option_string(sd_dhcp_message *message, uint8_t code, char **ret);
int dhcp_message_get_option_routes(sd_dhcp_message *message, uint8_t code, size_t *ret_n_routes, sd_dhcp_route **ret_routes);
int dhcp_message_get_option_6rd(
                sd_dhcp_message *message,
                uint8_t *ret_ipv4masklen,
                uint8_t *ret_prefixlen,
                struct in6_addr *ret_prefix,
                size_t *ret_n_br_addresses,
                struct in_addr **ret_br_addresses);
int dhcp_message_get_option_client_id(sd_dhcp_message *message, sd_dhcp_client_id *ret);
int dhcp_message_get_option_parameter_request_list(sd_dhcp_message *message, Set **ret);
int dhcp_message_get_option_fqdn(sd_dhcp_message *message, uint8_t *ret_flags, char **ret_fqdn);
int dhcp_message_get_option_dns_name(sd_dhcp_message *message, uint8_t code, char **ret);
int dhcp_message_get_option_hostname(sd_dhcp_message *message, char **ret);
int dhcp_message_get_option_domains(sd_dhcp_message *message, uint8_t code, char ***ret);
int dhcp_message_get_option_sub_tlv(sd_dhcp_message *message, uint8_t code, TLVFlag flags, TLV **ret);
int dhcp_message_get_option_length_prefixed_data(sd_dhcp_message *message, uint8_t code, size_t length_size, struct iovec_wrapper *ret);
int dhcp_message_get_option_dnr(sd_dhcp_message *message, size_t *ret_n_resolvers, sd_dns_resolver **ret_resolvers);

int dhcp_message_parse(
                const struct iovec *iov,
                uint8_t op,
                const uint32_t *xid,
                uint16_t arp_type,
                const struct hw_addr_data *hw_addr,
                sd_dhcp_message **ret);

int dhcp_message_build(sd_dhcp_message *message, struct iovec_wrapper *ret);

int dhcp_message_build_json(sd_dhcp_message *message, sd_json_variant **ret);
int dhcp_message_parse_json(sd_json_variant *v, sd_dhcp_message **ret);

int dhcp_message_send_udp(
                sd_dhcp_message *message,
                int fd,
                be32_t src_addr,
                be32_t dst_addr,
                uint16_t dst_port);
int dhcp_message_send_raw(
                sd_dhcp_message *message,
                int fd,
                int ifindex,
                be32_t src_addr,
                uint16_t src_port,
                const struct hw_addr_data *dst_hw_addr,
                be32_t dst_addr,
                uint16_t dst_port,
                int ip_service_type);
