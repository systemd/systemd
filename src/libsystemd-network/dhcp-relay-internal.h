/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-relay.h"

#include "dhcp-message.h"
#include "network-common.h"
#include "sd-forward.h"
#include "tlv-util.h"

struct sd_dhcp_relay {
        unsigned n_ref;

        sd_event *event;
        int event_priority;

        Hashmap *interfaces;            /* All interfaces by their ifindex. */
        Prioq *upstream_interfaces;     /* Upstream interfaces by their priorities. */
        Hashmap *downstream_interfaces; /* Downstream interfaces by their gateway address, circuit ID, and VSS. */

        struct in_addr server_address;
        uint16_t server_port;

        /* Global Relay Agent Information option (82) */
        struct iovec remote_id;          /* Agent Remote ID Sub-option (2) */
        bool server_identifier_override; /* Relay Agent Flags (10) and Server Identifier Override Sub-option (11) */
        TLV *extra_options;
};

struct sd_dhcp_relay_interface {
        unsigned n_ref;

        sd_dhcp_relay *relay;
        bool upstream;

        int ifindex;
        char *ifname;

        /* The address used for:
         * - the source IP of forwarded packets (both downstream and upstream),
         * - the Server Identifier Override Sub-option (when sd_dhcp_relay.server_identifier_override is true),
         * - the Link Selection Sub-option (when address != gateway_address).
         * Typically, this is an address of the interface itself, but we can specify an address of another
         * interface (e.g., for IP unnumbered setups). */
        struct in_addr address;
        uint16_t port;

        uint8_t ip_service_type; /* a.k.a. TOS */
        int socket_fd; /* socket fd set externally, used by unit tests */
        sd_event_source *io_event_source;

        /* Mutually exclusive fields depending on the 'upstream' boolean */
        union {
                /* Upstream specific */
                struct {
                        int64_t priority;
                        unsigned priority_idx;
                };

                /* Downstream specific */
                struct {
                        /* The address set in the giaddr field of the DHCP message header. Typically, it is
                         * the same as 'address' above, but we can specify a different address, and it does
                         * not need to be an address assigned to the interface. */
                        struct in_addr gateway_address;

                        /* Per-interface Relay Agent Information option (82) */
                        struct iovec circuit_id; /* Agent Circuit ID Sub-option (1) */
                        struct iovec vss;        /* DHCPv4 Virtual Subnet Selection Sub-Option (151) */
                        TLV *extra_options;
                };
        };
};

int dhcp_relay_set_extra_options(sd_dhcp_relay *relay, TLV *options);

int downstream_set_extra_options(sd_dhcp_relay_interface *interface, TLV *options);
int downstream_register(sd_dhcp_relay_interface *interface);
void downstream_unregister(sd_dhcp_relay_interface *interface);
void downstream_done(sd_dhcp_relay_interface *interface);
int downstream_get(sd_dhcp_relay *relay, sd_dhcp_message *message, sd_dhcp_relay_interface **ret);
int downstream_open_socket(sd_dhcp_relay_interface *interface);
int downstream_process_message(sd_dhcp_relay_interface *interface, const struct iovec *iov, bool unicast);
int downstream_receive_message(sd_event_source *s, int fd, uint32_t revents, void *userdata);
int downstream_send_message(sd_dhcp_relay_interface *interface, sd_dhcp_message *message);

int upstream_register(sd_dhcp_relay_interface *interface);
void upstream_unregister(sd_dhcp_relay_interface *interface);
void upstream_done(sd_dhcp_relay_interface *interface);
int upstream_get(sd_dhcp_relay *relay, sd_dhcp_relay_interface **ret);
int upstream_open_socket(sd_dhcp_relay_interface *interface);
int upstream_process_message(sd_dhcp_relay_interface *interface, const struct iovec *iov);
int upstream_receive_message(sd_event_source *s, int fd, uint32_t revents, void *userdata);
int upstream_send_message(sd_dhcp_relay_interface *interface, sd_dhcp_message *message);

#define log_dhcp_relay_interface_errno(interface, error, fmt, ...)      \
        log_interface_prefix_full_errno(                                \
                        "DHCPv4 relay: ",                               \
                        sd_dhcp_relay_interface, interface,             \
                        error, fmt, ##__VA_ARGS__)
#define log_dhcp_relay_interface(interface, fmt, ...)                   \
        log_interface_prefix_full_errno_zerook(                         \
                        "DHCPv4 relay: ",                               \
                        sd_dhcp_relay_interface, interface,             \
                        0, fmt, ##__VA_ARGS__)
