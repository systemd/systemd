/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-client.h"

#include "dhcp-client-id-internal.h"
#include "ether-addr-util.h"
#include "iovec-wrapper.h"
#include "network-common.h"
#include "sd-forward.h"
#include "socket-util.h"
#include "tlv-util.h"

typedef enum DHCPState {
        DHCP_STATE_STOPPED,
        DHCP_STATE_INIT,
        DHCP_STATE_SELECTING,
        DHCP_STATE_INIT_REBOOT,
        DHCP_STATE_REBOOTING,
        DHCP_STATE_REQUESTING,
        DHCP_STATE_BOUND,
        DHCP_STATE_RENEWING,
        DHCP_STATE_REBINDING,
        _DHCP_STATE_MAX,
        _DHCP_STATE_INVALID                     = -EINVAL,
} DHCPState;

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(dhcp_state, DHCPState);

struct sd_dhcp_client {
        unsigned n_ref;

        DHCPState state;
        sd_event *event;
        int event_priority;
        sd_event_source *timeout_resend;

        int ifindex;
        char *ifname;

        sd_device *dev;

        uint16_t port;
        uint16_t server_port;
        union sockaddr_union link;
        sd_event_source *receive_message;
        bool request_broadcast;
        Set *req_opts;
        bool anonymize;
        bool rapid_commit;
        be32_t last_addr;
        struct hw_addr_data hw_addr;
        struct hw_addr_data bcast_addr;
        uint16_t arp_type;
        sd_dhcp_client_id client_id;
        char *hostname;
        char *vendor_class_identifier;
        char *mudurl;
        struct iovec_wrapper user_class;
        uint32_t mtu;
        usec_t fallback_lease_lifetime;
        uint32_t xid;
        usec_t start_time;
        usec_t t1_time;
        usec_t t2_time;
        usec_t expire_time;
        uint64_t discover_attempt;
        uint64_t request_attempt;
        uint64_t max_discover_attempts;
        TLV *extra_options;
        TLV *vendor_options;
        sd_event_source *timeout_t1;
        sd_event_source *timeout_t2;
        sd_event_source *timeout_expire;
        sd_dhcp_client_callback_t callback;
        void *userdata;
        sd_dhcp_client_callback_t state_callback;
        void *state_userdata;
        sd_dhcp_lease *lease;
        usec_t start_delay;
        uint8_t ip_service_type;
        int socket_priority;
        bool ipv6_acquired;
        bool bootp;
        bool send_release;
};

int dhcp_client_set_state_callback(
                sd_dhcp_client *client,
                sd_dhcp_client_callback_t cb,
                void *userdata);
int dhcp_client_get_state(sd_dhcp_client *client);

int dhcp_client_set_extra_options(sd_dhcp_client *client, TLV *options);
int dhcp_client_set_vendor_options(sd_dhcp_client *client, TLV *options);
int dhcp_client_set_user_class(sd_dhcp_client *client, const struct iovec_wrapper *user_class);

int client_receive_message_raw(
                sd_event_source *s,
                int fd,
                uint32_t revents,
                void *userdata);
int client_receive_message_udp(
                sd_event_source *s,
                int fd,
                uint32_t revents,
                void *userdata);

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
