/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>

#include "sd-dhcp-client.h"

#include "macro.h"
#include "network-common.h"

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

const char* dhcp_state_to_string(DHCPState s) _const_;

typedef struct sd_dhcp_client sd_dhcp_client;

int dhcp_client_set_state_callback(
                sd_dhcp_client *client,
                sd_dhcp_client_callback_t cb,
                void *userdata);
int dhcp_client_get_state(sd_dhcp_client *client);

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
