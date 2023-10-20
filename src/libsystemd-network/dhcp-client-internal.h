/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>

#include "sd-dhcp-client.h"

#include "macro.h"

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

const char *dhcp_state_to_string(DHCPState s) _const_;

extern const struct hash_ops dhcp_option_hash_ops;

int dhcp_client_set_state_callback(
                sd_dhcp_client *client,
                sd_dhcp_client_callback_t cb,
                void *userdata);
int dhcp_client_get_state(sd_dhcp_client *client);
