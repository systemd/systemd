/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-client.h"

extern const struct hash_ops dhcp_option_hash_ops;

int dhcp_client_set_state_callback(
                sd_dhcp_client *client,
                sd_dhcp_client_callback_t cb,
                void *userdata);
int dhcp_client_get_state(sd_dhcp_client *client);
