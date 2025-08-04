/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "sd-dhcp6-client.h"

int dhcp6_client_set_state_callback(
                sd_dhcp6_client *client,
                sd_dhcp6_client_callback_t cb,
                void *userdata);
int dhcp6_client_get_state(sd_dhcp6_client *client);
