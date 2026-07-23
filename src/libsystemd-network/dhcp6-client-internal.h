/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "sd-dhcp6-client.h"
#include "time-util.h"

#define DHCP6_ADDRESS_REGISTRATION_DEFAULT_IRT (1 * USEC_PER_SEC)
#define DHCP6_ADDRESS_REGISTRATION_DEFAULT_MRC 3U

int dhcp6_client_set_state_callback(
                sd_dhcp6_client *client,
                sd_dhcp6_client_callback_t cb,
                void *userdata);
int dhcp6_client_get_state(sd_dhcp6_client *client);

int dhcp6_client_set_address_registration_enabled(sd_dhcp6_client *client, bool enabled);
int dhcp6_client_update_address_registration(
                sd_dhcp6_client *client,
                const struct in6_addr *address,
                usec_t lifetime_preferred_usec,
                usec_t lifetime_valid_usec);
void dhcp6_client_remove_address_registration(
                sd_dhcp6_client *client,
                const struct in6_addr *address);
void dhcp6_client_address_registration_reset(sd_dhcp6_client *client);
