/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp6-client.h"

#include "dhcp6-client-internal.h"
#include "forward.h"

typedef struct DHCP6AddressRegistrationEngine {
        bool enabled;
        bool supported;
} DHCP6AddressRegistrationEngine;

int dhcp6_client_address_registration_discover(
                sd_dhcp6_client *client,
                uint8_t message_type,
                bool advertised);
