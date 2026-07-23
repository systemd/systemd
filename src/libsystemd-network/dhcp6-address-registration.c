/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dhcp6-address-registration.h"
#include "dhcp6-internal.h"
#include "dhcp6-protocol.h"

int dhcp6_client_set_address_registration_enabled(sd_dhcp6_client *client, bool enabled) {
        assert_return(client, -EINVAL);
        assert_return(!sd_dhcp6_client_is_running(client), -EBUSY);

        client->address_registration.enabled = enabled;
        if (!enabled)
                dhcp6_client_address_registration_reset(client);

        return 0;
}

int dhcp6_client_address_registration_discover(
                sd_dhcp6_client *client,
                uint8_t message_type,
                bool advertised) {

        assert(client);

        if (!IN_SET(message_type, DHCP6_MESSAGE_ADVERTISE, DHCP6_MESSAGE_REPLY))
                return 0;

        if (!client->address_registration.enabled || !advertised || client->address_registration.supported)
                return 0;

        client->address_registration.supported = true;
        return 1;
}

void dhcp6_client_address_registration_reset(sd_dhcp6_client *client) {
        assert(client);

        client->address_registration.supported = false;
}
