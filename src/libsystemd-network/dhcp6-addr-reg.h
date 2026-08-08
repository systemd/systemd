/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  DHCPv6 Address Registration (RFC 9686).
***/

#include <netinet/in.h>

#include "forward.h"

/* Registers (or updates, or de-registers when lifetime_valid_usec == 0) the given global-scope address
 * with the DHCPv6 server(s) on the link, per RFC 9686. This creates (on first call for a given address) or
 * reuses the shared per-client socket used for ADDR-REG-INFORM/ADDR-REG-REPLY exchanges, and takes care of
 * retransmission and periodic refresh of the registration for as long as the client exists. */
int dhcp6_client_register_address(
                sd_dhcp6_client *client,
                const struct in6_addr *address,
                usec_t lifetime_valid_usec,
                usec_t lifetime_preferred_usec);

/* Tears down all address registrations of the client, best-effort notifying the server(s) that the
 * addresses are no longer in use, and releases the shared socket. Safe to call multiple times. */
void dhcp6_client_addr_reg_flush(sd_dhcp6_client *client);
