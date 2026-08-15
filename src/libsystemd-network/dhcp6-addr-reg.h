/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  DHCPv6 Address Registration (RFC 9686).
***/

#include <netinet/in.h>

#include "forward.h"

/* Registers (or updates, or de-registers when valid_until_usec == 0) the given global-scope address
 * with the DHCPv6 server(s) on the link, per RFC 9686. valid_until_usec and preferred_until_usec are
 * absolute CLOCK_BOOTTIME timestamps, not durations; USEC_INFINITY marks a lifetime as never
 * expiring. This creates (on first call for a given address) or reuses the shared per-client socket
 * used for ADDR-REG-INFORM/ADDR-REG-REPLY exchanges, and takes care of retransmission and periodic
 * refresh of the registration for as long as the client exists. */
int dhcp6_client_register_address(
                sd_dhcp6_client *client,
                const struct in6_addr *address,
                usec_t valid_until_usec,
                usec_t preferred_until_usec);

/* Drops the registration tracking entry for a single address without sending a de-registration
 * message. Use this when the address is already gone from the interface and sending is impossible. */
void dhcp6_client_drop_address_registration(sd_dhcp6_client *client, const struct in6_addr *address);

/* Tears down all address registrations of the client, best-effort notifying the server(s) that the
 * addresses are no longer in use, and releases the shared socket. Safe to call multiple times. */
void dhcp6_client_addr_reg_flush(sd_dhcp6_client *client);
