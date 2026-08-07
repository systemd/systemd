/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  DHCPv6 Address Registration (RFC 9686).
***/

#include "forward.h"

/* Registers (or updates, or de-registers when valid_until_usec == 0) the given global-scope address
 * with the DHCPv6 server(s) on the link, per RFC 9686. valid_until_usec and preferred_until_usec are
 * absolute CLOCK_BOOTTIME timestamps; USEC_INFINITY marks a lifetime as never expiring. This creates
 * (on first call for a given address) or reuses the shared per-client socket used for ADDR-REG-INFORM
 * and ADDR-REG-REPLY exchanges, and takes care of retransmission and periodic refresh of the
 * registration for as long as the client exists. */
int dhcp6_client_register_address(
                sd_dhcp6_client *client,
                const struct in6_addr *address,
                usec_t valid_until_usec,
                usec_t preferred_until_usec);

/* Drops the registration tracking entry for a single address without sending a de-registration
 * message. Use this when the address is already gone from the interface and sending is impossible. */
void dhcp6_client_drop_address_registration(sd_dhcp6_client *client, const struct in6_addr *address);

/* Returns true once the registration process has started on the link, i.e. after the first address was
 * registered, and until dhcp6_client_addr_reg_flush() is called. RFC 9686 section 4.4: once started, the
 * client must keep registering addresses until it disconnects from the link, even if subsequent DHCPv6
 * replies no longer carry OPTION_ADDR_REG_ENABLE. */
bool dhcp6_client_addr_reg_is_active(sd_dhcp6_client *client);

/* Tears down all address registrations of the client without notifying the server(s), and releases
 * the shared socket. To be called when disconnecting from the link; also called when the client is
 * freed. Safe to call multiple times. */
void dhcp6_client_addr_reg_flush(sd_dhcp6_client *client);
