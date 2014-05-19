/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosdnetworkhfoo
#define foosdnetworkhfoo

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering
  Copyright 2014 Tom Gundersen

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/types.h>
#include <inttypes.h>

#include "sd-dhcp-lease.h"

#include "_sd-common.h"

/*
 * A few points:
 *
 * Instead of returning an empty string array or empty integer array, we
 * may return NULL.
 *
 * Free the data the library returns with libc free(). String arrays
 * are NULL terminated, and you need to free the array itself in
 * addition to the strings contained.
 *
 * We return error codes as negative errno, kernel-style. On success, we
 * return 0 or positive.
 *
 * These functions access data in /run. This is a virtual file system;
 * therefore, accesses are relatively cheap.
 *
 * See sd-network(3) for more information.
 */

_SD_BEGIN_DECLARATIONS;

/* Get state from ifindex.
 * Possible states: failed, configuring, configured
 * Possible return codes:
 *   -ENODATA: networkd is not aware of the link
 *   -EUNATCH: networkd is not managing this link
 *   -EBUSY: udev is still processing the link, networkd does not yet know if it will manage it
 */
int sd_network_get_link_state(unsigned index, char **state);

/* Get operatinal state from ifindex.
 * Possible states: unknown, dormant, carrier, degraded, routable
 * Possible return codes:
 *   -ENODATA: networkd is not aware of the link
 */
int sd_network_get_link_operational_state(unsigned index, char **state);

/* Get overall opeartional state
 * Possible states: unknown, dormant, carrier, degraded, routable
 * Possible return codes:
 *   -ENODATA: networkd is not aware of any links
 */
int sd_network_get_operational_state(char **state);

/* Returns true if link exists and is loopback, and false otherwise */
int sd_network_link_is_loopback(unsigned index);

/* Get DHCPv4 lease from ifindex. */
int sd_network_get_dhcp_lease(unsigned index, sd_dhcp_lease **ret);

/* Returns true if link is configured to respect DNS entries received by DHCP */
int sd_network_dhcp_use_dns(unsigned index);

/* Returns true if link is configured to respect NTP entries received by DHCP */
int sd_network_dhcp_use_ntp(unsigned index);

/* Get IPv4 DNS entries statically configured for the link */
int sd_network_get_dns(unsigned index, struct in_addr **addr, size_t *addr_size);

/* Get IPv4 NTP entries statically configured for the link */
int sd_network_get_ntp(unsigned index, struct in_addr **addr, size_t *addr_size);

/* Get IPv6 DNS entries statically configured for the link */
int sd_network_get_dns6(unsigned index, struct in6_addr **addr, size_t *addr_size);

/* Get IPv6 NTP entries statically configured for the link */
int sd_network_get_ntp6(unsigned index, struct in6_addr **addr, size_t *addr_size);

/* Get all network interfaces' indices, and store them in *indices. Returns
 * the number of indices. If indices is NULL, only returns the number of indices. */
int sd_network_get_ifindices(unsigned **indices);

/* Monitor object */
typedef struct sd_network_monitor sd_network_monitor;

/* Create a new monitor. Category must be NULL, "links" or "leases". */
int sd_network_monitor_new(const char *category, sd_network_monitor **ret);

/* Destroys the passed monitor. Returns NULL. */
sd_network_monitor* sd_network_monitor_unref(sd_network_monitor *m);

/* Flushes the monitor */
int sd_network_monitor_flush(sd_network_monitor *m);

/* Get FD from monitor */
int sd_network_monitor_get_fd(sd_network_monitor *m);

/* Get poll() mask to monitor */
int sd_network_monitor_get_events(sd_network_monitor *m);

/* Get timeout for poll(), as usec value relative to CLOCK_MONOTONIC's epoch */
int sd_network_monitor_get_timeout(sd_network_monitor *m, uint64_t *timeout_usec);

_SD_END_DECLARATIONS;

#endif
