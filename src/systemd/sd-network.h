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

/* Get overall operational state
 * Possible states: down, up, dormant, carrier, degraded, routable
 * Possible return codes:
 *   -ENODATA: networkd is not aware of any links
 */
int sd_network_get_operational_state(char **state);

/* Get DNS entries for all links. These are string representations of
 * IP addresses */
int sd_network_get_dns(char ***dns);

/* Get NTP entries for all links. These are domain names or string
 * representations of IP addresses */
int sd_network_get_ntp(char ***ntp);

/* Get the search/routing domains for all links. */
int sd_network_get_domains(char ***domains);

/* Get setup state from ifindex.
 * Possible states:
 *   pending: udev is still processing the link, we don't yet know if we will manage it
 *   failed: networkd failed to manage the link
 *   configuring: in the process of retrieving configuration or configuring the link
 *   configured: link configured successfully
 *   unmanaged: networkd is not handling the link
 *   linger: the link is gone, but has not yet been dropped by networkd
 * Possible return codes:
 *   -ENODATA: networkd is not aware of the link
 */
int sd_network_link_get_setup_state(int ifindex, char **state);

/* Get operational state from ifindex.
 * Possible states:
 *   off: the device is powered down
 *   no-carrier: the device is powered up, but it does not yet have a carrier
 *   dormant: the device has a carrier, but is not yet ready for normal traffic
 *   carrier: the link has a carrier
 *   degraded: the link has carrier and addresses valid on the local link configured
 *   routable: the link has carrier and routable address configured
 * Possible return codes:
 *   -ENODATA: networkd is not aware of the link
 */
int sd_network_link_get_operational_state(int ifindex, char **state);

/* Get path to .network file applied to link */
int sd_network_link_get_network_file(int ifindex, char **filename);

/* Get DNS entries for a given link. These are string representations of
 * IP addresses */
int sd_network_link_get_dns(int ifindex, char ***addr);

/* Get NTP entries for a given link. These are domain names or string
 * representations of IP addresses */
int sd_network_link_get_ntp(int ifindex, char ***addr);

/* Indicates whether or not LLMNR should be enabled for the link
 * Possible levels of support: yes, no, resolve
 * Possible return codes:
 *   -ENODATA: networkd is not aware of the link
 */
int sd_network_link_get_llmnr(int ifindex, char **llmnr);

int sd_network_link_get_lldp(int ifindex, char **lldp);

/* Get the DNS domain names for a given link. */
int sd_network_link_get_domains(int ifindex, char ***domains);

/* Get the CARRIERS to which current link is bound to. */
int sd_network_link_get_carrier_bound_to(int ifindex, char ***carriers);

/* Get the CARRIERS that are bound to current link. */
int sd_network_link_get_carrier_bound_by(int ifindex, char ***carriers);

/* Get the timezone that was learnt on a specific link. */
int sd_network_link_get_timezone(int ifindex, char **timezone);

/* Returns whether or not domains that don't match any link should be resolved
 * on this link. 1 for yes, 0 for no and negative value for error */
int sd_network_link_get_wildcard_domain(int ifindex);

/* Monitor object */
typedef struct sd_network_monitor sd_network_monitor;

/* Create a new monitor. Category must be NULL, "links" or "leases". */
int sd_network_monitor_new(sd_network_monitor **ret, const char *category);

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
