/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdcloudproviderfoo
#define foosdcloudproviderfoo

/***
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

#include <inttypes.h>
#include <sys/types.h>

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
 * See sd-cloud-provider(3) for more information.
 */

_SD_BEGIN_DECLARATIONS;

int sd_cloud_provider_azure_link_get_ipv4_private_ips(int ifindex, char ***ret);
int sd_cloud_provider_azure_link_get_ipv4_public_ips(int ifindex, char ***ret);
int sd_cloud_provider_azure_link_get_ipv4_subnet(int ifindex, char ***ret);

int sd_cloud_provider_azure_get_ipv4_prefixlen(int ifindex, char **prefixlen);

/* Monitor object */
typedef struct sd_cloud_provider_monitor sd_cloud_provider_monitor;

/* Create a new monitor. */
int sd_cloud_provider_monitor_new(sd_cloud_provider_monitor **ret);

/* Destroys the passed monitor. Returns NULL. */
sd_cloud_provider_monitor* sd_cloud_provider_monitor_unref(sd_cloud_provider_monitor *m);

/* Flushes the monitor */
int sd_cloud_provider_monitor_flush(sd_cloud_provider_monitor *m);

/* Get FD from monitor */
int sd_cloud_provider_monitor_get_fd(sd_cloud_provider_monitor *m);

/* Get poll() mask to monitor */
int sd_cloud_provider_monitor_get_events(sd_cloud_provider_monitor *m);

/* Get timeout for poll(), as usec value relative to CLOCK_MONOTONIC's epoch */
int sd_cloud_provider_monitor_get_timeout(sd_cloud_provider_monitor *m, uint64_t *timeout_usec);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_cloud_provider_monitor, sd_cloud_provider_monitor_unref);

_SD_END_DECLARATIONS;

#endif
