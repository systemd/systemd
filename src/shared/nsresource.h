/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

/* Helpful constants for the only numbers of UIDs that can currently be allocated */
#define NSRESOURCE_UIDS_64K 0x10000U
#define NSRESOURCE_UIDS_1 1U

int nsresource_connect(sd_varlink **ret);

/* All the calls below take a 'link' parameter, that may be an already established Varlink connection object
 * towards systemd-nsresourced, previously created via nsresource_connect(). This serves two purposes: first
 * of all allows more efficient resource usage, as this allows recycling already allocated resources for
 * multiple calls. Secondly, the user credentials are pinned at time of nsresource_connect(), and the caller
 * hence can drop privileges afterwards while keeping open the connection and still execute relevant
 * operations under the original identity, until the connection is closed. The 'link' parameter may be passed
 * as NULL in which case a short-lived connection is created, just to execute the requested operation. */

int nsresource_allocate_userns_full(sd_varlink *vl, const char *name, uint64_t size, uint64_t delegate_container_ranges);
static inline int nsresource_allocate_userns(sd_varlink *vl, const char *name, uint64_t size) {
        return nsresource_allocate_userns_full(vl, name, size, /* delegate_container_ranges= */ 0);
}
int nsresource_register_userns(sd_varlink *vl, const char *name, int userns_fd);
int nsresource_add_mount(sd_varlink *vl, int userns_fd, int mount_fd);
int nsresource_add_cgroup(sd_varlink *vl, int userns_fd, int cgroup_fd);
int nsresource_add_netif_veth(sd_varlink *vl, int userns_fd, int netns_fd, const char *namespace_ifname, char **ret_host_ifname, char **ret_namespace_ifname);
int nsresource_add_netif_tap(sd_varlink *vl, int userns_fd, char **ret_host_ifname);
