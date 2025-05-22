/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int nsresource_allocate_userns(const char *name, uint64_t size);
int nsresource_register_userns(const char *name, int userns_fd);
int nsresource_add_mount(int userns_fd, int mount_fd);
int nsresource_add_cgroup(int userns_fd, int cgroup_fd);
int nsresource_add_netif_veth(int userns_fd, int netns_fd, const char *namespace_ifname, char **ret_host_ifname, char **ret_namespace_ifname);
int nsresource_add_netif_tap(int userns_fd, char **ret_host_ifname);
