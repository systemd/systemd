/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <net/if.h>
#include <stdbool.h>
#include <sys/types.h>

#include "ether-addr-util.h"

int test_network_interfaces_initialized(char **iface_pairs);
int resolve_network_interface_names(char **iface_pairs);

int setup_veth(const char *machine_name, pid_t pid, char iface_name[IFNAMSIZ], bool bridge, const struct ether_addr *provided_mac);
int setup_veth_extra(const char *machine_name, pid_t pid, char **pairs);

int setup_bridge(const char *veth_name, const char *bridge_name, bool create);
int remove_bridge(const char *bridge_name);

int setup_macvlan(const char *machine_name, pid_t pid, char **iface_pairs);
int remove_macvlan(int child_netns_fd, char **interface_pairs);
int setup_ipvlan(const char *machine_name, pid_t pid, char **iface_pairs);

int move_network_interfaces(int netns_fd, char **iface_pairs);
int move_back_network_interfaces(int child_netns_fd, char **interface_pairs);

int veth_extra_parse(char ***l, const char *p);

int remove_veth_links(const char *primary, char **pairs);

int interface_pair_parse(char ***l, const char *p);
int macvlan_pair_parse(char ***l, const char *p);
int ipvlan_pair_parse(char ***l, const char *p);
