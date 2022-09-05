/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <net/if.h>
#include <stdbool.h>
#include <sys/types.h>

int test_network_interface_initialized(const char *name);

int setup_veth(const char *machine_name, pid_t pid, char iface_name[IFNAMSIZ], bool bridge);
int setup_veth_extra(const char *machine_name, pid_t pid, char **pairs);

int setup_bridge(const char *veth_name, const char *bridge_name, bool create);
int remove_bridge(const char *bridge_name);

int setup_macvlan(const char *machine_name, pid_t pid, char **pairs);
int setup_ipvlan(const char *machine_name, pid_t pid, char **pairs);

int move_network_interfaces(int netns_fd, char **pairs);

int veth_extra_parse(char ***l, const char *p);

int remove_veth_links(const char *primary, char **pairs);

int network_interface_parse_and_test(char ***l, const char *p);

int network_macvlan_parse_and_test(char ***l, const char *p);

int network_ipvlan_parse_and_test(char ***l, const char *p);
