/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include <linux/types.h>
#include <stdint.h>

/*
 * Bind rule is matched with socket fields accessible to cgroup/bind{4,6} hook
 * through bpf_sock_addr struct.
 * 'address_family' is expected to be one of AF_UNSPEC, AF_INET, AF_INET6 or the
 * magic SOCKET_BIND_RULE_AF_MATCH_NOTHING.
 * Matching by family is bypassed for rules with AF_UNSPEC set, which makes the
 * rest of a rule applicable for both IPv4 and IPv6 addresses.
 * If SOCKET_BIND_RULE_AF_MATCH_NOTHING is set the rule fails unconditionally
 * and other checks are skipped.
 * If matching by family is either successful or bypassed, a rule and a socket
 * are matched by ip protocol.
 * If 'protocol' is 0, matching is bypassed.
 * 'nr_ports' and 'port_min' fields specify a set of ports to match a user port
 * with.
 * If 'nr_ports' is 0, matching by port is bypassed, making that rule applicable
 * for all possible ports, e.g. [1, 65535] range. Thus a rule with
 * 'address_family', 'protocol' and 'nr_ports' equal to AF_UNSPEC, 0 and 0
 * correspondingly forms 'allow any' or 'deny any' cases.
 * For positive 'nr_ports', a user_port lying in a range from 'port_min' to'
 * 'port_min' + 'nr_ports' exclusively is considered to be a match. 'nr_ports'
 * equalling to 1 forms a rule for a single port.
 * Ports are in host order.
 *
 * Examples:
 * AF_UNSPEC, 1, 0, 7777: match IPv4 and IPv6 addresses with 7777 user port;
 *
 * AF_INET, 1023, 0, 1: match IPv4 addresses with user port in [1, 1023]
 * range inclusively;
 *
 * AF_INET6, 0, 0, 0: match IPv6 addresses;
 *
 * AF_UNSPEC, 0, 0, 0: match IPv4 and IPv6 addresses;
 *
 * AF_INET6, IPPROTO_TCP, 0, 0: match IPv6/TCP addresses.
 */

struct socket_bind_rule {
        __u32 address_family;
        __u32 protocol;
        __u16 nr_ports;
        __u16 port_min;
};

#define SOCKET_BIND_MAX_RULES 128
#define SOCKET_BIND_RULE_AF_MATCH_NOTHING UINT32_MAX
