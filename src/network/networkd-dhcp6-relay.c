/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-dhcp6-relay.h"

#include "conf-parser.h"
#include "in-addr-util.h"
#include "networkd-dhcp6-relay.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "string-util.h"

int dhcp6_relay_configure(Link *link) {
        _cleanup_(sd_dhcp6_relay_unrefp) sd_dhcp6_relay *relay = NULL;
        int r;

        assert(link);
        assert(link->network);

        if (!in6_addr_is_set(&link->network->dhcp6_relay_target))
                return 0;

        if (sd_dhcp6_relay_is_running(link->dhcp6_relay))
                return 0;

        r = sd_dhcp6_relay_new(&relay);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to create DHCPv6 relay agent: %m");

        r = sd_dhcp6_relay_set_ifindex(relay, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set ifindex for DHCPv6 relay agent: %m");

        r = sd_dhcp6_relay_set_ifname(relay, link->ifname);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set ifname for DHCPv6 relay agent: %m");

        r = sd_dhcp6_relay_attach_event(relay, link->manager->event, 0);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to attach event for DHCPv6 relay agent: %m");

        if (in6_addr_is_set(&link->ipv6ll_address)) {
                r = sd_dhcp6_relay_set_link_address(relay, &link->ipv6ll_address);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set link address for DHCPv6 relay agent: %m");
        }

        r = sd_dhcp6_relay_set_relay_target(relay, &link->network->dhcp6_relay_target);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to set relay target for DHCPv6 relay agent: %m");

        if (link->network->dhcp6_relay_interface_id) {
                r = sd_dhcp6_relay_set_interface_id(relay, link->network->dhcp6_relay_interface_id);
                if (r < 0)
                        return log_link_error_errno(link, r, "Failed to set interface ID for DHCPv6 relay agent: %m");
        }

        r = sd_dhcp6_relay_start(relay);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to start DHCPv6 relay agent: %m");

        sd_dhcp6_relay_unref(link->dhcp6_relay);
        link->dhcp6_relay = TAKE_PTR(relay);
        return 0;
}

int config_parse_dhcp6_relay_interface_id(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(userdata);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->dhcp6_relay_interface_id = mfree(network->dhcp6_relay_interface_id);
                return 0;
        }

        return free_and_strdup(&network->dhcp6_relay_interface_id, rvalue);
}
