/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/rtnetlink.h>

#include "sd-event.h"
#include "sd-id128.h"

#include "conf-parser.h"
#include "dhcp-relay-internal.h"
#include "hashmap.h"
#include "iovec-util.h"
#include "networkd-address.h"
#include "networkd-dhcp-relay.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "string-table.h"
#include "string-util.h"  /* IWYU pragma: keep */

#define DHCP_RELAY_APP_REMOTE_ID SD_ID128_MAKE(85,bb,eb,d2,b8,56,47,0b,b0,86,4c,f3,d3,9b,c1,b5)

void network_adjust_dhcp_relay(Network *network) {
        assert(network);
        assert(network->manager);

        if (network->dhcp_relay_interface_mode < 0)
                return;

        if (in4_addr_is_null(&network->manager->dhcp_relay_server_address)) {
                log_warning("%s: DHCPRelay= is enabled, but [DHCPRelay] ServerAddress= in networkd.conf is not configured. Disabling DHCP relay agent.",
                            network->filename);
                network->dhcp_relay_interface_mode = _DHCP_RELAY_INTERFACE_INVALID;
                return;
        }

        Address *a;
        ORDERED_HASHMAP_FOREACH(a, network->addresses_by_section) {
                assert(!section_is_invalid(a->section));

                if (a->family != AF_INET)
                        continue;

                if (in4_addr_is_set(&network->dhcp_relay_agent_address_in_addr)) {
                        if (!in4_addr_equal(&a->in_addr.in, &network->dhcp_relay_agent_address_in_addr))
                                continue;

                } else {
                        if (in4_addr_is_localhost(&a->in_addr.in))
                                continue;

                        if (in4_addr_is_link_local(&a->in_addr.in))
                                continue;

                        if (a->scope != RT_SCOPE_UNIVERSE)
                                continue;
                }

                network->dhcp_relay_agent_address = a;
                break;
        }

        if (!network->dhcp_relay_agent_address) {
                log_warning("%s: DHCPRelay= is enabled, but no suitable static address configured. Disabling DHCP relay agent.",
                            network->filename);
                network->dhcp_relay_interface_mode = _DHCP_RELAY_INTERFACE_INVALID;
                return;
        }
}

static int manager_configure_dhcp_relay(Manager *manager) {
        int r;

        assert(manager);
        assert(manager->event);

        if (manager->dhcp_relay)
                return 0;

        if (in4_addr_is_null(&manager->dhcp_relay_server_address))
                return -EADDRNOTAVAIL;

        _cleanup_(sd_dhcp_relay_unrefp) sd_dhcp_relay *relay = NULL;
        r = sd_dhcp_relay_new(&relay);
        if (r < 0)
                return r;

        r = sd_dhcp_relay_attach_event(relay, manager->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        if (iovec_is_set(&manager->dhcp_relay_remote_id)) {
                r = sd_dhcp_relay_set_remote_id(relay, &manager->dhcp_relay_remote_id);
                if (r < 0)
                        return r;
        } else {
                sd_id128_t id;
                r = sd_id128_get_machine_app_specific(DHCP_RELAY_APP_REMOTE_ID, &id);
                if (r < 0)
                        return r;

                r = sd_dhcp_relay_set_remote_id(relay, &IOVEC_MAKE_STRING(SD_ID128_TO_STRING(id)));
                if (r < 0)
                        return r;
        }

        r = sd_dhcp_relay_set_server_identifier_override(relay, manager->dhcp_relay_override_server_id);
        if (r < 0)
                return r;

        r = dhcp_relay_set_extra_options(relay, &manager->dhcp_relay_extra_options);
        if (r < 0)
                return r;

        manager->dhcp_relay = TAKE_PTR(relay);
        return 0;
}

static int link_configure_dhcp_relay(Link *link) {
        int r;

        assert(link);
        assert(link->manager);
        assert(link->network);
        assert(!link->dhcp_relay_interface);
        assert(link->network->dhcp_relay_agent_address);
        assert(IN_SET(link->network->dhcp_relay_interface_mode, DHCP_RELAY_INTERFACE_UPSTREAM, DHCP_RELAY_INTERFACE_DOWNSTREAM));

        r = manager_configure_dhcp_relay(link->manager);
        if (r < 0)
                return r;

        bool upstream = link->network->dhcp_relay_interface_mode == DHCP_RELAY_INTERFACE_UPSTREAM;

        _cleanup_(sd_dhcp_relay_interface_unrefp) sd_dhcp_relay_interface *interface = NULL;
        r = sd_dhcp_relay_add_interface(link->manager->dhcp_relay, link->ifindex, upstream, &interface);
        if (r < 0)
                return r;

        r = sd_dhcp_relay_interface_set_ifname(interface, link->ifname);
        if (r < 0)
                return r;

        r = sd_dhcp_relay_interface_set_address(interface, &link->network->dhcp_relay_agent_address->in_addr.in);
        if (r < 0)
                return r;

        if (upstream) {
                r = sd_dhcp_relay_upstream_set_priority(interface, link->network->dhcp_relay_interface_priority);
                if (r < 0)
                        return r;
        } else {
                r = sd_dhcp_relay_downstream_set_gateway_address(interface, &link->network->dhcp_relay_gateway_address);
                if (r < 0)
                        return r;

                if (iovec_is_set(&link->network->dhcp_relay_circuit_id))
                        r = sd_dhcp_relay_downstream_set_circuit_id(interface, &link->network->dhcp_relay_circuit_id);
                else
                        r = sd_dhcp_relay_downstream_set_circuit_id(interface, &IOVEC_MAKE_STRING(link->ifname));
                if (r < 0)
                        return r;

                r = sd_dhcp_relay_downstream_set_virtual_subnet_selection(interface, &link->network->dhcp_relay_vss);
                if (r < 0)
                        return r;

                r = downstream_set_extra_options(interface, &link->network->dhcp_relay_extra_options);
                if (r < 0)
                        return r;
        }

        link->dhcp_relay_interface = TAKE_PTR(interface);
        return 0;
}

static bool dhcp_relay_is_ready_to_configure(Link *link) {
        assert(link);
        assert(link->network);

        if (!link_is_ready_to_configure(link, /* allow_unmanaged= */ false))
                return false;

        if (!link_has_carrier(link))
                return false;

        if (!link->static_addresses_configured)
                return false;

        Address *a;
        if (address_get(link, link->network->dhcp_relay_agent_address, &a) < 0)
                return false;

        if (!address_is_ready(a))
                return false;

        return true;
}

static int dhcp_relay_process_request(Request *req, Link *link, void *userdata) {
        int r;

        assert(link);

        if (!dhcp_relay_is_ready_to_configure(link))
                return 0;

        r = link_configure_dhcp_relay(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure DHCP relay agent: %m");

        log_link_debug(link, "DHCP relay agent is configured.");

        r = link_start_dhcp_relay(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to start DHCP relay agent: %m");

        return 1;
}

int link_request_dhcp_relay(Link *link) {
        int r;

        assert(link);
        assert(link->manager);

        if (link->manager->state != MANAGER_RUNNING)
                return 0;

        if (!link->network)
                return 0;

        if (link->network->dhcp_relay_interface_mode < 0)
                return 0;

        if (link->dhcp_relay_interface)
                return 0;

        r = link_queue_request(link, REQUEST_TYPE_DHCP_RELAY, dhcp_relay_process_request, NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request configuring of the DHCP relay agent: %m");

        log_link_debug(link, "Requested configuring of the DHCP relay agent.");
        return 0;
}

int link_start_dhcp_relay(Link *link) {
        int r;

        assert(link);
        assert(link->manager);

        if (!link->dhcp_relay_interface)
                return 0; /* Not configured yet. */

        if (!link_has_carrier(link))
                return 0;

        if (sd_dhcp_relay_interface_is_running(link->dhcp_relay_interface))
                return 0; /* already started. */

        r = sd_dhcp_relay_interface_start(link->dhcp_relay_interface);
        if (r < 0)
                return r;

        log_link_debug(link, "Relaying DHCPv4 messages.");
        return 0;
}

int link_dhcp_relay_address_dropped(Link *link, const Address *address) {
        int r;

        assert(link);
        assert(link->manager);
        assert(address);

        /* This is called when an address is removed from the interface. */

        if (link->manager->state != MANAGER_RUNNING)
                return 0;

        if (!link->network)
                return 0;

        if (!link->dhcp_relay_interface)
                return 0;

        struct in_addr a;
        r = sd_dhcp_relay_interface_get_address(link->dhcp_relay_interface, &a);
        if (r <= 0)
                return r;

        if (address->family != AF_INET)
                return 0;

        if (!in4_addr_equal(&address->in_addr.in, &a))
                return 0;

        r = sd_dhcp_relay_interface_stop(link->dhcp_relay_interface);
        if (r < 0)
                return r;

        link->dhcp_relay_interface = sd_dhcp_relay_interface_unref(link->dhcp_relay_interface);

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return 0;

        /* The address may be reconfigured later. Let's reconfigure DHCP relay interface when the address come back. */
        return link_request_dhcp_relay(link);
}

static const char * const dhcp_relay_interface_mode_table[_DHCP_RELAY_INTERFACE_MAX] = {
        [DHCP_RELAY_INTERFACE_UPSTREAM]   = "upstream",
        [DHCP_RELAY_INTERFACE_DOWNSTREAM] = "downstream",
};

DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(dhcp_relay_interface_mode, DHCPRelayInterfaceMode);

DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(
                config_parse_dhcp_relay_interface_mode,
                dhcp_relay_interface_mode,
                DHCPRelayInterfaceMode,
                _DHCP_RELAY_INTERFACE_INVALID);
