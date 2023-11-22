/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_link.h>
#include <linux/netdevice.h>
#include <sys/socket.h>
#include <unistd.h>

#include "alloc-util.h"
#include "arphrd-util.h"
#include "batadv.h"
#include "bond.h"
#include "bridge.h"
#include "bus-util.h"
#include "device-private.h"
#include "device-util.h"
#include "dhcp-identifier.h"
#include "dhcp-lease-internal.h"
#include "env-file.h"
#include "ethtool-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "logarithm.h"
#include "missing_network.h"
#include "netlink-util.h"
#include "network-internal.h"
#include "networkd-address-label.h"
#include "networkd-address.h"
#include "networkd-bridge-fdb.h"
#include "networkd-bridge-mdb.h"
#include "networkd-bridge-vlan.h"
#include "networkd-can.h"
#include "networkd-dhcp-prefix-delegation.h"
#include "networkd-dhcp-server.h"
#include "networkd-dhcp4.h"
#include "networkd-dhcp6.h"
#include "networkd-ipv4acd.h"
#include "networkd-ipv4ll.h"
#include "networkd-ipv6-proxy-ndp.h"
#include "networkd-link-bus.h"
#include "networkd-link.h"
#include "networkd-lldp-tx.h"
#include "networkd-manager.h"
#include "networkd-ndisc.h"
#include "networkd-neighbor.h"
#include "networkd-nexthop.h"
#include "networkd-queue.h"
#include "networkd-radv.h"
#include "networkd-route-util.h"
#include "networkd-route.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-setlink.h"
#include "networkd-sriov.h"
#include "networkd-state-file.h"
#include "networkd-sysctl.h"
#include "networkd-wifi.h"
#include "set.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "strv.h"
#include "tc.h"
#include "tmpfile-util.h"
#include "tuntap.h"
#include "udev-util.h"
#include "vrf.h"

bool link_ipv6_enabled(Link *link) {
        assert(link);

        if (!socket_ipv6_is_supported())
                return false;

        if (link->iftype == ARPHRD_CAN)
                return false;

        if (!link->network)
                return false;

        if (link->network->bond)
                return false;

        if (link_may_have_ipv6ll(link, /* check_multicast = */ false))
                return true;

        if (network_has_static_ipv6_configurations(link->network))
                return true;

        return false;
}

bool link_has_ipv6_connectivity(Link *link) {
        LinkAddressState ipv6_address_state;

        assert(link);

        link_get_address_states(link, NULL, &ipv6_address_state, NULL);

        switch (ipv6_address_state) {
        case LINK_ADDRESS_STATE_ROUTABLE:
                /* If the interface has a routable IPv6 address, then we assume yes. */
                return true;

        case LINK_ADDRESS_STATE_DEGRADED:
                /* If the interface has only degraded IPv6 address (mostly, link-local address), then let's check
                 * there is an IPv6 default gateway. */
                return link_has_default_gateway(link, AF_INET6);

        case LINK_ADDRESS_STATE_OFF:
                /* No IPv6 address. */
                return false;

        default:
                assert_not_reached();
        }
}

static bool link_is_ready_to_configure_one(Link *link, bool allow_unmanaged) {
        assert(link);

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED, LINK_STATE_UNMANAGED))
                return false;

        if (!link->network)
                return allow_unmanaged;

        if (!link->network->configure_without_carrier) {
                if (link->set_flags_messages > 0)
                        return false;

                if (!link_has_carrier(link))
                        return false;
        }

        if (link->set_link_messages > 0)
                return false;

        if (!link->activated)
                return false;

        return true;
}

bool link_is_ready_to_configure(Link *link, bool allow_unmanaged) {
        return check_ready_for_all_sr_iov_ports(link, allow_unmanaged, link_is_ready_to_configure_one);
}

void link_ntp_settings_clear(Link *link) {
        link->ntp = strv_free(link->ntp);
}

void link_dns_settings_clear(Link *link) {
        if (link->n_dns != UINT_MAX)
                for (unsigned i = 0; i < link->n_dns; i++)
                        in_addr_full_free(link->dns[i]);
        link->dns = mfree(link->dns);
        link->n_dns = UINT_MAX;

        link->search_domains = ordered_set_free(link->search_domains);
        link->route_domains = ordered_set_free(link->route_domains);

        link->dns_default_route = -1;
        link->llmnr = _RESOLVE_SUPPORT_INVALID;
        link->mdns = _RESOLVE_SUPPORT_INVALID;
        link->dnssec_mode = _DNSSEC_MODE_INVALID;
        link->dns_over_tls_mode = _DNS_OVER_TLS_MODE_INVALID;

        link->dnssec_negative_trust_anchors = set_free_free(link->dnssec_negative_trust_anchors);
}

static void link_free_engines(Link *link) {
        if (!link)
                return;

        link->dhcp_server = sd_dhcp_server_unref(link->dhcp_server);

        link->dhcp_client = sd_dhcp_client_unref(link->dhcp_client);
        link->dhcp_lease = sd_dhcp_lease_unref(link->dhcp_lease);
        link->dhcp4_6rd_tunnel_name = mfree(link->dhcp4_6rd_tunnel_name);

        link->lldp_rx = sd_lldp_rx_unref(link->lldp_rx);
        link->lldp_tx = sd_lldp_tx_unref(link->lldp_tx);

        link->ipv4acd_by_address = hashmap_free(link->ipv4acd_by_address);

        link->ipv4ll = sd_ipv4ll_unref(link->ipv4ll);

        link->dhcp6_client = sd_dhcp6_client_unref(link->dhcp6_client);
        link->dhcp6_lease = sd_dhcp6_lease_unref(link->dhcp6_lease);

        link->ndisc = sd_ndisc_unref(link->ndisc);
        link->ndisc_expire = sd_event_source_disable_unref(link->ndisc_expire);
        ndisc_flush(link);

        link->radv = sd_radv_unref(link->radv);
}

static Link *link_free(Link *link) {
        assert(link);

        link_ntp_settings_clear(link);
        link_dns_settings_clear(link);

        link->routes = set_free(link->routes);
        link->nexthops = set_free(link->nexthops);
        link->neighbors = set_free(link->neighbors);
        link->addresses = set_free(link->addresses);
        link->qdiscs = set_free(link->qdiscs);
        link->tclasses = set_free(link->tclasses);

        link->dhcp_pd_prefixes = set_free(link->dhcp_pd_prefixes);

        link_free_engines(link);

        set_free(link->sr_iov_virt_port_ifindices);
        free(link->ifname);
        strv_free(link->alternative_names);
        free(link->kind);
        free(link->ssid);
        free(link->previous_ssid);
        free(link->driver);

        unlink_and_free(link->lease_file);
        unlink_and_free(link->lldp_file);
        unlink_and_free(link->state_file);

        sd_device_unref(link->dev);
        netdev_unref(link->netdev);

        hashmap_free(link->bound_to_links);
        hashmap_free(link->bound_by_links);

        set_free_with_destructor(link->slaves, link_unref);

        network_unref(link->network);

        sd_event_source_disable_unref(link->carrier_lost_timer);

        return mfree(link);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Link, link, link_free);

int link_get_by_index(Manager *m, int ifindex, Link **ret) {
        Link *link;

        assert(m);
        assert(ifindex > 0);

        link = hashmap_get(m->links_by_index, INT_TO_PTR(ifindex));
        if (!link)
                return -ENODEV;

        if (ret)
                *ret = link;
        return 0;
}

int link_get_by_name(Manager *m, const char *ifname, Link **ret) {
        Link *link;

        assert(m);
        assert(ifname);

        link = hashmap_get(m->links_by_name, ifname);
        if (!link)
                return -ENODEV;

        if (ret)
                *ret = link;
        return 0;
}

int link_get_by_hw_addr(Manager *m, const struct hw_addr_data *hw_addr, Link **ret) {
        Link *link;

        assert(m);
        assert(hw_addr);

        link = hashmap_get(m->links_by_hw_addr, hw_addr);
        if (!link)
                return -ENODEV;

        if (ret)
                *ret = link;
        return 0;
}

int link_get_master(Link *link, Link **ret) {
        assert(link);
        assert(link->manager);
        assert(ret);

        if (link->master_ifindex <= 0 || link->master_ifindex == link->ifindex)
                return -ENODEV;

        return link_get_by_index(link->manager, link->master_ifindex, ret);
}

void link_set_state(Link *link, LinkState state) {
        assert(link);

        if (link->state == state)
                return;

        log_link_debug(link, "State changed: %s -> %s",
                       link_state_to_string(link->state),
                       link_state_to_string(state));

        link->state = state;

        link_send_changed(link, "AdministrativeState", NULL);
        link_dirty(link);
}

int link_stop_engines(Link *link, bool may_keep_dhcp) {
        int r = 0, k;

        assert(link);
        assert(link->manager);
        assert(link->manager->event);

        bool keep_dhcp = may_keep_dhcp &&
                         link->network &&
                         !link->network->dhcp_send_decline && /* IPv4 ACD for the DHCPv4 address is running. */
                         (link->manager->restarting ||
                          FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP_ON_STOP));

        if (!keep_dhcp) {
                k = sd_dhcp_client_stop(link->dhcp_client);
                if (k < 0)
                        r = log_link_warning_errno(link, k, "Could not stop DHCPv4 client: %m");
        }

        k = sd_dhcp_server_stop(link->dhcp_server);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop DHCPv4 server: %m");

        k = sd_lldp_rx_stop(link->lldp_rx);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop LLDP Rx: %m");

        k = sd_lldp_tx_stop(link->lldp_tx);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop LLDP Tx: %m");

        k = sd_ipv4ll_stop(link->ipv4ll);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop IPv4 link-local: %m");

        k = ipv4acd_stop(link);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop IPv4 ACD client: %m");

        k = sd_dhcp6_client_stop(link->dhcp6_client);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop DHCPv6 client: %m");

        k = dhcp_pd_remove(link, /* only_marked = */ false);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not remove DHCPv6 PD addresses and routes: %m");

        k = ndisc_stop(link);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop IPv6 Router Discovery: %m");

        ndisc_flush(link);

        k = sd_radv_stop(link->radv);
        if (k < 0)
                r = log_link_warning_errno(link, k, "Could not stop IPv6 Router Advertisement: %m");

        return r;
}

void link_enter_failed(Link *link) {
        assert(link);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return;

        log_link_warning(link, "Failed");

        link_set_state(link, LINK_STATE_FAILED);

        (void) link_stop_engines(link, false);
}

void link_check_ready(Link *link) {
        Address *a;

        assert(link);

        if (link->state == LINK_STATE_CONFIGURED)
                return;

        if (link->state != LINK_STATE_CONFIGURING)
                return (void) log_link_debug(link, "%s(): link is in %s state.", __func__, link_state_to_string(link->state));

        if (!link->network)
                return (void) log_link_debug(link, "%s(): link is unmanaged.", __func__);

        if (!link->tc_configured)
                return (void) log_link_debug(link, "%s(): traffic controls are not configured.", __func__);

        if (link->set_link_messages > 0)
                return (void) log_link_debug(link, "%s(): link layer is configuring.", __func__);

        if (!link->activated)
                return (void) log_link_debug(link, "%s(): link is not activated.", __func__);

        if (link->iftype == ARPHRD_CAN) {
                /* let's shortcut things for CAN which doesn't need most of checks below. */
                link_set_state(link, LINK_STATE_CONFIGURED);
                return;
        }

        if (!link->stacked_netdevs_created)
                return (void) log_link_debug(link, "%s(): stacked netdevs are not created.", __func__);

        if (!link->static_addresses_configured)
                return (void) log_link_debug(link, "%s(): static addresses are not configured.", __func__);

        if (!link->static_address_labels_configured)
                return (void) log_link_debug(link, "%s(): static address labels are not configured.", __func__);

        if (!link->static_bridge_fdb_configured)
                return (void) log_link_debug(link, "%s(): static bridge MDB entries are not configured.", __func__);

        if (!link->static_bridge_mdb_configured)
                return (void) log_link_debug(link, "%s(): static bridge MDB entries are not configured.", __func__);

        if (!link->static_ipv6_proxy_ndp_configured)
                return (void) log_link_debug(link, "%s(): static IPv6 proxy NDP addresses are not configured.", __func__);

        if (!link->static_neighbors_configured)
                return (void) log_link_debug(link, "%s(): static neighbors are not configured.", __func__);

        if (!link->static_nexthops_configured)
                return (void) log_link_debug(link, "%s(): static nexthops are not configured.", __func__);

        if (!link->static_routes_configured)
                return (void) log_link_debug(link, "%s(): static routes are not configured.", __func__);

        if (!link->static_routing_policy_rules_configured)
                return (void) log_link_debug(link, "%s(): static routing policy rules are not configured.", __func__);

        if (!link->sr_iov_configured)
                return (void) log_link_debug(link, "%s(): SR-IOV is not configured.", __func__);

        /* IPv6LL is assigned after the link gains its carrier. */
        if (!link->network->configure_without_carrier &&
            link_ipv6ll_enabled(link) &&
            !in6_addr_is_set(&link->ipv6ll_address))
                return (void) log_link_debug(link, "%s(): IPv6LL is not configured yet.", __func__);

        /* All static addresses must be ready. */
        bool has_static_address = false;
        SET_FOREACH(a, link->addresses) {
                if (a->source != NETWORK_CONFIG_SOURCE_STATIC)
                        continue;
                if (!address_is_ready(a))
                        return (void) log_link_debug(link, "%s(): static address %s is not ready.", __func__,
                                                     IN_ADDR_PREFIX_TO_STRING(a->family, &a->in_addr, a->prefixlen));
                has_static_address = true;
        }

        /* If at least one static address is requested, do not request that dynamic addressing protocols are finished. */
        if (has_static_address)
                goto ready;

        /* If no dynamic addressing protocol enabled, assume the interface is ready.
         * Note, ignore NDisc when ConfigureWithoutCarrier= is enabled, as IPv6AcceptRA= is enabled by default. */
        if (!link_ipv4ll_enabled(link) && !link_dhcp4_enabled(link) &&
            !link_dhcp6_enabled(link) && !link_dhcp_pd_is_enabled(link) &&
            (link->network->configure_without_carrier || !link_ipv6_accept_ra_enabled(link)))
                goto ready;

        bool ipv4ll_ready =
                link_ipv4ll_enabled(link) && link->ipv4ll_address_configured &&
                link_check_addresses_ready(link, NETWORK_CONFIG_SOURCE_IPV4LL);
        bool dhcp4_ready =
                link_dhcp4_enabled(link) && link->dhcp4_configured &&
                link_check_addresses_ready(link, NETWORK_CONFIG_SOURCE_DHCP4);
        bool dhcp6_ready =
                link_dhcp6_enabled(link) && link->dhcp6_configured &&
                (!link->network->dhcp6_use_address ||
                 link_check_addresses_ready(link, NETWORK_CONFIG_SOURCE_DHCP6));
        bool dhcp_pd_ready =
                link_dhcp_pd_is_enabled(link) && link->dhcp_pd_configured &&
                (!link->network->dhcp_pd_assign ||
                 link_check_addresses_ready(link, NETWORK_CONFIG_SOURCE_DHCP_PD));
        bool ndisc_ready =
                link_ipv6_accept_ra_enabled(link) && link->ndisc_configured &&
                (!link->network->ipv6_accept_ra_use_autonomous_prefix ||
                 link_check_addresses_ready(link, NETWORK_CONFIG_SOURCE_NDISC));

        /* If the uplink for PD is self, then request the corresponding DHCP protocol is also ready. */
        if (dhcp_pd_is_uplink(link, link, /* accept_auto = */ false)) {
                if (link_dhcp4_enabled(link) && link->network->dhcp_use_6rd &&
                    sd_dhcp_lease_has_6rd(link->dhcp_lease)) {
                        if (!dhcp4_ready)
                                return (void) log_link_debug(link, "%s(): DHCPv4 6rd prefix is assigned, but DHCPv4 protocol is not finished yet.", __func__);
                        if (!dhcp_pd_ready)
                                return (void) log_link_debug(link, "%s(): DHCPv4 is finished, but prefix acquired by DHCPv4-6rd is not assigned yet.", __func__);
                }

                if (link_dhcp6_enabled(link) && link->network->dhcp6_use_pd_prefix &&
                    sd_dhcp6_lease_has_pd_prefix(link->dhcp6_lease)) {
                        if (!dhcp6_ready)
                                return (void) log_link_debug(link, "%s(): DHCPv6 IA_PD prefix is assigned, but DHCPv6 protocol is not finished yet.", __func__);
                        if (!dhcp_pd_ready)
                                return (void) log_link_debug(link, "%s(): DHCPv6 is finished, but prefix acquired by DHCPv6 IA_PD is not assigned yet.", __func__);
                }
        }

        /* At least one dynamic addressing protocol is finished. */
        if (!ipv4ll_ready && !dhcp4_ready && !dhcp6_ready && !dhcp_pd_ready && !ndisc_ready)
                return (void) log_link_debug(link, "%s(): dynamic addressing protocols are enabled but none of them finished yet.", __func__);

        log_link_debug(link, "%s(): IPv4LL:%s DHCPv4:%s DHCPv6:%s DHCP-PD:%s NDisc:%s",
                       __func__,
                       yes_no(ipv4ll_ready),
                       yes_no(dhcp4_ready),
                       yes_no(dhcp6_ready),
                       yes_no(dhcp_pd_ready),
                       yes_no(ndisc_ready));

ready:
        link_set_state(link, LINK_STATE_CONFIGURED);
}

static int link_request_static_configs(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->state != _LINK_STATE_INVALID);

        r = link_request_static_addresses(link);
        if (r < 0)
                return r;

        r = link_request_static_address_labels(link);
        if (r < 0)
                return r;

        r = link_request_static_bridge_fdb(link);
        if (r < 0)
                return r;

        r = link_request_static_bridge_mdb(link);
        if (r < 0)
                return r;

        r = link_request_static_ipv6_proxy_ndp_addresses(link);
        if (r < 0)
                return r;

        r = link_request_static_neighbors(link);
        if (r < 0)
                return r;

        r = link_request_static_nexthops(link, false);
        if (r < 0)
                return r;

        r = link_request_static_routes(link, false);
        if (r < 0)
                return r;

        r = link_request_static_routing_policy_rules(link);
        if (r < 0)
                return r;

        return 0;
}

static int link_request_stacked_netdevs(Link *link) {
        NetDev *netdev;
        int r;

        assert(link);

        link->stacked_netdevs_created = false;

        HASHMAP_FOREACH(netdev, link->network->stacked_netdevs) {
                r = link_request_stacked_netdev(link, netdev);
                if (r < 0)
                        return r;
        }

        if (link->create_stacked_netdev_messages == 0) {
                link->stacked_netdevs_created = true;
                link_check_ready(link);
        }

        return 0;
}

static int link_acquire_dynamic_ipv6_conf(Link *link) {
        int r;

        assert(link);

        r = radv_start(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to start IPv6 Router Advertisement engine: %m");

        r = ndisc_start(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to start IPv6 Router Discovery: %m");

        r = dhcp6_start(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to start DHCPv6 client: %m");

        return 0;
}

static int link_acquire_dynamic_ipv4_conf(Link *link) {
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->event);

        if (link->dhcp_client) {
                r = dhcp4_start(link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to start DHCPv4 client: %m");

                log_link_debug(link, "Acquiring DHCPv4 lease.");

        } else if (link->ipv4ll) {
                if (in4_addr_is_set(&link->network->ipv4ll_start_address)) {
                        r = sd_ipv4ll_set_address(link->ipv4ll, &link->network->ipv4ll_start_address);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "Could not set IPv4 link-local start address: %m");
                }

                r = sd_ipv4ll_start(link->ipv4ll);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not acquire IPv4 link-local address: %m");

                log_link_debug(link, "Acquiring IPv4 link-local address.");
        }

        if (link->dhcp_server) {
                r = sd_dhcp_server_start(link->dhcp_server);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not start DHCP server: %m");
        }

        r = ipv4acd_start(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not start IPv4 ACD client: %m");

        return 0;
}

static int link_acquire_dynamic_conf(Link *link) {
        int r;

        assert(link);
        assert(link->network);

        r = link_acquire_dynamic_ipv4_conf(link);
        if (r < 0)
                return r;

        if (in6_addr_is_set(&link->ipv6ll_address)) {
                r = link_acquire_dynamic_ipv6_conf(link);
                if (r < 0)
                        return r;
        }

        if (!link_radv_enabled(link) || !link->network->dhcp_pd_announce) {
                /* DHCPv6PD downstream does not require IPv6LL address. But may require RADV to be
                 * configured, and RADV may not be configured yet here. Only acquire subnet prefix when
                 * RADV is disabled, or the announcement of the prefix is disabled. Otherwise, the
                 * below will be called in radv_start(). */
                r = dhcp_request_prefix_delegation(link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to request DHCP delegated subnet prefix: %m");
        }

        if (link->lldp_tx) {
                r = sd_lldp_tx_start(link->lldp_tx);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to start LLDP transmission: %m");
        }

        if (link->lldp_rx) {
                r = sd_lldp_rx_start(link->lldp_rx);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to start LLDP client: %m");
        }

        return 0;
}

int link_ipv6ll_gained(Link *link) {
        int r;

        assert(link);

        log_link_info(link, "Gained IPv6LL");

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return 0;

        r = link_acquire_dynamic_ipv6_conf(link);
        if (r < 0)
                return r;

        link_check_ready(link);
        return 0;
}

int link_handle_bound_to_list(Link *link) {
        bool required_up = false;
        bool link_is_up = false;
        Link *l;

        assert(link);

        /* If at least one interface in bound_to_links has carrier, then make this interface up.
         * If all interfaces in bound_to_links do not, then make this interface down. */

        if (hashmap_isempty(link->bound_to_links))
                return 0;

        if (link->flags & IFF_UP)
                link_is_up = true;

        HASHMAP_FOREACH(l, link->bound_to_links)
                if (link_has_carrier(l)) {
                        required_up = true;
                        break;
                }

        if (!required_up && link_is_up)
                return link_request_to_bring_up_or_down(link, /* up = */ false);
        if (required_up && !link_is_up)
                return link_request_to_bring_up_or_down(link, /* up = */ true);

        return 0;
}

static int link_handle_bound_by_list(Link *link) {
        Link *l;
        int r;

        assert(link);

        /* Update up or down state of interfaces which depend on this interface's carrier state. */

        if (hashmap_isempty(link->bound_by_links))
                return 0;

        HASHMAP_FOREACH(l, link->bound_by_links) {
                r = link_handle_bound_to_list(l);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int link_put_carrier(Link *link, Link *carrier, Hashmap **h) {
        int r;

        assert(link);
        assert(carrier);

        if (link == carrier)
                return 0;

        if (hashmap_get(*h, INT_TO_PTR(carrier->ifindex)))
                return 0;

        r = hashmap_ensure_put(h, NULL, INT_TO_PTR(carrier->ifindex), carrier);
        if (r < 0)
                return r;

        link_dirty(link);

        return 0;
}

static int link_new_bound_by_list(Link *link) {
        Manager *m;
        Link *carrier;
        int r;

        assert(link);
        assert(link->manager);

        m = link->manager;

        HASHMAP_FOREACH(carrier, m->links_by_index) {
                if (!carrier->network)
                        continue;

                if (strv_isempty(carrier->network->bind_carrier))
                        continue;

                if (strv_fnmatch(carrier->network->bind_carrier, link->ifname)) {
                        r = link_put_carrier(link, carrier, &link->bound_by_links);
                        if (r < 0)
                                return r;
                }
        }

        HASHMAP_FOREACH(carrier, link->bound_by_links) {
                r = link_put_carrier(carrier, link, &carrier->bound_to_links);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int link_new_bound_to_list(Link *link) {
        Manager *m;
        Link *carrier;
        int r;

        assert(link);
        assert(link->manager);

        if (!link->network)
                return 0;

        if (strv_isempty(link->network->bind_carrier))
                return 0;

        m = link->manager;

        HASHMAP_FOREACH(carrier, m->links_by_index) {
                if (strv_fnmatch(link->network->bind_carrier, carrier->ifname)) {
                        r = link_put_carrier(link, carrier, &link->bound_to_links);
                        if (r < 0)
                                return r;
                }
        }

        HASHMAP_FOREACH(carrier, link->bound_to_links) {
                r = link_put_carrier(carrier, link, &carrier->bound_by_links);
                if (r < 0)
                        return r;
        }

        return 0;
}

static void link_free_bound_to_list(Link *link) {
        bool updated = false;
        Link *bound_to;

        assert(link);

        while ((bound_to = hashmap_steal_first(link->bound_to_links))) {
                updated = true;

                if (hashmap_remove(bound_to->bound_by_links, INT_TO_PTR(link->ifindex)))
                        link_dirty(bound_to);
        }

        if (updated)
                link_dirty(link);
}

static void link_free_bound_by_list(Link *link) {
        bool updated = false;
        Link *bound_by;

        assert(link);

        while ((bound_by = hashmap_steal_first(link->bound_by_links))) {
                updated = true;

                if (hashmap_remove(bound_by->bound_to_links, INT_TO_PTR(link->ifindex))) {
                        link_dirty(bound_by);
                        link_handle_bound_to_list(bound_by);
                }
        }

        if (updated)
                link_dirty(link);
}

static int link_append_to_master(Link *link) {
        Link *master;
        int r;

        assert(link);

        /* - The link may have no master.
         * - RTM_NEWLINK message about master interface may not be received yet. */
        if (link_get_master(link, &master) < 0)
                return 0;

        r = set_ensure_put(&master->slaves, NULL, link);
        if (r <= 0)
                return r;

        link_ref(link);
        return 0;
}

static void link_drop_from_master(Link *link) {
        Link *master;

        assert(link);

        if (!link->manager)
                return;

        if (link_get_master(link, &master) < 0)
                return;

        link_unref(set_remove(master->slaves, link));
}

static void link_drop_requests(Link *link) {
        Request *req;

        assert(link);
        assert(link->manager);

        ORDERED_SET_FOREACH(req, link->manager->request_queue)
                if (req->link == link)
                        request_detach(link->manager, req);
}

static Link *link_drop(Link *link) {
        if (!link)
                return NULL;

        assert(link->manager);

        link_set_state(link, LINK_STATE_LINGER);

        /* Drop all references from other links and manager. Note that async netlink calls may have
         * references to the link, and they will be dropped when we receive replies. */

        link_drop_requests(link);

        link_free_bound_to_list(link);
        link_free_bound_by_list(link);

        link_clear_sr_iov_ifindices(link);

        link_drop_from_master(link);

        if (link->state_file)
                (void) unlink(link->state_file);

        link_clean(link);

        STRV_FOREACH(n, link->alternative_names)
                hashmap_remove(link->manager->links_by_name, *n);
        hashmap_remove(link->manager->links_by_name, link->ifname);

        /* bonding master and its slaves have the same hardware address. */
        hashmap_remove_value(link->manager->links_by_hw_addr, &link->hw_addr, link);

        /* The following must be called at last. */
        assert_se(hashmap_remove(link->manager->links_by_index, INT_TO_PTR(link->ifindex)) == link);
        return link_unref(link);
}

static int link_drop_foreign_config(Link *link) {
        int r;

        assert(link);
        assert(link->manager);

        /* Drop foreign config, but ignore unmanaged, loopback, or critical interfaces. We do not want
         * to remove loopback address or addresses used for root NFS. */

        if (IN_SET(link->state, LINK_STATE_UNMANAGED, LINK_STATE_PENDING, LINK_STATE_INITIALIZED))
                return 0;
        if (FLAGS_SET(link->flags, IFF_LOOPBACK))
                return 0;
        if (link->network->keep_configuration == KEEP_CONFIGURATION_YES)
                return 0;

        r = link_drop_foreign_routes(link);

        RET_GATHER(r, link_drop_foreign_nexthops(link));
        RET_GATHER(r, link_drop_foreign_addresses(link));
        RET_GATHER(r, link_drop_foreign_neighbors(link));
        RET_GATHER(r, manager_drop_foreign_routing_policy_rules(link->manager));

        return r;
}

static int link_drop_managed_config(Link *link) {
        int r;

        assert(link);
        assert(link->manager);

        r = link_drop_managed_routes(link);

        RET_GATHER(r, link_drop_managed_nexthops(link));
        RET_GATHER(r, link_drop_managed_addresses(link));
        RET_GATHER(r, link_drop_managed_neighbors(link));
        RET_GATHER(r, link_drop_managed_routing_policy_rules(link));

        return r;
}

static void link_foreignize_config(Link *link) {
        assert(link);
        assert(link->manager);

        link_foreignize_routes(link);
        link_foreignize_nexthops(link);
        link_foreignize_addresses(link);
        link_foreignize_neighbors(link);
        link_foreignize_routing_policy_rules(link);
}

static int link_configure(Link *link) {
        int r;

        assert(link);
        assert(link->network);
        assert(link->state == LINK_STATE_INITIALIZED);

        link_set_state(link, LINK_STATE_CONFIGURING);

        r = link_new_bound_to_list(link);
        if (r < 0)
                return r;

        r = link_request_traffic_control(link);
        if (r < 0)
                return r;

        r = link_configure_mtu(link);
        if (r < 0)
                return r;

        if (link->iftype == ARPHRD_CAN) {
                /* let's shortcut things for CAN which doesn't need most of what's done below. */
                r = link_request_to_set_can(link);
                if (r < 0)
                        return r;

                return link_request_to_activate(link);
        }

        r = link_request_sr_iov_vfs(link);
        if (r < 0)
                return r;

        r = link_set_sysctl(link);
        if (r < 0)
                return r;

        r = link_request_to_set_mac(link, /* allow_retry = */ true);
        if (r < 0)
                return r;

        r = link_request_to_set_ipoib(link);
        if (r < 0)
                return r;

        r = link_request_to_set_flags(link);
        if (r < 0)
                return r;

        r = link_request_to_set_group(link);
        if (r < 0)
                return r;

        r = link_request_to_set_addrgen_mode(link);
        if (r < 0)
                return r;

        r = link_request_to_set_master(link);
        if (r < 0)
                return r;

        r = link_request_stacked_netdevs(link);
        if (r < 0)
                return r;

        r = link_request_to_set_bond(link);
        if (r < 0)
                return r;

        r = link_request_to_set_bridge(link);
        if (r < 0)
                return r;

        r = link_request_to_set_bridge_vlan(link);
        if (r < 0)
                return r;

        r = link_request_to_activate(link);
        if (r < 0)
                return r;

        r = ipv4ll_configure(link);
        if (r < 0)
                return r;

        r = link_request_dhcp4_client(link);
        if (r < 0)
                return r;

        r = link_request_dhcp6_client(link);
        if (r < 0)
                return r;

        r = link_request_ndisc(link);
        if (r < 0)
                return r;

        r = link_request_dhcp_server(link);
        if (r < 0)
                return r;

        r = link_request_radv(link);
        if (r < 0)
                return r;

        r = link_lldp_rx_configure(link);
        if (r < 0)
                return r;

        r = link_lldp_tx_configure(link);
        if (r < 0)
                return r;

        r = link_drop_foreign_config(link);
        if (r < 0)
                return r;

        r = link_request_static_configs(link);
        if (r < 0)
                return r;

        if (!link_has_carrier(link))
                return 0;

        return link_acquire_dynamic_conf(link);
}

static int link_get_network(Link *link, Network **ret) {
        Network *network;
        int r;

        assert(link);
        assert(link->manager);
        assert(ret);

        ORDERED_HASHMAP_FOREACH(network, link->manager->networks) {
                bool warn = false;

                r = net_match_config(
                                &network->match,
                                link->dev,
                                &link->hw_addr,
                                &link->permanent_hw_addr,
                                link->driver,
                                link->iftype,
                                link->kind,
                                link->ifname,
                                link->alternative_names,
                                link->wlan_iftype,
                                link->ssid,
                                &link->bssid);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (network->match.ifname && link->dev) {
                        uint8_t name_assign_type = NET_NAME_UNKNOWN;
                        const char *attr;

                        if (sd_device_get_sysattr_value(link->dev, "name_assign_type", &attr) >= 0)
                                (void) safe_atou8(attr, &name_assign_type);

                        warn = name_assign_type == NET_NAME_ENUM;
                }

                log_link_full(link, warn ? LOG_WARNING : LOG_DEBUG,
                              "found matching network '%s'%s.",
                              network->filename,
                              warn ? ", based on potentially unpredictable interface name" : "");

                if (network->unmanaged)
                        return -ENOENT;

                *ret = network;
                return 0;
        }

        return -ENOENT;
}

int link_reconfigure_impl(Link *link, bool force) {
        Network *network = NULL;
        NetDev *netdev = NULL;
        int r;

        assert(link);

        if (IN_SET(link->state, LINK_STATE_PENDING, LINK_STATE_LINGER))
                return 0;

        r = netdev_get(link->manager, link->ifname, &netdev);
        if (r < 0 && r != -ENOENT)
                return r;

        r = link_get_network(link, &network);
        if (r < 0 && r != -ENOENT)
                return r;

        if (link->state != LINK_STATE_UNMANAGED && !network)
                /* If link is in initialized state, then link->network is also NULL. */
                force = true;

        if (link->network == network && !force)
                return 0;

        if (network) {
                if (link->state == LINK_STATE_INITIALIZED)
                        log_link_info(link, "Configuring with %s.", network->filename);
                else
                        log_link_info(link, "Reconfiguring with %s.", network->filename);
        } else
                log_link_full(link, link->state == LINK_STATE_INITIALIZED ? LOG_DEBUG : LOG_INFO,
                              "Unmanaging interface.");

        /* Dropping old .network file */
        r = link_stop_engines(link, false);
        if (r < 0)
                return r;

        link_drop_requests(link);

        if (network && !force && network->keep_configuration != KEEP_CONFIGURATION_YES)
                /* When a new/updated .network file is assigned, first make all configs (addresses,
                 * routes, and so on) foreign, and then drop unnecessary configs later by
                 * link_drop_foreign_config() in link_configure().
                 * Note, when KeepConfiguration=yes, link_drop_foreign_config() does nothing. Hence,
                 * here we need to drop the configs such as addresses, routes, and so on configured by
                 * the previously assigned .network file. */
                link_foreignize_config(link);
        else {
                /* Remove all managed configs. Note, foreign configs are removed in later by
                 * link_configure() -> link_drop_foreign_config() if the link is managed by us. */
                r = link_drop_managed_config(link);
                if (r < 0)
                        return r;
        }

        /* The bound_to map depends on .network file, hence it needs to be freed. But, do not free the
         * bound_by map. Otherwise, if a link enters unmanaged state below, then its carrier state will
         * not propagated to other interfaces anymore. Moreover, it is not necessary to recreate the
         * map here, as it depends on .network files assigned to other links. */
        link_free_bound_to_list(link);

        link_free_engines(link);
        link->network = network_unref(link->network);

        netdev_unref(link->netdev);
        link->netdev = netdev_ref(netdev);

        if (!network) {
                link_set_state(link, LINK_STATE_UNMANAGED);
                return 0;
        }

        /* Then, apply new .network file */
        link->network = network_ref(network);
        link_update_operstate(link, true);
        link_dirty(link);

        link_set_state(link, LINK_STATE_INITIALIZED);
        link->activated = false;

        r = link_configure(link);
        if (r < 0)
                return r;

        return 1;
}

static int link_reconfigure_handler_internal(sd_netlink *rtnl, sd_netlink_message *m, Link *link, bool force) {
        int r;

        assert(link);

        r = link_getlink_handler_internal(rtnl, m, link, "Failed to update link state");
        if (r <= 0)
                return r;

        r = link_reconfigure_impl(link, force);
        if (r < 0) {
                link_enter_failed(link);
                return 0;
        }

        return r;
}

static int link_reconfigure_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return link_reconfigure_handler_internal(rtnl, m, link, /* force = */ false);
}

static int link_force_reconfigure_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        return link_reconfigure_handler_internal(rtnl, m, link, /* force = */ true);
}

int link_reconfigure(Link *link, bool force) {
        int r;

        assert(link);

        /* When link in pending or initialized state, then link_configure() will be called. To prevent
         * the function from being called multiple times simultaneously, refuse to reconfigure the
         * interface in these cases. */
        if (IN_SET(link->state, LINK_STATE_PENDING, LINK_STATE_INITIALIZED, LINK_STATE_LINGER))
                return 0; /* 0 means no-op. */

        r = link_call_getlink(link, force ? link_force_reconfigure_handler : link_reconfigure_handler);
        if (r < 0)
                return r;

        return 1; /* 1 means the interface will be reconfigured. */
}

static int link_initialized_and_synced(Link *link) {
        int r;

        assert(link);
        assert(link->manager);

        if (link->manager->test_mode) {
                log_link_debug(link, "Running in test mode, refusing to enter initialized state.");
                link_set_state(link, LINK_STATE_UNMANAGED);
                return 0;
        }

        if (link->state == LINK_STATE_PENDING) {
                log_link_debug(link, "Link state is up-to-date");
                link_set_state(link, LINK_STATE_INITIALIZED);

                r = link_new_bound_by_list(link);
                if (r < 0)
                        return r;

                r = link_handle_bound_by_list(link);
                if (r < 0)
                        return r;
        }

        return link_reconfigure_impl(link, /* force = */ false);
}

static int link_initialized_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        r = link_getlink_handler_internal(rtnl, m, link, "Failed to wait for the interface to be initialized");
        if (r <= 0)
                return r;

        r = link_initialized_and_synced(link);
        if (r < 0)
                link_enter_failed(link);

        return 0;
}

static int link_initialized(Link *link, sd_device *device) {
        int r;

        assert(link);
        assert(device);

        /* Always replace with the new sd_device object. As the sysname (and possibly other properties
         * or sysattrs) may be outdated. */
        device_unref_and_replace(link->dev, device);

        if (link->dhcp_client) {
                r = sd_dhcp_client_attach_device(link->dhcp_client, link->dev);
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to attach device to DHCPv4 client, ignoring: %m");
        }

        if (link->dhcp6_client) {
                r = sd_dhcp6_client_attach_device(link->dhcp6_client, link->dev);
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to attach device to DHCPv6 client, ignoring: %m");
        }

        r = link_set_sr_iov_ifindices(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to manage SR-IOV PF and VF ports, ignoring: %m");

        if (link->state != LINK_STATE_PENDING)
                return link_reconfigure(link, /* force = */ false);

        log_link_debug(link, "udev initialized link");

        /* udev has initialized the link, but we don't know if we have yet
         * processed the NEWLINK messages with the latest state. Do a GETLINK,
         * when it returns we know that the pending NEWLINKs have already been
         * processed and that we are up-to-date */

        return link_call_getlink(link, link_initialized_handler);
}

static int link_check_initialized(Link *link) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        int r;

        assert(link);

        if (!udev_available())
                return link_initialized_and_synced(link);

        /* udev should be around */
        r = sd_device_new_from_ifindex(&device, link->ifindex);
        if (r < 0) {
                log_link_debug_errno(link, r, "Could not find device, waiting for device initialization: %m");
                return 0;
        }

        r = sd_device_get_is_initialized(device);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not determine whether the device is initialized: %m");
        if (r == 0) {
                /* not yet ready */
                log_link_debug(link, "link pending udev initialization...");
                return 0;
        }

        r = device_is_renaming(device);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to determine the device is being renamed: %m");
        if (r > 0) {
                log_link_debug(link, "Interface is being renamed, pending initialization.");
                return 0;
        }

        r = device_is_processing(device);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to determine the device is being processed: %m");
        if (r > 0) {
                log_link_debug(link, "Interface is being processed by udevd, pending initialization.");
                return 0;
        }

        return link_initialized(link, device);
}

int manager_udev_process_link(Manager *m, sd_device *device, sd_device_action_t action) {
        int r, ifindex;
        const char *s;
        Link *link;

        assert(m);
        assert(device);

        r = sd_device_get_ifindex(device, &ifindex);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to get ifindex: %m");

        r = link_get_by_index(m, ifindex, &link);
        if (r < 0) {
                /* This error is not critical, as the corresponding rtnl message may be received later. */
                log_device_debug_errno(device, r, "Failed to get link from ifindex %i, ignoring: %m", ifindex);
                return 0;
        }

        /* Let's unref the sd-device object assigned to the corresponding Link object, but keep the Link
         * object here. It will be removed only when rtnetlink says so. */
        if (action == SD_DEVICE_REMOVE) {
                link->dev = sd_device_unref(link->dev);
                return 0;
        }

        r = device_is_renaming(device);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to determine if the device is renaming or not: %m");
        if (r > 0) {
                log_device_debug(device, "Device is renaming, waiting for the interface to be renamed.");
                /* TODO:
                 * What happens when a device is initialized, then soon renamed after that? When we detect
                 * such, maybe we should cancel or postpone all queued requests for the interface. */
                return 0;
        }

        r = sd_device_get_property_value(device, "ID_NET_MANAGED_BY", &s);
        if (r < 0 && r != -ENOENT)
                log_device_debug_errno(device, r, "Failed to get ID_NET_MANAGED_BY udev property, ignoring: %m");
        if (r >= 0 && !streq(s, "io.systemd.Network")) {
                log_device_debug(device, "Interface is requested to be managed by '%s', not managing the interface.", s);
                link_set_state(link, LINK_STATE_UNMANAGED);
                return 0;
        }

        r = link_initialized(link, device);
        if (r < 0)
                link_enter_failed(link);

        return 0;
}

static int link_carrier_gained(Link *link) {
        bool force_reconfigure;
        int r;

        assert(link);

        r = event_source_disable(link->carrier_lost_timer);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to disable carrier lost timer, ignoring: %m");

        /* If a wireless interface was connected to an access point, and the SSID is changed (that is,
         * both previous_ssid and ssid are non-NULL), then the connected wireless network could be
         * changed. So, always reconfigure the link. Which means e.g. the DHCP client will be
         * restarted, and the correct network information will be gained.
         *
         * However, do not reconfigure the wireless interface forcibly if it was not connected to any
         * access points previously (previous_ssid is NULL in this case). As, a .network file may be
         * already assigned to the interface (in that case, the .network file does not have the SSID=
         * setting in the [Match] section), and the interface is already being configured. Of course,
         * there may exist another .network file with higher priority and a matching SSID= setting. But
         * in that case, link_reconfigure_impl() can handle that without the force_reconfigure flag.
         *
         * For non-wireless interfaces, we have no way to detect the connected network change. So,
         * setting force_reconfigure = false. Note, both ssid and previous_ssid are NULL in that case. */
        force_reconfigure = link->previous_ssid && !streq_ptr(link->previous_ssid, link->ssid);
        link->previous_ssid = mfree(link->previous_ssid);

        /* AP and P2P-GO interfaces may have a new SSID - update the link properties in case a new .network
         * profile wants to match on it with SSID= in its [Match] section.
         */
        if (IN_SET(link->wlan_iftype, NL80211_IFTYPE_AP, NL80211_IFTYPE_P2P_GO)) {
                r = link_get_wlan_interface(link);
                if (r < 0)
                        return r;
        }

        /* At this stage, both wlan and link information should be up-to-date. Hence, it is not necessary to
         * call RTM_GETLINK, NL80211_CMD_GET_INTERFACE, or NL80211_CMD_GET_STATION commands, and simply call
         * link_reconfigure_impl(). Note, link_reconfigure_impl() returns 1 when the link is reconfigured. */
        r = link_reconfigure_impl(link, force_reconfigure);
        if (r != 0)
                return r;

        r = link_handle_bound_by_list(link);
        if (r < 0)
                return r;

        if (link->iftype == ARPHRD_CAN)
                /* let's shortcut things for CAN which doesn't need most of what's done below. */
                return 0;

        if (IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED)) {
                r = link_acquire_dynamic_conf(link);
                if (r < 0)
                        return r;

                r = link_request_static_configs(link);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int link_carrier_lost_impl(Link *link) {
        int r, ret = 0;

        assert(link);

        link->previous_ssid = mfree(link->previous_ssid);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        if (!link->network)
                return 0;

        r = link_stop_engines(link, false);
        if (r < 0)
                ret = r;

        r = link_drop_managed_config(link);
        if (r < 0 && ret >= 0)
                ret = r;

        return ret;
}

static int link_carrier_lost_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        Link *link = ASSERT_PTR(userdata);
        int r;

        r = link_carrier_lost_impl(link);
        if (r < 0) {
                log_link_warning_errno(link, r, "Failed to process carrier lost event: %m");
                link_enter_failed(link);
        }

        return 0;
}

static int link_carrier_lost(Link *link) {
        uint16_t dhcp_mtu;
        usec_t usec;
        int r;

        assert(link);

        r = link_handle_bound_by_list(link);
        if (r < 0)
                return r;

        if (link->iftype == ARPHRD_CAN)
                /* let's shortcut things for CAN which doesn't need most of what's done below. */
                return 0;

        if (!link->network)
                return 0;

        if (link->network->ignore_carrier_loss_set)
                /* If IgnoreCarrierLoss= is explicitly specified, then use the specified value. */
                usec = link->network->ignore_carrier_loss_usec;

        else if (link->network->bond && link->wlan_iftype > 0)
                /* Enslaving wlan interface to a bond disconnects from the connected AP, and causes its
                 * carrier to be lost. See #19832. */
                usec = 3 * USEC_PER_SEC;

        else if (link->network->dhcp_use_mtu &&
                 link->dhcp_lease &&
                 sd_dhcp_lease_get_mtu(link->dhcp_lease, &dhcp_mtu) >= 0 &&
                 dhcp_mtu != link->original_mtu)
                /* Some drivers reset interfaces when changing MTU. Resetting interfaces by the static
                 * MTU should not cause any issues, as MTU is changed only once. However, setting MTU
                 * through DHCP lease causes an infinite loop of resetting the interface. See #18738. */
                usec = 5 * USEC_PER_SEC;

        else
                /* Otherwise, use the currently set value. */
                usec = link->network->ignore_carrier_loss_usec;

        if (usec == USEC_INFINITY)
                return 0;

        if (usec == 0)
                return link_carrier_lost_impl(link);

        return event_reset_time_relative(link->manager->event,
                                         &link->carrier_lost_timer,
                                         CLOCK_BOOTTIME,
                                         usec,
                                         0,
                                         link_carrier_lost_handler,
                                         link,
                                         0,
                                         "link-carrier-loss",
                                         true);
}

static int link_admin_state_up(Link *link) {
        int r;

        assert(link);

        /* This is called every time an interface admin state changes to up;
         * specifically, when IFF_UP flag changes from unset to set. */

        if (!link->network)
                return 0;

        if (link->activated && link->network->activation_policy == ACTIVATION_POLICY_ALWAYS_DOWN) {
                log_link_info(link, "Activation policy is \"always-down\", forcing link down.");
                return link_request_to_bring_up_or_down(link, /* up = */ false);
        }

        /* We set the ipv6 mtu after the device mtu, but the kernel resets
         * ipv6 mtu on NETDEV_UP, so we need to reset it. */
        r = link_set_ipv6_mtu(link);
        if (r < 0)
                log_link_warning_errno(link, r, "Cannot set IPv6 MTU, ignoring: %m");

        return 0;
}

static int link_admin_state_down(Link *link) {
        assert(link);

        if (!link->network)
                return 0;

        if (link->activated && link->network->activation_policy == ACTIVATION_POLICY_ALWAYS_UP) {
                log_link_info(link, "Activation policy is \"always-up\", forcing link up.");
                return link_request_to_bring_up_or_down(link, /* up = */ true);
        }

        return 0;
}

static bool link_is_enslaved(Link *link) {
        if (link->flags & IFF_SLAVE)
                return true;

        if (link->master_ifindex > 0)
                return true;

        return false;
}

void link_update_operstate(Link *link, bool also_update_master) {
        LinkOperationalState operstate;
        LinkCarrierState carrier_state;
        LinkAddressState ipv4_address_state, ipv6_address_state, address_state;
        LinkOnlineState online_state;
        _cleanup_strv_free_ char **p = NULL;
        bool changed = false;

        assert(link);

        if (link->kernel_operstate == IF_OPER_DORMANT)
                carrier_state = LINK_CARRIER_STATE_DORMANT;
        else if (link_has_carrier(link)) {
                if (link_is_enslaved(link))
                        carrier_state = LINK_CARRIER_STATE_ENSLAVED;
                else
                        carrier_state = LINK_CARRIER_STATE_CARRIER;
        } else if (link->flags & IFF_UP)
                carrier_state = LINK_CARRIER_STATE_NO_CARRIER;
        else
                carrier_state = LINK_CARRIER_STATE_OFF;

        if (carrier_state >= LINK_CARRIER_STATE_CARRIER) {
                Link *slave;

                SET_FOREACH(slave, link->slaves) {
                        link_update_operstate(slave, false);

                        if (slave->carrier_state < LINK_CARRIER_STATE_CARRIER)
                                carrier_state = LINK_CARRIER_STATE_DEGRADED_CARRIER;
                }
        }

        link_get_address_states(link, &ipv4_address_state, &ipv6_address_state, &address_state);

        /* Mapping of address and carrier state vs operational state
         *                                                     carrier state
         *                          | off | no-carrier | dormant | degraded-carrier | carrier  | enslaved
         *                 ------------------------------------------------------------------------------
         *                 off      | off | no-carrier | dormant | degraded-carrier | carrier  | enslaved
         * address_state   degraded | off | no-carrier | dormant | degraded         | degraded | enslaved
         *                 routable | off | no-carrier | dormant | routable         | routable | routable
         */

        if (carrier_state == LINK_CARRIER_STATE_DEGRADED_CARRIER && address_state == LINK_ADDRESS_STATE_ROUTABLE)
                operstate = LINK_OPERSTATE_ROUTABLE;
        else if (carrier_state == LINK_CARRIER_STATE_DEGRADED_CARRIER && address_state == LINK_ADDRESS_STATE_DEGRADED)
                operstate = LINK_OPERSTATE_DEGRADED;
        else if (carrier_state < LINK_CARRIER_STATE_CARRIER || address_state == LINK_ADDRESS_STATE_OFF)
                operstate = (LinkOperationalState) carrier_state;
        else if (address_state == LINK_ADDRESS_STATE_ROUTABLE)
                operstate = LINK_OPERSTATE_ROUTABLE;
        else if (carrier_state == LINK_CARRIER_STATE_CARRIER)
                operstate = LINK_OPERSTATE_DEGRADED;
        else
                operstate = LINK_OPERSTATE_ENSLAVED;

        /* Only determine online state for managed links with RequiredForOnline=yes */
        if (!link->network || !link->network->required_for_online)
                online_state = _LINK_ONLINE_STATE_INVALID;
        else if (operstate < link->network->required_operstate_for_online.min ||
                 operstate > link->network->required_operstate_for_online.max)
                online_state = LINK_ONLINE_STATE_OFFLINE;
        else {
                AddressFamily required_family = link->network->required_family_for_online;
                bool needs_ipv4 = required_family & ADDRESS_FAMILY_IPV4;
                bool needs_ipv6 = required_family & ADDRESS_FAMILY_IPV6;

                /* The operational state is within the range required for online.
                 * If a particular address family is also required, we might revert
                 * to offline in the blocks below. */
                online_state = LINK_ONLINE_STATE_ONLINE;

                if (link->network->required_operstate_for_online.min >= LINK_OPERSTATE_DEGRADED) {
                        if (needs_ipv4 && ipv4_address_state < LINK_ADDRESS_STATE_DEGRADED)
                                online_state = LINK_ONLINE_STATE_OFFLINE;
                        if (needs_ipv6 && ipv6_address_state < LINK_ADDRESS_STATE_DEGRADED)
                                online_state = LINK_ONLINE_STATE_OFFLINE;
                }

                if (link->network->required_operstate_for_online.min >= LINK_OPERSTATE_ROUTABLE) {
                        if (needs_ipv4 && ipv4_address_state < LINK_ADDRESS_STATE_ROUTABLE)
                                online_state = LINK_ONLINE_STATE_OFFLINE;
                        if (needs_ipv6 && ipv6_address_state < LINK_ADDRESS_STATE_ROUTABLE)
                                online_state = LINK_ONLINE_STATE_OFFLINE;
                }
        }

        if (link->carrier_state != carrier_state) {
                link->carrier_state = carrier_state;
                changed = true;
                if (strv_extend(&p, "CarrierState") < 0)
                        log_oom();
        }

        if (link->address_state != address_state) {
                link->address_state = address_state;
                changed = true;
                if (strv_extend(&p, "AddressState") < 0)
                        log_oom();
        }

        if (link->ipv4_address_state != ipv4_address_state) {
                link->ipv4_address_state = ipv4_address_state;
                changed = true;
                if (strv_extend(&p, "IPv4AddressState") < 0)
                        log_oom();
        }

        if (link->ipv6_address_state != ipv6_address_state) {
                link->ipv6_address_state = ipv6_address_state;
                changed = true;
                if (strv_extend(&p, "IPv6AddressState") < 0)
                        log_oom();
        }

        if (link->operstate != operstate) {
                link->operstate = operstate;
                changed = true;
                if (strv_extend(&p, "OperationalState") < 0)
                        log_oom();
        }

        if (link->online_state != online_state) {
                link->online_state = online_state;
                changed = true;
                if (strv_extend(&p, "OnlineState") < 0)
                        log_oom();
        }

        if (p)
                link_send_changed_strv(link, p);
        if (changed)
                link_dirty(link);

        if (also_update_master) {
                Link *master;

                if (link_get_master(link, &master) >= 0)
                        link_update_operstate(master, true);
        }
}

#define FLAG_STRING(string, flag, old, new)                      \
        (((old ^ new) & flag)                                    \
         ? ((old & flag) ? (" -" string) : (" +" string))        \
         : "")

static int link_update_flags(Link *link, sd_netlink_message *message) {
        bool link_was_admin_up, had_carrier;
        uint8_t operstate;
        unsigned flags;
        int r;

        assert(link);
        assert(message);

        r = sd_rtnl_message_link_get_flags(message, &flags);
        if (r < 0)
                return log_link_debug_errno(link, r, "rtnl: failed to read link flags: %m");

        r = sd_netlink_message_read_u8(message, IFLA_OPERSTATE, &operstate);
        if (r == -ENODATA)
                /* If we got a message without operstate, assume the state was unchanged. */
                operstate = link->kernel_operstate;
        else if (r < 0)
                return log_link_debug_errno(link, r, "rtnl: failed to read operational state: %m");

        if (link->flags == flags && link->kernel_operstate == operstate)
                return 0;

        if (link->flags != flags) {
                unsigned unknown_flags, unknown_flags_added, unknown_flags_removed;

                log_link_debug(link, "Flags change:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                               FLAG_STRING("LOOPBACK", IFF_LOOPBACK, link->flags, flags),
                               FLAG_STRING("MASTER", IFF_MASTER, link->flags, flags),
                               FLAG_STRING("SLAVE", IFF_SLAVE, link->flags, flags),
                               FLAG_STRING("UP", IFF_UP, link->flags, flags),
                               FLAG_STRING("DORMANT", IFF_DORMANT, link->flags, flags),
                               FLAG_STRING("LOWER_UP", IFF_LOWER_UP, link->flags, flags),
                               FLAG_STRING("RUNNING", IFF_RUNNING, link->flags, flags),
                               FLAG_STRING("MULTICAST", IFF_MULTICAST, link->flags, flags),
                               FLAG_STRING("BROADCAST", IFF_BROADCAST, link->flags, flags),
                               FLAG_STRING("POINTOPOINT", IFF_POINTOPOINT, link->flags, flags),
                               FLAG_STRING("PROMISC", IFF_PROMISC, link->flags, flags),
                               FLAG_STRING("ALLMULTI", IFF_ALLMULTI, link->flags, flags),
                               FLAG_STRING("PORTSEL", IFF_PORTSEL, link->flags, flags),
                               FLAG_STRING("AUTOMEDIA", IFF_AUTOMEDIA, link->flags, flags),
                               FLAG_STRING("DYNAMIC", IFF_DYNAMIC, link->flags, flags),
                               FLAG_STRING("NOARP", IFF_NOARP, link->flags, flags),
                               FLAG_STRING("NOTRAILERS", IFF_NOTRAILERS, link->flags, flags),
                               FLAG_STRING("DEBUG", IFF_DEBUG, link->flags, flags),
                               FLAG_STRING("ECHO", IFF_ECHO, link->flags, flags));

                unknown_flags = ~(IFF_LOOPBACK | IFF_MASTER | IFF_SLAVE | IFF_UP |
                                  IFF_DORMANT | IFF_LOWER_UP | IFF_RUNNING |
                                  IFF_MULTICAST | IFF_BROADCAST | IFF_POINTOPOINT |
                                  IFF_PROMISC | IFF_ALLMULTI | IFF_PORTSEL |
                                  IFF_AUTOMEDIA | IFF_DYNAMIC | IFF_NOARP |
                                  IFF_NOTRAILERS | IFF_DEBUG | IFF_ECHO);
                unknown_flags_added = ((link->flags ^ flags) & flags & unknown_flags);
                unknown_flags_removed = ((link->flags ^ flags) & link->flags & unknown_flags);

                if (unknown_flags_added)
                        log_link_debug(link, "Unknown link flags gained, ignoring: %#.5x", unknown_flags_added);

                if (unknown_flags_removed)
                        log_link_debug(link, "Unknown link flags lost, ignoring: %#.5x", unknown_flags_removed);
        }

        link_was_admin_up = link->flags & IFF_UP;
        had_carrier = link_has_carrier(link);

        link->flags = flags;
        link->kernel_operstate = operstate;

        link_update_operstate(link, true);

        if (!link_was_admin_up && (link->flags & IFF_UP)) {
                log_link_info(link, "Link UP");

                r = link_admin_state_up(link);
                if (r < 0)
                        return r;
        } else if (link_was_admin_up && !(link->flags & IFF_UP)) {
                log_link_info(link, "Link DOWN");

                r = link_admin_state_down(link);
                if (r < 0)
                        return r;
        }

        if (!had_carrier && link_has_carrier(link)) {
                log_link_info(link, "Gained carrier");

                r = link_carrier_gained(link);
                if (r < 0)
                        return r;
        } else if (had_carrier && !link_has_carrier(link)) {
                log_link_info(link, "Lost carrier");

                r = link_carrier_lost(link);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int link_update_master(Link *link, sd_netlink_message *message) {
        int master_ifindex, r;

        assert(link);
        assert(message);

        r = sd_netlink_message_read_u32(message, IFLA_MASTER, (uint32_t*) &master_ifindex);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return log_link_debug_errno(link, r, "rtnl: failed to read master ifindex: %m");

        if (master_ifindex == link->ifindex)
                master_ifindex = 0;

        if (master_ifindex == link->master_ifindex)
                return 0;

        if (link->master_ifindex == 0)
                log_link_debug(link, "Attached to master interface: %i", master_ifindex);
        else if (master_ifindex == 0)
                log_link_debug(link, "Detached from master interface: %i", link->master_ifindex);
        else
                log_link_debug(link, "Master interface changed: %i %s %i", link->master_ifindex,
                               special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), master_ifindex);

        link_drop_from_master(link);

        link->master_ifindex = master_ifindex;

        r = link_append_to_master(link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to append link to master: %m");

        return 0;
}

static int link_update_driver(Link *link, sd_netlink_message *message) {
        int r;

        assert(link);
        assert(link->manager);
        assert(message);

        /* Driver is already read. Assuming the driver is never changed. */
        if (link->ethtool_driver_read)
                return 0;

        /* When udevd is running, read the driver after the interface is initialized by udevd.
         * Otherwise, ethtool may not work correctly. See issue #22538.
         * When udevd is not running, read the value when the interface is detected. */
        if (udev_available() && !link->dev)
                return 0;

        link->ethtool_driver_read = true;

        r = ethtool_get_driver(&link->manager->ethtool_fd, link->ifname, &link->driver);
        if (r < 0) {
                log_link_debug_errno(link, r, "Failed to get driver, continuing without: %m");
                return 0;
        }

        log_link_debug(link, "Found driver: %s", strna(link->driver));

        if (streq_ptr(link->driver, "dsa")) {
                uint32_t dsa_master_ifindex = 0;

                r = sd_netlink_message_read_u32(message, IFLA_LINK, &dsa_master_ifindex);
                if (r < 0 && r != -ENODATA)
                        return log_link_debug_errno(link, r, "rtnl: failed to read ifindex of the DSA master interface: %m");

                if (dsa_master_ifindex > INT_MAX) {
                        log_link_debug(link, "rtnl: received too large DSA master ifindex (%"PRIu32" > INT_MAX), ignoring.",
                                       dsa_master_ifindex);
                        dsa_master_ifindex = 0;
                }

                link->dsa_master_ifindex = (int) dsa_master_ifindex;
        }

        return 1; /* needs reconfigure */
}

static int link_update_permanent_hardware_address_from_ethtool(Link *link, sd_netlink_message *message) {
        int r;

        assert(link);
        assert(link->manager);
        assert(message);

        if (link->ethtool_permanent_hw_addr_read)
                return 0;

        /* When udevd is running, read the permanent hardware address after the interface is
         * initialized by udevd. Otherwise, ethtool may not work correctly. See issue #22538.
         * When udevd is not running, read the value when the interface is detected. */
        if (udev_available() && !link->dev)
                return 0;

        /* If the interface does not have a hardware address, then it will not have a permanent address either. */
        r = netlink_message_read_hw_addr(message, IFLA_ADDRESS, NULL);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to read IFLA_ADDRESS attribute: %m");

        link->ethtool_permanent_hw_addr_read = true;

        r = ethtool_get_permanent_hw_addr(&link->manager->ethtool_fd, link->ifname, &link->permanent_hw_addr);
        if (r < 0)
                log_link_debug_errno(link, r, "Permanent hardware address not found, continuing without: %m");

        return 0;
}

static int link_update_permanent_hardware_address(Link *link, sd_netlink_message *message) {
        int r;

        assert(link);
        assert(link->manager);
        assert(message);

        if (link->permanent_hw_addr.length > 0)
                return 0;

        r = netlink_message_read_hw_addr(message, IFLA_PERM_ADDRESS, &link->permanent_hw_addr);
        if (r < 0) {
                if (r != -ENODATA)
                        return log_link_debug_errno(link, r, "Failed to read IFLA_PERM_ADDRESS attribute: %m");

                /* Fallback to ethtool for older kernels. */
                r = link_update_permanent_hardware_address_from_ethtool(link, message);
                if (r < 0)
                        return r;
        }

        if (link->permanent_hw_addr.length > 0)
                log_link_debug(link, "Saved permanent hardware address: %s", HW_ADDR_TO_STR(&link->permanent_hw_addr));

        return 1; /* needs reconfigure */
}

static int link_update_hardware_address(Link *link, sd_netlink_message *message) {
        struct hw_addr_data addr;
        int r;

        assert(link);
        assert(message);

        r = netlink_message_read_hw_addr(message, IFLA_BROADCAST, &link->bcast_addr);
        if (r < 0 && r != -ENODATA)
                return log_link_debug_errno(link, r, "rtnl: failed to read broadcast address: %m");

        r = netlink_message_read_hw_addr(message, IFLA_ADDRESS, &addr);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return log_link_debug_errno(link, r, "rtnl: failed to read hardware address: %m");

        if (hw_addr_equal(&link->hw_addr, &addr))
                return 0;

        if (link->hw_addr.length == 0)
                log_link_debug(link, "Saved hardware address: %s", HW_ADDR_TO_STR(&addr));
        else {
                log_link_debug(link, "Hardware address is changed: %s %s %s",
                               HW_ADDR_TO_STR(&link->hw_addr),
                               special_glyph(SPECIAL_GLYPH_ARROW_RIGHT),
                               HW_ADDR_TO_STR(&addr));

                hashmap_remove_value(link->manager->links_by_hw_addr, &link->hw_addr, link);
        }

        link->hw_addr = addr;

        if (!hw_addr_is_null(&link->hw_addr)) {
                r = hashmap_ensure_put(&link->manager->links_by_hw_addr, &hw_addr_hash_ops, &link->hw_addr, link);
                if (r == -EEXIST && streq_ptr(link->kind, "bond"))
                        /* bonding master and its slaves have the same hardware address. */
                        r = hashmap_replace(link->manager->links_by_hw_addr, &link->hw_addr, link);
                if (r < 0)
                        log_link_debug_errno(link, r, "Failed to manage link by its new hardware address, ignoring: %m");
        }

        r = ipv4acd_update_mac(link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not update MAC address in IPv4 ACD client: %m");

        r = ipv4ll_update_mac(link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not update MAC address in IPv4LL client: %m");

        r = dhcp4_update_mac(link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not update MAC address in DHCP client: %m");

        r = dhcp6_update_mac(link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not update MAC address in DHCPv6 client: %m");

        r = radv_update_mac(link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not update MAC address for Router Advertisement: %m");

        if (link->ndisc && link->hw_addr.length == ETH_ALEN) {
                r = sd_ndisc_set_mac(link->ndisc, &link->hw_addr.ether);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not update MAC for NDisc: %m");
        }

        if (link->lldp_rx) {
                r = sd_lldp_rx_set_filter_address(link->lldp_rx, &link->hw_addr.ether);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not update MAC address for LLDP Rx: %m");
        }

        if (link->lldp_tx) {
                r = sd_lldp_tx_set_hwaddr(link->lldp_tx, &link->hw_addr.ether);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not update MAC address for LLDP Tx: %m");
        }

        return 1; /* needs reconfigure */
}

static int link_update_mtu(Link *link, sd_netlink_message *message) {
        uint32_t mtu, min_mtu = 0, max_mtu = UINT32_MAX;
        int r;

        assert(link);
        assert(message);

        r = sd_netlink_message_read_u32(message, IFLA_MTU, &mtu);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return log_link_debug_errno(link, r, "rtnl: failed to read MTU in RTM_NEWLINK message: %m");
        if (mtu == 0)
                return 0;

        r = sd_netlink_message_read_u32(message, IFLA_MIN_MTU, &min_mtu);
        if (r < 0 && r != -ENODATA)
                return log_link_debug_errno(link, r, "rtnl: failed to read minimum MTU in RTM_NEWLINK message: %m");

        r = sd_netlink_message_read_u32(message, IFLA_MAX_MTU, &max_mtu);
        if (r < 0 && r != -ENODATA)
                return log_link_debug_errno(link, r, "rtnl: failed to read maximum MTU in RTM_NEWLINK message: %m");

        if (max_mtu == 0)
                max_mtu = UINT32_MAX;

        link->min_mtu = min_mtu;
        link->max_mtu = max_mtu;

        if (link->original_mtu == 0) {
                link->original_mtu = mtu;
                log_link_debug(link, "Saved original MTU %" PRIu32" (min: %"PRIu32", max: %"PRIu32")",
                               link->original_mtu, link->min_mtu, link->max_mtu);
        }

        if (link->mtu == mtu)
                return 0;

        if (link->mtu != 0)
                log_link_debug(link, "MTU is changed: %"PRIu32" %s %"PRIu32" (min: %"PRIu32", max: %"PRIu32")",
                               link->mtu, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), mtu,
                               link->min_mtu, link->max_mtu);

        link->mtu = mtu;

        if (link->dhcp_client) {
                r = sd_dhcp_client_set_mtu(link->dhcp_client, link->mtu);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not update MTU in DHCP client: %m");
        }

        if (link->radv) {
                r = sd_radv_set_mtu(link->radv, link->mtu);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Could not set MTU for Router Advertisement: %m");
        }

        return 0;
}

static int link_update_alternative_names(Link *link, sd_netlink_message *message) {
        _cleanup_strv_free_ char **altnames = NULL;
        int r;

        assert(link);
        assert(message);

        r = sd_netlink_message_read_strv(message, IFLA_PROP_LIST, IFLA_ALT_IFNAME, &altnames);
        if (r == -ENODATA)
                /* The message does not have IFLA_PROP_LIST container attribute. It does not mean the
                 * interface has no alternative name. */
                return 0;
        if (r < 0)
                return log_link_debug_errno(link, r, "rtnl: failed to read alternative names: %m");

        if (strv_equal(altnames, link->alternative_names))
                return 0;

        STRV_FOREACH(n, link->alternative_names)
                hashmap_remove(link->manager->links_by_name, *n);

        strv_free_and_replace(link->alternative_names, altnames);

        STRV_FOREACH(n, link->alternative_names) {
                r = hashmap_ensure_put(&link->manager->links_by_name, &string_hash_ops, *n, link);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to manage link by its new alternative names: %m");
        }

        return 1; /* needs reconfigure */
}

static int link_update_name(Link *link, sd_netlink_message *message) {
        char ifname_from_index[IF_NAMESIZE];
        const char *ifname;
        int r;

        assert(link);
        assert(message);

        r = sd_netlink_message_read_string(message, IFLA_IFNAME, &ifname);
        if (r == -ENODATA)
                /* Hmm?? But ok. */
                return 0;
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to read interface name in RTM_NEWLINK message: %m");

        if (streq(ifname, link->ifname))
                return 0;

        r = format_ifname(link->ifindex, ifname_from_index);
        if (r < 0)
                return log_link_debug_errno(link, r, "Could not get interface name for index %i.", link->ifindex);

        if (!streq(ifname, ifname_from_index)) {
                log_link_debug(link, "New interface name '%s' received from the kernel does not correspond "
                               "with the name currently configured on the actual interface '%s'. Ignoring.",
                               ifname, ifname_from_index);
                return 0;
        }

        log_link_info(link, "Interface name change detected, renamed to %s.", ifname);

        hashmap_remove(link->manager->links_by_name, link->ifname);

        r = free_and_strdup(&link->ifname, ifname);
        if (r < 0)
                return log_oom_debug();

        r = hashmap_ensure_put(&link->manager->links_by_name, &string_hash_ops, link->ifname, link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to manage link by its new name: %m");

        if (link->dhcp_client) {
                r = sd_dhcp_client_set_ifname(link->dhcp_client, link->ifname);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to update interface name in DHCP client: %m");
        }

        if (link->dhcp6_client) {
                r = sd_dhcp6_client_set_ifname(link->dhcp6_client, link->ifname);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to update interface name in DHCP6 client: %m");
        }

        if (link->ndisc) {
                r = sd_ndisc_set_ifname(link->ndisc, link->ifname);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to update interface name in NDisc: %m");
        }

        if (link->dhcp_server) {
                r = sd_dhcp_server_set_ifname(link->dhcp_server, link->ifname);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to update interface name in DHCP server: %m");
        }

        if (link->radv) {
                r = sd_radv_set_ifname(link->radv, link->ifname);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to update interface name in Router Advertisement: %m");
        }

        if (link->lldp_rx) {
                r = sd_lldp_rx_set_ifname(link->lldp_rx, link->ifname);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to update interface name in LLDP Rx: %m");
        }

        if (link->lldp_tx) {
                r = sd_lldp_tx_set_ifname(link->lldp_tx, link->ifname);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to update interface name in LLDP Tx: %m");
        }

        if (link->ipv4ll) {
                r = sd_ipv4ll_set_ifname(link->ipv4ll, link->ifname);
                if (r < 0)
                        return log_link_debug_errno(link, r, "Failed to update interface name in IPv4LL client: %m");
        }

        r = ipv4acd_set_ifname(link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to update interface name in IPv4ACD client: %m");

        return 1; /* needs reconfigure */
}

static int link_update(Link *link, sd_netlink_message *message) {
        bool needs_reconfigure = false;
        int r;

        assert(link);
        assert(message);

        r = link_update_name(link, message);
        if (r < 0)
                return r;
        needs_reconfigure = needs_reconfigure || r > 0;

        r = link_update_alternative_names(link, message);
        if (r < 0)
                return r;
        needs_reconfigure = needs_reconfigure || r > 0;

        r = link_update_mtu(link, message);
        if (r < 0)
                return r;

        r = link_update_driver(link, message);
        if (r < 0)
                return r;
        needs_reconfigure = needs_reconfigure || r > 0;

        r = link_update_permanent_hardware_address(link, message);
        if (r < 0)
                return r;
        needs_reconfigure = needs_reconfigure || r > 0;

        r = link_update_hardware_address(link, message);
        if (r < 0)
                return r;
        needs_reconfigure = needs_reconfigure || r > 0;

        r = link_update_master(link, message);
        if (r < 0)
                return r;

        r = link_update_ipv6ll_addrgen_mode(link, message);
        if (r < 0)
                return r;

        r = link_update_flags(link, message);
        if (r < 0)
                return r;

        r = link_update_bridge_vlan(link, message);
        if (r < 0)
                return r;

        return needs_reconfigure;
}

static Link *link_drop_or_unref(Link *link) {
        if (!link)
                return NULL;
        if (!link->manager)
                return link_unref(link);
        return link_drop(link);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Link*, link_drop_or_unref);

static int link_new(Manager *manager, sd_netlink_message *message, Link **ret) {
        _cleanup_free_ char *ifname = NULL, *kind = NULL, *state_file = NULL, *lease_file = NULL, *lldp_file = NULL;
        _cleanup_(link_drop_or_unrefp) Link *link = NULL;
        unsigned short iftype;
        int r, ifindex;

        assert(manager);
        assert(message);
        assert(ret);

        r = sd_rtnl_message_link_get_ifindex(message, &ifindex);
        if (r < 0)
                return log_debug_errno(r, "rtnl: failed to read ifindex from link message: %m");
        else if (ifindex <= 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "rtnl: received link message without valid ifindex.");

        r = sd_rtnl_message_link_get_type(message, &iftype);
        if (r < 0)
                return log_debug_errno(r, "rtnl: failed to read interface type from link message: %m");

        r = sd_netlink_message_read_string_strdup(message, IFLA_IFNAME, &ifname);
        if (r < 0)
                return log_debug_errno(r, "rtnl: failed to read interface name from link message: %m");

        /* check for link kind */
        r = sd_netlink_message_enter_container(message, IFLA_LINKINFO);
        if (r >= 0) {
                r = sd_netlink_message_read_string_strdup(message, IFLA_INFO_KIND, &kind);
                if (r < 0 && r != -ENODATA)
                        return log_debug_errno(r, "rtnl: failed to read interface kind from link message: %m");
                r = sd_netlink_message_exit_container(message);
                if (r < 0)
                        return log_debug_errno(r, "rtnl: failed to exit IFLA_LINKINFO container: %m");
        }

        if (!manager->test_mode) {
                /* Do not update state files when running in test mode. */
                if (asprintf(&state_file, "/run/systemd/netif/links/%d", ifindex) < 0)
                        return log_oom_debug();

                if (asprintf(&lease_file, "/run/systemd/netif/leases/%d", ifindex) < 0)
                        return log_oom_debug();

                if (asprintf(&lldp_file, "/run/systemd/netif/lldp/%d", ifindex) < 0)
                        return log_oom_debug();
        }

        link = new(Link, 1);
        if (!link)
                return -ENOMEM;

        *link = (Link) {
                .n_ref = 1,
                .state = LINK_STATE_PENDING,
                .online_state = _LINK_ONLINE_STATE_INVALID,
                .ifindex = ifindex,
                .iftype = iftype,
                .ifname = TAKE_PTR(ifname),
                .kind = TAKE_PTR(kind),

                .bridge_vlan_pvid = UINT16_MAX,

                .ipv6ll_address_gen_mode = _IPV6_LINK_LOCAL_ADDRESS_GEN_MODE_INVALID,

                .state_file = TAKE_PTR(state_file),
                .lease_file = TAKE_PTR(lease_file),
                .lldp_file = TAKE_PTR(lldp_file),

                .n_dns = UINT_MAX,
                .dns_default_route = -1,
                .llmnr = _RESOLVE_SUPPORT_INVALID,
                .mdns = _RESOLVE_SUPPORT_INVALID,
                .dnssec_mode = _DNSSEC_MODE_INVALID,
                .dns_over_tls_mode = _DNS_OVER_TLS_MODE_INVALID,
        };

        r = hashmap_ensure_put(&manager->links_by_index, NULL, INT_TO_PTR(link->ifindex), link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to store link into manager: %m");

        link->manager = manager;

        r = hashmap_ensure_put(&manager->links_by_name, &string_hash_ops, link->ifname, link);
        if (r < 0)
                return log_link_debug_errno(link, r, "Failed to manage link by its interface name: %m");

        log_link_debug(link, "Saved new link: ifindex=%i, iftype=%s(%u), kind=%s",
                       link->ifindex, strna(arphrd_to_name(link->iftype)), link->iftype, strna(link->kind));

        /* If contained in this set, the link is wireless and the corresponding NL80211_CMD_NEW_INTERFACE
         * message arrived too early. Request the wireless link information again.
         */
        if (set_remove(manager->new_wlan_ifindices, INT_TO_PTR(link->ifindex))) {
                r = link_get_wlan_interface(link);
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to get wireless interface, ignoring: %m");
        }

        *ret = TAKE_PTR(link);
        return 0;
}

int manager_rtnl_process_link(sd_netlink *rtnl, sd_netlink_message *message, Manager *manager) {
        Link *link = NULL;
        NetDev *netdev = NULL;
        uint16_t type;
        const char *name;
        int r, ifindex;

        assert(rtnl);
        assert(message);
        assert(manager);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_message_warning_errno(message, r, "rtnl: Could not receive link message, ignoring");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWLINK, RTM_DELLINK)) {
                log_warning("rtnl: Received unexpected message type %u when processing link, ignoring.", type);
                return 0;
        }

        r = sd_rtnl_message_link_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Could not get ifindex from link message, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received link message with invalid ifindex %d, ignoring.", ifindex);
                return 0;
        }

        r = sd_netlink_message_read_string(message, IFLA_IFNAME, &name);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Received link message without ifname, ignoring: %m");
                return 0;
        }

        (void) link_get_by_index(manager, ifindex, &link);
        (void) netdev_get(manager, name, &netdev);

        switch (type) {
        case RTM_NEWLINK:
                if (netdev) {
                        /* netdev exists, so make sure the ifindex matches */
                        r = netdev_set_ifindex(netdev, message);
                        if (r < 0) {
                                log_netdev_warning_errno(netdev, r, "Could not process new link message for netdev, ignoring: %m");
                                return 0;
                        }
                }

                if (!link) {
                        /* link is new, so add it */
                        r = link_new(manager, message, &link);
                        if (r < 0) {
                                log_warning_errno(r, "Could not process new link message: %m");
                                return 0;
                        }

                        r = link_update(link, message);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Could not process link message: %m");
                                link_enter_failed(link);
                                return 0;
                        }

                        r = link_check_initialized(link);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Failed to check link is initialized: %m");
                                link_enter_failed(link);
                                return 0;
                        }
                } else {
                        r = link_update(link, message);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "Could not process link message: %m");
                                link_enter_failed(link);
                                return 0;
                        }
                        if (r > 0) {
                                r = link_reconfigure_impl(link, /* force = */ false);
                                if (r < 0) {
                                        log_link_warning_errno(link, r, "Failed to reconfigure interface: %m");
                                        link_enter_failed(link);
                                        return 0;
                                }
                        }
                }
                break;

        case RTM_DELLINK:
                link_drop(link);
                netdev_drop(netdev);
                break;

        default:
                assert_not_reached();
        }

        return 1;
}

int link_getlink_handler_internal(sd_netlink *rtnl, sd_netlink_message *m, Link *link, const char *error_msg) {
        uint16_t message_type;
        int r;

        assert(m);
        assert(link);
        assert(error_msg);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_link_message_warning_errno(link, m, r, error_msg);
                link_enter_failed(link);
                return 0;
        }

        r = sd_netlink_message_get_type(m, &message_type);
        if (r < 0) {
                log_link_debug_errno(link, r, "rtnl: failed to read link message type, ignoring: %m");
                return 0;
        }
        if (message_type != RTM_NEWLINK) {
                log_link_debug(link, "rtnl: received invalid link message type, ignoring.");
                return 0;
        }

        r = link_update(link, m);
        if (r < 0) {
                link_enter_failed(link);
                return 0;
        }

        return 1;
}

int link_call_getlink(Link *link, link_netlink_message_handler_t callback) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(callback);

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_GETLINK, link->ifindex);
        if (r < 0)
                return r;

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return r;

        link_ref(link);
        return 0;
}

static const char* const link_state_table[_LINK_STATE_MAX] = {
        [LINK_STATE_PENDING]     = "pending",
        [LINK_STATE_INITIALIZED] = "initialized",
        [LINK_STATE_CONFIGURING] = "configuring",
        [LINK_STATE_CONFIGURED]  = "configured",
        [LINK_STATE_UNMANAGED]   = "unmanaged",
        [LINK_STATE_FAILED]      = "failed",
        [LINK_STATE_LINGER]      = "linger",
};

DEFINE_STRING_TABLE_LOOKUP(link_state, LinkState);

int link_flags_to_string_alloc(uint32_t flags, char **ret) {
        _cleanup_free_ char *str = NULL;
        static const char* map[] = {
                [LOG2U(IFF_UP)]          = "up",             /* interface is up. */
                [LOG2U(IFF_BROADCAST)]   = "broadcast",      /* broadcast address valid. */
                [LOG2U(IFF_DEBUG)]       = "debug",          /* turn on debugging. */
                [LOG2U(IFF_LOOPBACK)]    = "loopback",       /* interface is a loopback net. */
                [LOG2U(IFF_POINTOPOINT)] = "point-to-point", /* interface has p-p link. */
                [LOG2U(IFF_NOTRAILERS)]  = "no-trailers",    /* avoid use of trailers. */
                [LOG2U(IFF_RUNNING)]     = "running",        /* interface RFC2863 OPER_UP. */
                [LOG2U(IFF_NOARP)]       = "no-arp",         /* no ARP protocol. */
                [LOG2U(IFF_PROMISC)]     = "promiscuous",    /* receive all packets. */
                [LOG2U(IFF_ALLMULTI)]    = "all-multicast",  /* receive all multicast packets. */
                [LOG2U(IFF_MASTER)]      = "master",         /* master of a load balancer. */
                [LOG2U(IFF_SLAVE)]       = "slave",          /* slave of a load balancer. */
                [LOG2U(IFF_MULTICAST)]   = "multicast",      /* supports multicast. */
                [LOG2U(IFF_PORTSEL)]     = "portsel",        /* can set media type. */
                [LOG2U(IFF_AUTOMEDIA)]   = "auto-media",     /* auto media select active. */
                [LOG2U(IFF_DYNAMIC)]     = "dynamic",        /* dialup device with changing addresses. */
                [LOG2U(IFF_LOWER_UP)]    = "lower-up",       /* driver signals L1 up. */
                [LOG2U(IFF_DORMANT)]     = "dormant",        /* driver signals dormant. */
                [LOG2U(IFF_ECHO)]        = "echo",           /* echo sent packets. */
        };

        assert(ret);

        for (size_t i = 0; i < ELEMENTSOF(map); i++)
                if (FLAGS_SET(flags, 1 << i) && map[i])
                        if (!strextend_with_separator(&str, ",", map[i]))
                                return -ENOMEM;

        *ret = TAKE_PTR(str);
        return 0;
}

static const char * const kernel_operstate_table[] = {
        [IF_OPER_UNKNOWN]        = "unknown",
        [IF_OPER_NOTPRESENT]     = "not-present",
        [IF_OPER_DOWN]           = "down",
        [IF_OPER_LOWERLAYERDOWN] = "lower-layer-down",
        [IF_OPER_TESTING]        = "testing",
        [IF_OPER_DORMANT]        = "dormant",
        [IF_OPER_UP]             = "up",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(kernel_operstate, int);
