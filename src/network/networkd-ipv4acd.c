/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h> /* IFF_LOOPBACK */
#include <net/if_arp.h> /* ARPHRD_ETHER */

#include "sd-dhcp-client.h"
#include "sd-ipv4acd.h"

#include "ipvlan.h"
#include "networkd-address.h"
#include "networkd-dhcp4.h"
#include "networkd-ipv4acd.h"
#include "networkd-link.h"
#include "networkd-manager.h"

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        ipv4acd_hash_ops,
        void, trivial_hash_func, trivial_compare_func,
        sd_ipv4acd, sd_ipv4acd_unref);

bool link_ipv4acd_supported(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        /* ARPHRD_INFINIBAND seems to potentially support IPv4ACD.
         * But currently sd-ipv4acd only supports ARPHRD_ETHER. */
        if (link->iftype != ARPHRD_ETHER)
                return false;

        if (link->hw_addr.length != ETH_ALEN)
                return false;

        if (ether_addr_is_null(&link->hw_addr.ether))
                return false;

        if (streq_ptr(link->kind, "vrf"))
                return false;

        /* L3 or L3S mode do not support ARP. */
        if (IN_SET(link_get_ipvlan_mode(link), NETDEV_IPVLAN_MODE_L3, NETDEV_IPVLAN_MODE_L3S))
                return false;

        return true;
}

static bool address_ipv4acd_enabled(Link *link, const Address *address) {
        assert(link);
        assert(address);

        if (address->family != AF_INET)
                return false;

        if (!FLAGS_SET(address->duplicate_address_detection, ADDRESS_FAMILY_IPV4))
                return false;

        /* Currently, only static and DHCP4 addresses are supported. */
        if (!IN_SET(address->source, NETWORK_CONFIG_SOURCE_STATIC, NETWORK_CONFIG_SOURCE_DHCP4))
                return false;

        return link_ipv4acd_supported(link);
}

bool ipv4acd_bound(Link *link, const Address *address) {
        sd_ipv4acd *acd;

        assert(link);
        assert(address);

        if (address->family != AF_INET)
                return true;

        acd = hashmap_get(link->ipv4acd_by_address, IN4_ADDR_TO_PTR(&address->in_addr.in));
        if (!acd)
                return true;

        return sd_ipv4acd_is_bound(acd) > 0;
}

static int static_ipv4acd_address_remove(Link *link, Address *address, bool on_conflict) {
        int r;

        assert(link);
        assert(address);

        if (!address_exists(address))
                return 0; /* Not assigned. */

        if (on_conflict)
                log_link_warning(link, "Dropping address %s, as an address conflict was detected.", IN4_ADDR_TO_STRING(&address->in_addr.in));
        else
                log_link_debug(link, "Removing address %s, as the ACD client is stopped.", IN4_ADDR_TO_STRING(&address->in_addr.in));

        r = address_remove(address, link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to remove address %s: %m", IN4_ADDR_TO_STRING(&address->in_addr.in));

        return 0;
}

static int dhcp4_address_on_conflict(Link *link) {
        int r;

        assert(link);
        assert(link->dhcp_client);

        r = sd_dhcp_client_send_decline(link->dhcp_client);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to send DHCP DECLINE, ignoring: %m");

        if (!link->dhcp_lease)
                /* Unlikely, but during probing the address, the lease may be lost. */
                return 0;

        log_link_warning(link, "Dropping DHCPv4 lease, as an address conflict was detected.");
        r = dhcp4_lease_lost(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to drop DHCPv4 lease: %m");

        /* It is not necessary to call address_remove() here, as dhcp4_lease_lost() removes it. */
        return 0;
}

static void on_acd(sd_ipv4acd *acd, int event, void *userdata) {
        Link *link = ASSERT_PTR(userdata);
        Address *address = NULL;
        struct in_addr a;
        int r;

        assert(acd);

        r = sd_ipv4acd_get_address(acd, &a);
        if (r < 0) {
                log_link_warning_errno(link, r, "Failed to get address from IPv4ACD: %m");
                link_enter_failed(link);
        }

        (void) link_get_ipv4_address(link, &a, 0, &address);

        switch (event) {
        case SD_IPV4ACD_EVENT_STOP:
                if (!address)
                        break;

                if (address->source == NETWORK_CONFIG_SOURCE_STATIC) {
                        r = static_ipv4acd_address_remove(link, address, /* on_conflict = */ false);
                        if (r < 0)
                                link_enter_failed(link);
                }

                /* We have nothing to do for DHCPv4 lease here, as the dhcp client is already stopped
                 * when stopping the ipv4acd client. See link_stop_engines(). */
                break;

        case SD_IPV4ACD_EVENT_BIND:
                log_link_debug(link, "Successfully claimed address %s", IN4_ADDR_TO_STRING(&a));
                break;

        case SD_IPV4ACD_EVENT_CONFLICT:
                if (!address)
                        break;

                log_link_warning(link, "Dropping address %s, as an address conflict was detected.", IN4_ADDR_TO_STRING(&a));

                if (address->source == NETWORK_CONFIG_SOURCE_STATIC)
                        r = static_ipv4acd_address_remove(link, address, /* on_conflict = */ true);
                else
                        r = dhcp4_address_on_conflict(link);
                if (r < 0)
                        link_enter_failed(link);
                break;

        default:
                assert_not_reached();
        }
}

static int ipv4acd_check_mac(sd_ipv4acd *acd, const struct ether_addr *mac, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        struct hw_addr_data hw_addr;

        assert(mac);

        hw_addr = (struct hw_addr_data) {
                .length = ETH_ALEN,
                .ether = *mac,
        };

        return link_get_by_hw_addr(m, &hw_addr, NULL) >= 0;
}

static int ipv4acd_start_one(Link *link, sd_ipv4acd *acd) {
        assert(link);
        assert(acd);

        if (sd_ipv4acd_is_running(acd))
                return 0;

        if (!link_has_carrier(link))
                return 0;

        return sd_ipv4acd_start(acd, /* reset_conflicts = */ true);
}

int ipv4acd_configure(Link *link, const Address *address) {
        _cleanup_(sd_ipv4acd_unrefp) sd_ipv4acd *acd = NULL;
        sd_ipv4acd *existing;
        int r;

        assert(link);
        assert(link->manager);
        assert(address);

        if (address->family != AF_INET)
                return 0;

        existing = hashmap_get(link->ipv4acd_by_address, IN4_ADDR_TO_PTR(&address->in_addr.in));

        if (!address_ipv4acd_enabled(link, address))
                return sd_ipv4acd_stop(existing);

        if (existing)
                return ipv4acd_start_one(link, existing);

        log_link_debug(link, "Configuring IPv4ACD for address %s.", IN4_ADDR_TO_STRING(&address->in_addr.in));

        r = sd_ipv4acd_new(&acd);
        if (r < 0)
                return r;

        r = sd_ipv4acd_attach_event(acd, link->manager->event, 0);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_ifindex(acd, link->ifindex);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_mac(acd, &link->hw_addr.ether);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_address(acd, &address->in_addr.in);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_callback(acd, on_acd, link);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_check_mac_callback(acd, ipv4acd_check_mac, link->manager);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&link->ipv4acd_by_address, &ipv4acd_hash_ops, IN4_ADDR_TO_PTR(&address->in_addr.in), acd);
        if (r < 0)
                return r;

        return ipv4acd_start_one(link, TAKE_PTR(acd));
}

void ipv4acd_detach(Link *link, const Address *address) {
        assert(link);
        assert(address);

        if (address->family != AF_INET)
                return;

        sd_ipv4acd_unref(hashmap_remove(link->ipv4acd_by_address, IN4_ADDR_TO_PTR(&address->in_addr.in)));
}

int ipv4acd_update_mac(Link *link) {
        sd_ipv4acd *acd;
        int r;

        assert(link);

        if (link->hw_addr.length != ETH_ALEN)
                return 0;
        if (ether_addr_is_null(&link->hw_addr.ether))
                return 0;

        HASHMAP_FOREACH(acd, link->ipv4acd_by_address) {
                r = sd_ipv4acd_set_mac(acd, &link->hw_addr.ether);
                if (r < 0)
                        return r;
        }

        return 0;
}

int ipv4acd_start(Link *link) {
        sd_ipv4acd *acd;
        int r;

        assert(link);

        HASHMAP_FOREACH(acd, link->ipv4acd_by_address) {
                r = ipv4acd_start_one(link, acd);
                if (r < 0)
                        return r;
        }

        return 0;
}

int ipv4acd_stop(Link *link) {
        sd_ipv4acd *acd;
        int k, r = 0;

        assert(link);

        HASHMAP_FOREACH(acd, link->ipv4acd_by_address) {
                k = sd_ipv4acd_stop(acd);
                if (k < 0)
                        r = k;
        }

        return r;
}

int ipv4acd_set_ifname(Link *link) {
        sd_ipv4acd *acd;
        int r;

        assert(link);

        HASHMAP_FOREACH(acd, link->ipv4acd_by_address) {
                r = sd_ipv4acd_set_ifname(acd, link->ifname);
                if (r < 0)
                        return r;
        }

        return 0;
}
