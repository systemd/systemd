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

DEFINE_PRIVATE_HASH_OPS_FULL(
        ipv4acd_hash_ops,
        Address,
        address_hash_func,
        address_compare_func,
        address_unref,
        sd_ipv4acd,
        sd_ipv4acd_unref);

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

        acd = hashmap_get(link->ipv4acd_by_address, address);
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

        /* Do not call address_remove_and_cancel() here. Otherwise, the request is cancelled, and the
         * interface may be in configured state without the address. */
        r = address_remove(address, link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to remove address %s: %m", IN4_ADDR_TO_STRING(&address->in_addr.in));

        return 0;
}

static int dhcp4_address_on_conflict(Link *link) {
        int r;

        assert(link);
        assert(link->dhcp_client);

        log_link_warning(link, "Dropping DHCPv4 lease, as an address conflict was detected.");

        r = sd_dhcp_client_send_decline(link->dhcp_client);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to send DHCP DECLINE, ignoring: %m");

        if (!link->dhcp_lease)
                return 0;

        r = dhcp4_lease_lost(link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to drop DHCPv4 lease: %m");

        /* It is not necessary to call address_remove() here, as dhcp4_lease_lost() removes the address. */
        return 0;
}

static void on_acd(sd_ipv4acd *acd, int event, void *userdata) {
        Link *link = ASSERT_PTR(userdata);
        Address *address = NULL;
        int r;

        assert(acd);

        void *val, *key;
        HASHMAP_FOREACH_KEY(val, key, link->ipv4acd_by_address)
                if (val == acd) {
                        (void) address_get(link, key, &address);
                        break;
                }

        if (!address)
                return;

        switch (event) {
        case SD_IPV4ACD_EVENT_STOP:
                if (address->source == NETWORK_CONFIG_SOURCE_STATIC) {
                        r = static_ipv4acd_address_remove(link, address, /* on_conflict = */ false);
                        if (r < 0)
                                link_enter_failed(link);
                }

                /* We have nothing to do for DHCPv4 lease here, as the dhcp client is already stopped
                 * when stopping the ipv4acd client. See link_stop_engines(). */
                break;

        case SD_IPV4ACD_EVENT_BIND:
                log_link_debug(link, "Successfully claimed address %s", IN4_ADDR_TO_STRING(&address->in_addr.in));
                break;

        case SD_IPV4ACD_EVENT_CONFLICT:
                log_link_warning(link, "Dropping address %s, as an address conflict was detected.", IN4_ADDR_TO_STRING(&address->in_addr.in));

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
        _cleanup_(address_unrefp) Address *a = NULL;
        sd_ipv4acd *existing;
        int r;

        assert(link);
        assert(link->manager);
        assert(address);

        if (address->family != AF_INET)
                return 0;

        existing = hashmap_get(link->ipv4acd_by_address, address);

        if (!address_ipv4acd_enabled(link, address))
                return sd_ipv4acd_stop(existing);

        if (existing)
                return ipv4acd_start_one(link, existing);

        log_link_debug(link, "Configuring IPv4ACD for address %s.", IN4_ADDR_TO_STRING(&address->in_addr.in));

        r = address_new(&a);
        if (r < 0)
                return r;

        a->family = AF_INET;
        a->in_addr = address->in_addr;
        a->in_addr_peer = address->in_addr_peer;
        a->prefixlen = address->prefixlen;

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

        r = ipv4acd_start_one(link, acd);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&link->ipv4acd_by_address, &ipv4acd_hash_ops, a, acd);
        if (r < 0)
                return r;

        TAKE_PTR(a);
        TAKE_PTR(acd);
        return 0;
}

void ipv4acd_detach(Link *link, const Address *address) {
        assert(link);
        assert(address);

        if (address->family != AF_INET)
                return;

        Address *a;
        sd_ipv4acd_unref(hashmap_remove2(link->ipv4acd_by_address, address, (void**) &a));
        address_unref(a);
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
