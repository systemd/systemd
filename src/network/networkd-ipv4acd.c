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

static bool address_ipv4acd_enabled(Address *address) {
        assert(address);
        assert(address->link);

        if (address->family != AF_INET)
                return false;

        if (!FLAGS_SET(address->duplicate_address_detection, ADDRESS_FAMILY_IPV4))
                return false;

        /* Currently, only static and DHCP4 addresses are supported. */
        if (!IN_SET(address->source, NETWORK_CONFIG_SOURCE_STATIC, NETWORK_CONFIG_SOURCE_DHCP4))
                return false;

        if (!link_ipv4acd_supported(address->link))
                return false;

        return true;
}

bool ipv4acd_bound(const Address *address) {
        assert(address);

        if (!address->acd)
                return true;

        return address->acd_bound;
}

static int static_ipv4acd_address_remove(Link *link, Address *address, bool on_conflict) {
        int r;

        assert(link);
        assert(address);

        if (!address_exists(address))
                return 0; /* Not assigned. */

        if (on_conflict)
                log_link_warning(link, "Dropping address "IPV4_ADDRESS_FMT_STR", as an address conflict was detected.",
                                 IPV4_ADDRESS_FMT_VAL(address->in_addr.in));
        else
                log_link_debug(link, "Removing address "IPV4_ADDRESS_FMT_STR", as the ACD client is stopped.",
                               IPV4_ADDRESS_FMT_VAL(address->in_addr.in));

        r = address_remove(address);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to remove address "IPV4_ADDRESS_FMT_STR": %m",
                                              IPV4_ADDRESS_FMT_VAL(address->in_addr.in));

        return 0;
}

static int dhcp4_address_on_conflict(Link *link, Address *address) {
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
        Address *address = ASSERT_PTR(userdata);
        Link *link;
        int r;

        assert(acd);
        assert(address->acd == acd);
        assert(address->link);
        assert(address->family == AF_INET);
        assert(IN_SET(address->source, NETWORK_CONFIG_SOURCE_STATIC, NETWORK_CONFIG_SOURCE_DHCP4));

        link = address->link;

        switch (event) {
        case SD_IPV4ACD_EVENT_STOP:
                address->acd_bound = false;

                if (address->source == NETWORK_CONFIG_SOURCE_STATIC) {
                        r = static_ipv4acd_address_remove(link, address, /* on_conflict = */ false);
                        if (r < 0)
                                link_enter_failed(link);
                }

                /* We have nothing to do for DHCPv4 lease here, as the dhcp client is already stopped
                 * when stopping the ipv4acd client. See link_stop_engines(). */
                break;

        case SD_IPV4ACD_EVENT_BIND:
                address->acd_bound = true;

                log_link_debug(link, "Successfully claimed address "IPV4_ADDRESS_FMT_STR,
                               IPV4_ADDRESS_FMT_VAL(address->in_addr.in));
                break;

        case SD_IPV4ACD_EVENT_CONFLICT:
                address->acd_bound = false;

                log_link_warning(link, "Dropping address "IPV4_ADDRESS_FMT_STR", as an address conflict was detected.",
                                 IPV4_ADDRESS_FMT_VAL(address->in_addr.in));

                if (address->source == NETWORK_CONFIG_SOURCE_STATIC)
                        r = static_ipv4acd_address_remove(link, address, /* on_conflict = */ true);
                else
                        r = dhcp4_address_on_conflict(link, address);
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

static int address_ipv4acd_start(Address *address) {
        assert(address);
        assert(address->link);

        if (!address->acd)
                return 0;

        if (sd_ipv4acd_is_running(address->acd))
                return 0;

        if (!link_has_carrier(address->link))
                return 0;

        return sd_ipv4acd_start(address->acd, true);
}

int ipv4acd_configure(Address *address) {
        Link *link;
        int r;

        assert(address);

        link = ASSERT_PTR(address->link);

        if (!address_ipv4acd_enabled(address)) {
                address->acd = sd_ipv4acd_unref(address->acd);
                address->acd_bound = false;
                return 0;
        }

        if (address->acd)
                return address_ipv4acd_start(address);

        log_link_debug(link, "Configuring IPv4ACD for address "IPV4_ADDRESS_FMT_STR,
                       IPV4_ADDRESS_FMT_VAL(address->in_addr.in));

        r = sd_ipv4acd_new(&address->acd);
        if (r < 0)
                return r;

        r = sd_ipv4acd_attach_event(address->acd, link->manager->event, 0);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_ifindex(address->acd, link->ifindex);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_mac(address->acd, &link->hw_addr.ether);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_address(address->acd, &address->in_addr.in);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_callback(address->acd, on_acd, address);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_check_mac_callback(address->acd, ipv4acd_check_mac, link->manager);
        if (r < 0)
                return r;

        return address_ipv4acd_start(address);
}

int ipv4acd_update_mac(Link *link) {
        Address *address;
        int k, r = 0;

        assert(link);

        if (link->hw_addr.length != ETH_ALEN)
                return 0;
        if (ether_addr_is_null(&link->hw_addr.ether))
                return 0;

        SET_FOREACH(address, link->addresses) {
                if (!address->acd)
                        continue;

                k = sd_ipv4acd_set_mac(address->acd, &link->hw_addr.ether);
                if (k < 0)
                        r = k;
        }
        if (r < 0)
                link_enter_failed(link);

        return r;
}

int ipv4acd_start(Link *link) {
        Address *address;
        int r;

        assert(link);

        SET_FOREACH(address, link->addresses) {
                r = address_ipv4acd_start(address);
                if (r < 0)
                        return r;
        }

        return 0;
}

int ipv4acd_stop(Link *link) {
        Address *address;
        int k, r = 0;

        assert(link);

        SET_FOREACH(address, link->addresses) {
                if (!address->acd)
                        continue;

                k = sd_ipv4acd_stop(address->acd);
                if (k < 0)
                        r = k;
        }

        return r;
}

int ipv4acd_set_ifname(Link *link) {
        Address *address;
        int r;

        assert(link);

        SET_FOREACH(address, link->addresses) {
                if (!address->acd)
                        continue;

                r = sd_ipv4acd_set_ifname(address->acd, link->ifname);
                if (r < 0)
                        return r;
        }

        return 0;
}
