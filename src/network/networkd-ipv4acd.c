/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-dhcp-client.h"
#include "sd-ipv4acd.h"

#include "networkd-address.h"
#include "networkd-dhcp4.h"
#include "networkd-ipv4acd.h"
#include "networkd-link.h"
#include "networkd-manager.h"

static void on_acd(sd_ipv4acd *acd, int event, void *userdata, bool is_static) {
        Address *address = userdata;
        Link *link;
        int r;

        assert(acd);
        assert(address);
        assert(address->acd == acd);
        assert(address->link);
        assert(address->family == AF_INET);

        link = address->link;

        switch (event) {
        case SD_IPV4ACD_EVENT_STOP:
                log_link_debug(link, "Stopping ACD client...");

                if (address_get(link, address, NULL) < 0)
                        return;

                r = address_remove(address, link);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Failed to remove address "IPV4_ADDRESS_FMT_STR": %m",
                                               IPV4_ADDRESS_FMT_VAL(address->in_addr.in));
                        link_enter_failed(link);
                }
                break;

        case SD_IPV4ACD_EVENT_BIND: {
                log_link_debug(link, "Successfully claimed address "IPV4_ADDRESS_FMT_STR,
                               IPV4_ADDRESS_FMT_VAL(address->in_addr.in));

                r = set_ensure_put(&link->addresses, &address_hash_ops, address);
                if (r <= 0) {
                        log_link_warning_errno(link, r == 0 ? -EEXIST : r, "Failed to store address "IPV4_ADDRESS_FMT_STR": %m",
                                               IPV4_ADDRESS_FMT_VAL(address->in_addr.in));
                        link_enter_failed(link);
                        return;
                }

                /* Consider address tentative until we get the real flags from the kernel */
                address->flags |= IFA_F_TENTATIVE;

                if (is_static)
                        r = link_request_static_address(link, address, false);
                else
                        r = link_request_dhcp4_address(link, address, false);
                if (r < 0) {
                        link_enter_failed(link);
                        return;
                }

                break;
        }
        case SD_IPV4ACD_EVENT_CONFLICT:
                if (!is_static) {
                        assert(link->dhcp_client);

                        r = sd_dhcp_client_send_decline(link->dhcp_client);
                        if (r < 0)
                                log_link_warning_errno(link, r, "Failed to send DHCP DECLINE, ignoring: %m");

                        if (link->dhcp_lease) {
                                log_link_warning(link, "ACD conflict. Dropping DHCPv4 lease.");
                                r = dhcp4_lease_lost(link);
                                if (r < 0) {
                                        link_enter_failed(link);
                                        return;
                                }
                        }
                }

                if (address_get(link, address, NULL) < 0) {
                        log_link_warning(link, "ACD conflict. Give up to configure address "IPV4_ADDRESS_FMT_STR,
                                         IPV4_ADDRESS_FMT_VAL(address->in_addr.in));

                        address_free(address);
                        return;
                }

                log_link_warning(link, "ACD conflict. Dropping address "IPV4_ADDRESS_FMT_STR,
                                 IPV4_ADDRESS_FMT_VAL(address->in_addr.in));

                r = address_remove(address, link);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Failed to drop ACD conflicted address "IPV4_ADDRESS_FMT_STR": %m",
                                               IPV4_ADDRESS_FMT_VAL(address->in_addr.in));
                        link_enter_failed(link);
                }
                break;

        default:
                assert_not_reached("Invalid IPv4ACD event.");
        }
}

static void static_address_on_acd(sd_ipv4acd *acd, int event, void *userdata) {
        on_acd(acd, event, userdata, true);
}

static void dhcp4_address_on_acd(sd_ipv4acd *acd, int event, void *userdata) {
        on_acd(acd, event, userdata, false);
}

int ipv4acd_configure(Link *link, Address *address, bool is_static) {
        _cleanup_(address_freep) Address *a = NULL;
        Link *l;
        int r;

        assert(link);
        assert(address);
        assert(address->family == AF_INET);
        assert(address->duplicate_address_detection & ADDRESS_FAMILY_IPV4);

        r = address_acquire(link, address, &a);
        if (r < 0)
                return r;

        if (!a) {
                r = address_dup(address, &a);
                if (r < 0)
                        return r;
        }

        r = set_ensure_put(&link->addresses_ipv4acd, &address_hash_ops, a);
        if (r < 0)
                return r;
        a->link = link;

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

        HASHMAP_FOREACH(l, link->manager->links) {
                if (l == link)
                        continue;
                if (l->hw_addr.length != ETH_ALEN)
                        continue;
                if (ether_addr_is_null(&l->hw_addr.ether))
                        continue;
                r = sd_ipv4acd_add_other_mac(address->acd, &l->hw_addr.ether);
                if (r < 0)
                        return r;
        }

        r = sd_ipv4acd_set_address(address->acd, &address->in_addr.in);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_callback(address->acd,
                                    is_static ? static_address_on_acd : dhcp4_address_on_acd,
                                    address);
        if (r < 0)
                return r;

        if (link_has_carrier(link)) {
                r = sd_ipv4acd_start(address->acd, true);
                if (r < 0)
                        return r;
        }

        return 0;
}

int ipv4acd_update_mac(Link *link, struct hw_addr_data *old) {
        Address *address;
        int k, r;
        Link *l;

        assert(link);

        if (link->hw_addr.length != ETH_ALEN)
                return 0;
        if (ether_addr_is_null(&link->hw_addr.ether))
                return 0;

        HASHMAP_FOREACH(l, link->manager->links) {
                if (l == link)
                        continue;

                r = 0;
                SET_FOREACH(address, l->addresses_ipv4acd) {
                        assert(address->acd);

                        k = sd_ipv4acd_remove_other_mac(address->acd, &old->ether);
                        if (k < 0)
                                r = k;
                        k = sd_ipv4acd_add_other_mac(address->acd, &link->hw_addr.ether);
                        if (k < 0)
                                r = k;
                }
                if (r < 0)
                        link_enter_failed(l);
        }

        r = 0;
        SET_FOREACH(address, link->addresses_ipv4acd) {
                assert(address->acd);

                k = sd_ipv4acd_set_mac(address->acd, &link->hw_addr.ether);
                if (k < 0)
                        r = k;
        }
        if (r < 0)
                link_enter_failed(link);

        return r;
}

void ipv4acd_drop_mac(Link *link) {
        Address *address;
        int k, r;
        Link *l;

        assert(link);

        if (link->hw_addr.length != ETH_ALEN)
                return;
        if (ether_addr_is_null(&link->hw_addr.ether))
                return;

        HASHMAP_FOREACH(l, link->manager->links) {
                if (l == link)
                        continue;

                r = 0;
                SET_FOREACH(address, l->addresses_ipv4acd) {
                        assert(address->acd);

                        k = sd_ipv4acd_remove_other_mac(address->acd, &link->hw_addr.ether);
                        if (k < 0)
                                r = k;
                }
                if (r < 0)
                        link_enter_failed(l);
        }
}

int ipv4acd_start(Link *link) {
        Address *address;
        int r;

        assert(link);

        SET_FOREACH(address, link->addresses_ipv4acd) {
                r = sd_ipv4acd_start(address->acd, true);
                if (r < 0)
                        return r;
        }

        return 0;
}

int ipv4acd_stop(Link *link) {
        Address *address;
        int k, r = 0;

        assert(link);

        SET_FOREACH(address, link->addresses_ipv4acd) {
                k = sd_ipv4acd_stop(address->acd);
                if (k < 0)
                        r = k;
        }

        return r;
}
