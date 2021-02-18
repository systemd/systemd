/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <net/if_arp.h>

#include "alloc-util.h"
#include "firewall-util.h"
#include "memory-util.h"
#include "netlink-util.h"
#include "networkd-address-pool.h"
#include "networkd-address.h"
#include "networkd-ipv6-proxy-ndp.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"

#define ADDRESSES_PER_LINK_MAX 2048U
#define STATIC_ADDRESSES_PER_NETWORK_MAX 1024U

int generate_ipv6_eui_64_address(const Link *link, struct in6_addr *ret) {
        assert(link);
        assert(ret);

        if (link->iftype == ARPHRD_INFINIBAND) {
                /* see RFC4391 section 8 */
                memcpy(&ret->s6_addr[8], &link->hw_addr.addr.infiniband[12], 8);
                ret->s6_addr[8] ^= 1 << 1;

                return 0;
        }

        /* see RFC4291 section 2.5.1 */
        ret->s6_addr[8]  = link->hw_addr.addr.ether.ether_addr_octet[0];
        ret->s6_addr[8] ^= 1 << 1;
        ret->s6_addr[9]  = link->hw_addr.addr.ether.ether_addr_octet[1];
        ret->s6_addr[10] = link->hw_addr.addr.ether.ether_addr_octet[2];
        ret->s6_addr[11] = 0xff;
        ret->s6_addr[12] = 0xfe;
        ret->s6_addr[13] = link->hw_addr.addr.ether.ether_addr_octet[3];
        ret->s6_addr[14] = link->hw_addr.addr.ether.ether_addr_octet[4];
        ret->s6_addr[15] = link->hw_addr.addr.ether.ether_addr_octet[5];

        return 0;
}

int address_new(Address **ret) {
        _cleanup_(address_freep) Address *address = NULL;

        address = new(Address, 1);
        if (!address)
                return -ENOMEM;

        *address = (Address) {
                .family = AF_UNSPEC,
                .scope = RT_SCOPE_UNIVERSE,
                .cinfo.ifa_prefered = CACHE_INFO_INFINITY_LIFE_TIME,
                .cinfo.ifa_valid = CACHE_INFO_INFINITY_LIFE_TIME,
                .set_broadcast = -1,
                .duplicate_address_detection = ADDRESS_FAMILY_IPV6,
        };

        *ret = TAKE_PTR(address);

        return 0;
}

static int address_new_static(Network *network, const char *filename, unsigned section_line, Address **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(address_freep) Address *address = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        address = ordered_hashmap_get(network->addresses_by_section, n);
        if (address) {
                *ret = TAKE_PTR(address);
                return 0;
        }

        if (ordered_hashmap_size(network->addresses_by_section) >= STATIC_ADDRESSES_PER_NETWORK_MAX)
                return -E2BIG;

        r = address_new(&address);
        if (r < 0)
                return r;

        address->network = network;
        address->section = TAKE_PTR(n);

        r = ordered_hashmap_ensure_put(&network->addresses_by_section, &network_config_hash_ops, address->section, address);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(address);
        return 0;
}

Address *address_free(Address *address) {
        if (!address)
                return NULL;

        if (address->network) {
                assert(address->section);
                ordered_hashmap_remove(address->network->addresses_by_section, address->section);
        }

        if (address->link) {
                NDiscAddress *n;

                set_remove(address->link->addresses, address);
                set_remove(address->link->addresses_foreign, address);
                set_remove(address->link->static_addresses, address);
                if (address->link->dhcp_address == address)
                        address->link->dhcp_address = NULL;
                if (address->link->dhcp_address_old == address)
                        address->link->dhcp_address_old = NULL;
                set_remove(address->link->dhcp6_addresses, address);
                set_remove(address->link->dhcp6_addresses_old, address);
                set_remove(address->link->dhcp6_pd_addresses, address);
                set_remove(address->link->dhcp6_pd_addresses_old, address);
                SET_FOREACH(n, address->link->ndisc_addresses)
                        if (n->address == address)
                                free(set_remove(address->link->ndisc_addresses, n));

                if (address->family == AF_INET6 &&
                    in6_addr_equal(&address->in_addr.in6, &address->link->ipv6ll_address))
                        memzero(&address->link->ipv6ll_address, sizeof(struct in6_addr));
        }

        sd_ipv4acd_unref(address->acd);

        network_config_section_free(address->section);
        free(address->label);
        return mfree(address);
}

static bool address_may_have_broadcast(const Address *a) {
        assert(a);

        /* A /31 or /32 IPv4 address does not have a broadcast address.
         * See https://tools.ietf.org/html/rfc3021 */

        return a->family == AF_INET &&
                in_addr_is_null(AF_INET, &a->in_addr_peer) &&
                a->prefixlen <= 30;
}

static bool address_may_set_broadcast(const Address *a, const Link *link) {
        assert(a);
        assert(link);

        if (!address_may_have_broadcast(a))
                return false;

        if (a->set_broadcast >= 0)
                return a->set_broadcast;

        /* Typical configuration for wireguard does not set broadcast. */
        return !streq_ptr(link->kind, "wireguard");
}

static uint32_t address_prefix(const Address *a) {
        assert(a);

        /* make sure we don't try to shift by 32.
         * See ISO/IEC 9899:TC3 § 6.5.7.3. */
        if (a->prefixlen == 0)
                return 0;

        if (a->in_addr_peer.in.s_addr != 0)
                return be32toh(a->in_addr_peer.in.s_addr) >> (32 - a->prefixlen);
        else
                return be32toh(a->in_addr.in.s_addr) >> (32 - a->prefixlen);
}

void address_hash_func(const Address *a, struct siphash *state) {
        assert(a);

        siphash24_compress(&a->family, sizeof(a->family), state);

        switch (a->family) {
        case AF_INET:
                siphash24_compress(&a->prefixlen, sizeof(a->prefixlen), state);

                uint32_t prefix = address_prefix(a);
                siphash24_compress(&prefix, sizeof(prefix), state);

                _fallthrough_;
        case AF_INET6:
                siphash24_compress(&a->in_addr, FAMILY_ADDRESS_SIZE(a->family), state);
                break;
        default:
                /* treat any other address family as AF_UNSPEC */
                break;
        }
}

int address_compare_func(const Address *a1, const Address *a2) {
        int r;

        r = CMP(a1->family, a2->family);
        if (r != 0)
                return r;

        switch (a1->family) {
        case AF_INET:
                /* See kernel's find_matching_ifa() in net/ipv4/devinet.c */
                r = CMP(a1->prefixlen, a2->prefixlen);
                if (r != 0)
                        return r;

                r = CMP(address_prefix(a1), address_prefix(a2));
                if (r != 0)
                        return r;

                _fallthrough_;
        case AF_INET6:
                /* See kernel's ipv6_get_ifaddr() in net/ipv6/addrconf.c */
                return memcmp(&a1->in_addr, &a2->in_addr, FAMILY_ADDRESS_SIZE(a1->family));
        default:
                /* treat any other address family as AF_UNSPEC */
                return 0;
        }
}

DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(address_hash_ops, Address, address_hash_func, address_compare_func, address_free);

bool address_equal(const Address *a1, const Address *a2) {
        if (a1 == a2)
                return true;

        if (!a1 || !a2)
                return false;

        return address_compare_func(a1, a2) == 0;
}

static int address_copy(Address *dest, const Address *src) {
        int r;

        assert(dest);
        assert(src);

        if (src->family == AF_INET) {
                r = free_and_strdup(&dest->label, src->label);
                if (r < 0)
                        return r;
        }

        dest->family = src->family;
        dest->prefixlen = src->prefixlen;
        dest->scope = src->scope;
        dest->flags = src->flags;
        dest->cinfo = src->cinfo;
        dest->in_addr = src->in_addr;
        dest->in_addr_peer = src->in_addr_peer;
        if (address_may_have_broadcast(src))
                dest->broadcast = src->broadcast;
        dest->duplicate_address_detection = src->duplicate_address_detection;

        return 0;
}

static int address_set_masquerade(Address *address, bool add) {
        union in_addr_union masked;
        int r;

        assert(address);
        assert(address->link);

        if (!address->link->network)
                return 0;

        if (address->family == AF_INET &&
            !FLAGS_SET(address->link->network->ip_masquerade, ADDRESS_FAMILY_IPV4))
                return 0;

        if (address->family == AF_INET6 &&
            !FLAGS_SET(address->link->network->ip_masquerade, ADDRESS_FAMILY_IPV6))
                return 0;

        if (address->scope >= RT_SCOPE_LINK)
                return 0;

        if (address->ip_masquerade_done == add)
                return 0;

        masked = address->in_addr;
        r = in_addr_mask(address->family, &masked, address->prefixlen);
        if (r < 0)
                return r;

        r = fw_add_masquerade(&address->link->manager->fw_ctx, add, address->family, &masked, address->prefixlen);
        if (r < 0)
                return r;

        address->ip_masquerade_done = add;

        return 0;
}

static int address_add_internal(Link *link, Set **addresses, const Address *in, Address **ret) {
        _cleanup_(address_freep) Address *address = NULL;
        int r;

        assert(link);
        assert(addresses);
        assert(in);

        r = address_new(&address);
        if (r < 0)
                return r;

        r = address_copy(address, in);
        if (r < 0)
                return r;

        /* Consider address tentative until we get the real flags from the kernel */
        address->flags = IFA_F_TENTATIVE;

        r = set_ensure_put(addresses, &address_hash_ops, address);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        address->link = link;

        if (ret)
                *ret = address;
        TAKE_PTR(address);
        return 0;
}

static int address_add_foreign(Link *link, const Address *in, Address **ret) {
        return address_add_internal(link, &link->addresses_foreign, in, ret);
}

static int address_add(Link *link, const Address *in, Address **ret) {
        bool is_new = false;
        Address *address;
        int r;

        assert(link);
        assert(in);

        r = address_get(link, in, &address);
        if (r == -ENOENT) {
                /* Address does not exist, create a new one */
                r = address_add_internal(link, &link->addresses, in, &address);
                if (r < 0)
                        return r;
                is_new = true;
        } else if (r == 0) {
                /* Take over a foreign address */
                r = set_ensure_put(&link->addresses, &address_hash_ops, address);
                if (r < 0)
                        return r;

                set_remove(link->addresses_foreign, address);
        } else if (r == 1) {
                /* Already exists, do nothing */
                ;
        } else
                return r;

        if (ret)
                *ret = address;
        return is_new;
}

static int address_update(Address *address, const Address *src) {
        bool ready;
        int r;

        assert(address);
        assert(address->link);
        assert(src);

        ready = address_is_ready(address);

        address->flags = src->flags;
        address->scope = src->scope;
        address->cinfo = src->cinfo;

        if (IN_SET(address->link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        link_update_operstate(address->link, true);
        link_check_ready(address->link);

        if (!ready && address_is_ready(address)) {
                if (address->callback) {
                        r = address->callback(address);
                        if (r < 0)
                                return r;
                }

                if (address->family == AF_INET6 &&
                    in_addr_is_link_local(AF_INET6, &address->in_addr) > 0 &&
                    in6_addr_is_null(&address->link->ipv6ll_address)) {

                        r = link_ipv6ll_gained(address->link, &address->in_addr.in6);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int address_drop(Address *address) {
        Link *link;
        bool ready;
        int r;

        if (!address)
                return 0;

        ready = address_is_ready(address);
        link = address->link;

        r = address_set_masquerade(address, false);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to disable IP masquerading, ignoring: %m");

        address_free(address);

        link_update_operstate(link, true);

        if (link && !ready)
                link_check_ready(link);

        return 0;
}

int address_get(Link *link, const Address *in, Address **ret) {
        Address *existing;

        assert(link);
        assert(in);

        existing = set_get(link->addresses, in);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 1;
        }

        existing = set_get(link->addresses_foreign, in);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 0;
        }

        return -ENOENT;
}

int link_has_ipv6_address(Link *link, const struct in6_addr *address) {
        _cleanup_(address_freep) Address *a = NULL;
        int r;

        assert(link);
        assert(address);

        r = address_new(&a);
        if (r < 0)
                return r;

        /* address_compare_func() only compares the local address for IPv6 case. So, it is enough to
         * set only family and the address. */
        a->family = AF_INET6;
        a->in_addr.in6 = *address;

        return address_get(link, a, NULL) >= 0;
}

static void log_address_debug(const Address *address, const char *str, const Link *link) {
        assert(address);
        assert(str);
        assert(link);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *addr = NULL, *peer = NULL;
                char valid_buf[FORMAT_TIMESPAN_MAX], preferred_buf[FORMAT_TIMESPAN_MAX];
                const char *valid_str = NULL, *preferred_str = NULL;
                bool has_peer;

                (void) in_addr_to_string(address->family, &address->in_addr, &addr);
                has_peer = in_addr_is_set(address->family, &address->in_addr_peer);
                if (has_peer)
                        (void) in_addr_to_string(address->family, &address->in_addr_peer, &peer);

                if (address->cinfo.ifa_valid != CACHE_INFO_INFINITY_LIFE_TIME)
                        valid_str = format_timespan(valid_buf, FORMAT_TIMESPAN_MAX,
                                                    address->cinfo.ifa_valid * USEC_PER_SEC,
                                                    USEC_PER_SEC);

                if (address->cinfo.ifa_prefered != CACHE_INFO_INFINITY_LIFE_TIME)
                        preferred_str = format_timespan(preferred_buf, FORMAT_TIMESPAN_MAX,
                                                        address->cinfo.ifa_prefered * USEC_PER_SEC,
                                                        USEC_PER_SEC);

                log_link_debug(link, "%s address: %s%s%s/%u (valid %s%s, preferred %s%s)",
                               str, strnull(addr), has_peer ? " peer " : "",
                               has_peer ? strnull(peer) : "", address->prefixlen,
                               valid_str ? "for " : "forever", strempty(valid_str),
                               preferred_str ? "for " : "forever", strempty(preferred_str));
        }
}

static int address_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EADDRNOTAVAIL)
                log_link_message_warning_errno(link, m, r, "Could not drop address");
        else if (r >= 0)
                (void) manager_rtnl_process_address(rtnl, m, link->manager);

        return 1;
}

static int address_set_netlink_message(const Address *address, sd_netlink_message *req, Link *link) {
        int r;

        assert(address);
        assert(req);
        assert(link);

        r = sd_rtnl_message_addr_set_prefixlen(req, address->prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set prefixlen: %m");

        /* On remove, only IFA_F_MANAGETEMPADDR flag for IPv6 addresses are used. But anyway, set all
         * flags here unconditionally. Without setting the flag, the template addresses generated by
         * kernel will not be removed automatically when the main address is removed. */
        r = sd_rtnl_message_addr_set_flags(req, address->flags & 0xff);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set flags: %m");

        if ((address->flags & ~0xff) != 0) {
                r = sd_netlink_message_append_u32(req, IFA_FLAGS, address->flags);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set extended flags: %m");
        }

        r = netlink_message_append_in_addr_union(req, IFA_LOCAL, address->family, &address->in_addr);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFA_LOCAL attribute: %m");

        return 0;
}

int address_remove(
                const Address *address,
                Link *link,
                link_netlink_message_handler_t callback) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(address);
        assert(IN_SET(address->family, AF_INET, AF_INET6));
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);

        log_address_debug(address, "Removing", link);

        r = sd_rtnl_message_new_addr(link->manager->rtnl, &req, RTM_DELADDR,
                                     link->ifindex, address->family);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_DELADDR message: %m");

        r = address_set_netlink_message(address, req, link);
        if (r < 0)
                return r;

        r = netlink_call_async(link->manager->rtnl, NULL, req,
                               callback ?: address_remove_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static bool link_is_static_address_configured(const Link *link, const Address *address) {
        Address *net_address;

        assert(link);
        assert(address);

        if (!link->network)
                return false;

        ORDERED_HASHMAP_FOREACH(net_address, link->network->addresses_by_section)
                if (address_equal(net_address, address))
                        return true;

        return false;
}

bool link_address_is_dynamic(const Link *link, const Address *address) {
        Route *route;

        assert(link);
        assert(address);

        if (address->cinfo.ifa_prefered != CACHE_INFO_INFINITY_LIFE_TIME)
                return true;

        /* Even when the address is leased from a DHCP server, networkd assign the address
         * without lifetime when KeepConfiguration=dhcp. So, let's check that we have
         * corresponding routes with RTPROT_DHCP. */
        SET_FOREACH(route, link->routes_foreign) {
                if (route->protocol != RTPROT_DHCP)
                        continue;

                if (address->family != route->family)
                        continue;

                if (in_addr_equal(address->family, &address->in_addr, &route->prefsrc))
                        return true;
        }

        return false;
}

static int link_enumerate_ipv6_tentative_addresses(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        r = sd_rtnl_message_new_addr(link->manager->rtnl, &req, RTM_GETADDR, 0, AF_INET6);
        if (r < 0)
                return r;

        r = sd_netlink_call(link->manager->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *addr = reply; addr; addr = sd_netlink_message_next(addr)) {
                unsigned char flags;
                int ifindex;

                r = sd_rtnl_message_addr_get_ifindex(addr, &ifindex);
                if (r < 0) {
                        log_link_warning_errno(link, r, "rtnl: invalid ifindex, ignoring: %m");
                        continue;
                } else if (link->ifindex != ifindex)
                        continue;

                r = sd_rtnl_message_addr_get_flags(addr, &flags);
                if (r < 0) {
                        log_link_warning_errno(link, r, "rtnl: received address message with invalid flags, ignoring: %m");
                        continue;
                } else if (!(flags & IFA_F_TENTATIVE))
                        continue;

                log_link_debug(link, "Found tentative ipv6 link-local address");
                (void) manager_rtnl_process_address(link->manager->rtnl, addr, link->manager);
        }

        return 0;
}

int link_drop_foreign_addresses(Link *link) {
        Address *address;
        int k, r = 0;

        assert(link);

        /* The kernel doesn't notify us about tentative addresses;
         * so if ipv6ll is disabled, we need to enumerate them now so we can drop them below */
        if (!link_ipv6ll_enabled(link)) {
                r = link_enumerate_ipv6_tentative_addresses(link);
                if (r < 0)
                        return r;
        }

        SET_FOREACH(address, link->addresses_foreign) {
                /* we consider IPv6LL addresses to be managed by the kernel */
                if (address->family == AF_INET6 && in_addr_is_link_local(AF_INET6, &address->in_addr) == 1 && link_ipv6ll_enabled(link))
                        continue;

                if (link_address_is_dynamic(link, address)) {
                        if (link->network && FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP))
                                continue;
                } else if (link->network && FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_STATIC))
                        continue;

                if (link_is_static_address_configured(link, address)) {
                        k = address_add(link, address, NULL);
                        if (k < 0) {
                                log_link_error_errno(link, k, "Failed to add address: %m");
                                if (r >= 0)
                                        r = k;
                        }
                } else {
                        k = address_remove(address, link, NULL);
                        if (k < 0 && r >= 0)
                                r = k;
                }
        }

        return r;
}

static int remove_static_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);
        assert(link->address_remove_messages > 0);

        link->address_remove_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EADDRNOTAVAIL)
                log_link_message_warning_errno(link, m, r, "Could not drop address");
        else if (r >= 0)
                (void) manager_rtnl_process_address(rtnl, m, link->manager);

        if (link->address_remove_messages == 0 && link->request_static_addresses) {
                link_set_state(link, LINK_STATE_CONFIGURING);
                r = link_set_addresses(link);
                if (r < 0)
                        link_enter_failed(link);
        }

        return 1;
}

int link_drop_addresses(Link *link) {
        Address *address, *pool_address;
        int k, r = 0;

        assert(link);

        SET_FOREACH(address, link->addresses) {
                /* we consider IPv6LL addresses to be managed by the kernel */
                if (address->family == AF_INET6 && in_addr_is_link_local(AF_INET6, &address->in_addr) == 1 && link_ipv6ll_enabled(link))
                        continue;

                k = address_remove(address, link, remove_static_address_handler);
                if (k < 0 && r >= 0) {
                        r = k;
                        continue;
                }

                link->address_remove_messages++;

                SET_FOREACH(pool_address, link->pool_addresses)
                        if (address_equal(address, pool_address))
                                address_free(set_remove(link->pool_addresses, pool_address));
        }

        return r;
}

static int address_acquire(Link *link, const Address *original, Address **ret) {
        union in_addr_union in_addr = IN_ADDR_NULL;
        struct in_addr broadcast = {};
        _cleanup_(address_freep) Address *na = NULL;
        int r;

        assert(link);
        assert(original);
        assert(ret);

        /* Something useful was configured? just use it */
        if (in_addr_is_set(original->family, &original->in_addr)) {
                *ret = NULL;
                return 0;
        }

        /* The address is configured to be 0.0.0.0 or [::] by the user?
         * Then let's acquire something more useful from the pool. */
        r = address_pool_acquire(link->manager, original->family, original->prefixlen, &in_addr);
        if (r < 0)
                return r;
        if (r == 0)
                return -EBUSY;

        if (original->family == AF_INET) {
                /* Pick first address in range for ourselves ... */
                in_addr.in.s_addr = in_addr.in.s_addr | htobe32(1);

                /* .. and use last as broadcast address */
                if (original->prefixlen > 30)
                        broadcast.s_addr = 0;
                else
                        broadcast.s_addr = in_addr.in.s_addr | htobe32(0xFFFFFFFFUL >> original->prefixlen);
        } else if (original->family == AF_INET6)
                in_addr.in6.s6_addr[15] |= 1;

        r = address_new(&na);
        if (r < 0)
                return r;

        r = address_copy(na, original);
        if (r < 0)
                return r;

        na->broadcast = broadcast;
        na->in_addr = in_addr;

        r = set_ensure_put(&link->pool_addresses, &address_hash_ops, na);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        *ret = TAKE_PTR(na);
        return 1;
}

static int ipv4_dad_configure(Address *address);

int address_configure(
                const Address *address,
                Link *link,
                link_netlink_message_handler_t callback,
                Address **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        Address *acquired_address, *a;
        bool update;
        int r, k;

        assert(address);
        assert(IN_SET(address->family, AF_INET, AF_INET6));
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(callback);

        /* If this is a new address, then refuse adding more than the limit */
        if (address_get(link, address, NULL) <= 0 &&
            set_size(link->addresses) >= ADDRESSES_PER_LINK_MAX)
                return log_link_error_errno(link, SYNTHETIC_ERRNO(E2BIG),
                                            "Too many addresses are configured, refusing: %m");

        r = address_acquire(link, address, &acquired_address);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to acquire an address from pool: %m");
        if (acquired_address)
                address = acquired_address;

        update = address_get(link, address, NULL) >= 0;

        log_address_debug(address, update ? "Updating" : "Configuring", link);

        if (update)
                r = sd_rtnl_message_new_addr_update(link->manager->rtnl, &req,
                                                    link->ifindex, address->family);
        else
                r = sd_rtnl_message_new_addr(link->manager->rtnl, &req, RTM_NEWADDR,
                                             link->ifindex, address->family);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_NEWADDR message: %m");

        r = address_set_netlink_message(address, req, link);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_scope(req, address->scope);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set scope: %m");

        if (in_addr_is_set(address->family, &address->in_addr_peer)) {
                r = netlink_message_append_in_addr_union(req, IFA_ADDRESS, address->family, &address->in_addr_peer);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFA_ADDRESS attribute: %m");
        } else if (address_may_set_broadcast(address, link)) {
                r = sd_netlink_message_append_in_addr(req, IFA_BROADCAST, &address->broadcast);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFA_BROADCAST attribute: %m");
        }

        if (address->family == AF_INET && address->label) {
                r = sd_netlink_message_append_string(req, IFA_LABEL, address->label);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFA_LABEL attribute: %m");
        }

        r = sd_netlink_message_append_cache_info(req, IFA_CACHEINFO, &address->cinfo);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFA_CACHEINFO attribute: %m");

        k = address_add(link, address, &a);
        if (k < 0)
                return log_link_error_errno(link, k, "Could not add address: %m");

        r = address_set_masquerade(a, true);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not enable IP masquerading, ignoring: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback, link_netlink_destroy_callback, link);
        if (r < 0) {
                (void) address_set_masquerade(a, false);
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");
        }

        link_ref(link);

        if (FLAGS_SET(address->duplicate_address_detection, ADDRESS_FAMILY_IPV4)) {
                r = ipv4_dad_configure(a);
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to start IPv4ACD client, ignoring: %m");
        }

        if (ret)
                *ret = a;

        return k;
}

static int static_address_ready_callback(Address *address) {
        Address *a;
        Link *link;
        int r;

        assert(address);
        assert(address->link);

        link = address->link;

        if (!link->addresses_configured)
                return 0;

        SET_FOREACH(a, link->static_addresses)
                if (!address_is_ready(a)) {
                        _cleanup_free_ char *str = NULL;

                        (void) in_addr_prefix_to_string(a->family, &a->in_addr, a->prefixlen, &str);
                        log_link_debug(link, "an address %s is not ready", strnull(str));
                        return 0;
                }

        /* This should not be called again */
        SET_FOREACH(a, link->static_addresses)
                a->callback = NULL;

        link->addresses_ready = true;

        r = link_set_ipv6_proxy_ndp_addresses(link);
        if (r < 0)
                return r;

        return link_set_routes(link);
}

static int address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(rtnl);
        assert(m);
        assert(link);
        assert(link->ifname);
        assert(link->address_messages > 0);

        link->address_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not set address");
                link_enter_failed(link);
                return 1;
        } else if (r >= 0)
                (void) manager_rtnl_process_address(rtnl, m, link->manager);

        if (link->address_messages == 0) {
                Address *a;

                log_link_debug(link, "Addresses set");
                link->addresses_configured = true;

                /* When all static addresses are already ready, then static_address_ready_callback()
                 * will not be called automatically. So, call it here. */
                a = set_first(link->static_addresses);
                if (!a) {
                        log_link_debug(link, "No static address is stored. Already removed?");
                        return 1;
                }

                r = static_address_ready_callback(a);
                if (r < 0)
                        link_enter_failed(link);
        }

        return 1;
}

static int static_address_configure(const Address *address, Link *link) {
        Address *ret;
        int r;

        assert(address);
        assert(link);

        r = address_configure(address, link, address_handler, &ret);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not configure static address: %m");

        link->address_messages++;

        r = set_ensure_put(&link->static_addresses, &address_hash_ops, ret);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to store static address: %m");

        ret->callback = static_address_ready_callback;

        return 0;
}

int link_set_addresses(Link *link) {
        Address *ad;
        Prefix *p;
        int r;

        assert(link);
        assert(link->network);

        if (link->address_remove_messages != 0) {
                log_link_debug(link, "Removing old addresses, new addresses will be configured later.");
                link->request_static_addresses = true;
                return 0;
        }

        if (link->address_messages != 0) {
                log_link_debug(link, "Static addresses are configuring.");
                return 0;
        }

        ORDERED_HASHMAP_FOREACH(ad, link->network->addresses_by_section) {
                r = static_address_configure(ad, link);
                if (r < 0)
                        return r;
        }

        HASHMAP_FOREACH(p, link->network->prefixes_by_section) {
                _cleanup_(address_freep) Address *address = NULL;

                if (!p->assign)
                        continue;

                r = address_new(&address);
                if (r < 0)
                        return log_oom();

                r = sd_radv_prefix_get_prefix(p->radv_prefix, &address->in_addr.in6, &address->prefixlen);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not get RA prefix: %m");

                r = generate_ipv6_eui_64_address(link, &address->in_addr.in6);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not generate EUI64 address: %m");

                address->family = AF_INET6;
                r = static_address_configure(address, link);
                if (r < 0)
                        return r;
        }

        if (link->address_messages == 0) {
                link->addresses_configured = true;
                link->addresses_ready = true;

                r = link_set_ipv6_proxy_ndp_addresses(link);
                if (r < 0)
                        return r;

                r = link_set_routes(link);
                if (r < 0)
                        return r;
        } else {
                log_link_debug(link, "Setting addresses");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

int manager_rtnl_process_address(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(address_freep) Address *tmp = NULL;
        Link *link = NULL;
        uint16_t type;
        unsigned char flags;
        Address *address = NULL;
        int ifindex, r;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_message_warning_errno(message, r, "rtnl: failed to receive address message, ignoring");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWADDR, RTM_DELADDR)) {
                log_warning("rtnl: received unexpected message type %u when processing address, ignoring.", type);
                return 0;
        }

        r = sd_rtnl_message_addr_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get ifindex from message, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received address message with invalid ifindex %d, ignoring.", ifindex);
                return 0;
        }

        r = link_get(m, ifindex, &link);
        if (r < 0 || !link) {
                /* when enumerating we might be out of sync, but we will get the address again, so just
                 * ignore it */
                if (!m->enumerating)
                        log_warning("rtnl: received address for link '%d' we don't know about, ignoring.", ifindex);
                return 0;
        }

        r = address_new(&tmp);
        if (r < 0)
                return log_oom();

        r = sd_rtnl_message_addr_get_family(message, &tmp->family);
        if (r < 0) {
                log_link_warning(link, "rtnl: received address message without family, ignoring.");
                return 0;
        } else if (!IN_SET(tmp->family, AF_INET, AF_INET6)) {
                log_link_debug(link, "rtnl: received address message with invalid family '%i', ignoring.", tmp->family);
                return 0;
        }

        r = sd_rtnl_message_addr_get_prefixlen(message, &tmp->prefixlen);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received address message without prefixlen, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_addr_get_scope(message, &tmp->scope);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received address message without scope, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_addr_get_flags(message, &flags);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received address message without flags, ignoring: %m");
                return 0;
        }
        tmp->flags = flags;

        switch (tmp->family) {
        case AF_INET:
                r = sd_netlink_message_read_in_addr(message, IFA_LOCAL, &tmp->in_addr.in);
                if (r < 0) {
                        log_link_warning_errno(link, r, "rtnl: received address message without valid address, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_in_addr(message, IFA_ADDRESS, &tmp->in_addr_peer.in);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: could not get peer address from address message, ignoring: %m");
                        return 0;
                } else if (r >= 0) {
                        if (in4_addr_equal(&tmp->in_addr.in, &tmp->in_addr_peer.in))
                                tmp->in_addr_peer = IN_ADDR_NULL;
                }

                r = sd_netlink_message_read_in_addr(message, IFA_BROADCAST, &tmp->broadcast);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: could not get broadcast from address message, ignoring: %m");
                        return 0;
                }

                r = sd_netlink_message_read_string_strdup(message, IFA_LABEL, &tmp->label);
                if (r < 0 && r != -ENODATA) {
                        log_link_warning_errno(link, r, "rtnl: could not get label from address message, ignoring: %m");
                        return 0;
                } else if (r >= 0 && streq_ptr(tmp->label, link->ifname))
                        tmp->label = mfree(tmp->label);

                break;

        case AF_INET6:
                r = sd_netlink_message_read_in6_addr(message, IFA_LOCAL, &tmp->in_addr.in6);
                if (r >= 0) {
                        /* Have peer address. */
                        r = sd_netlink_message_read_in6_addr(message, IFA_ADDRESS, &tmp->in_addr_peer.in6);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "rtnl: could not get peer address from address message, ignoring: %m");
                                return 0;
                        }
                } else if (r == -ENODATA) {
                        /* Does not have peer address. */
                        r = sd_netlink_message_read_in6_addr(message, IFA_ADDRESS, &tmp->in_addr.in6);
                        if (r < 0) {
                                log_link_warning_errno(link, r, "rtnl: received address message without valid address, ignoring: %m");
                                return 0;
                        }
                } else {
                        log_link_warning_errno(link, r, "rtnl: could not get local address from address message, ignoring: %m");
                        return 0;
                }

                break;

        default:
                assert_not_reached("Received unsupported address family");
        }

        r = sd_netlink_message_read_cache_info(message, IFA_CACHEINFO, &tmp->cinfo);
        if (r < 0 && r != -ENODATA) {
                log_link_warning_errno(link, r, "rtnl: cannot get IFA_CACHEINFO attribute, ignoring: %m");
                return 0;
        }

        (void) address_get(link, tmp, &address);

        switch (type) {
        case RTM_NEWADDR:
                log_address_debug(tmp, address ? "Remembering updated" : "Remembering foreign", link);
                if (!address) {
                        /* An address appeared that we did not request */
                        r = address_add_foreign(link, tmp, &address);
                        if (r < 0) {
                                _cleanup_free_ char *buf = NULL;

                                (void) in_addr_prefix_to_string(tmp->family, &tmp->in_addr, tmp->prefixlen, &buf);
                                log_link_warning_errno(link, r, "Failed to remember foreign address %s, ignoring: %m",
                                                       strnull(buf));
                                return 0;
                        }
                }

                /* address_update() logs internally, so we don't need to here. */
                r = address_update(address, tmp);
                if (r < 0)
                        link_enter_failed(link);

                break;

        case RTM_DELADDR:
                log_address_debug(tmp, address ? "Forgetting" : "Kernel removed unknown", link);
                (void) address_drop(address);

                break;

        default:
                assert_not_reached("Received invalid RTNL message type");
        }

        return 1;
}

static void static_address_on_acd(sd_ipv4acd *acd, int event, void *userdata) {
        _cleanup_free_ char *pretty = NULL;
        Address *address;
        Link *link;
        int r;

        assert(acd);
        assert(userdata);

        address = (Address *) userdata;
        link = address->link;

        (void) in_addr_to_string(address->family, &address->in_addr, &pretty);
        switch (event) {
        case SD_IPV4ACD_EVENT_STOP:
                log_link_debug(link, "Stopping ACD client...");
                return;

        case SD_IPV4ACD_EVENT_BIND:
                log_link_debug(link, "Successfully claimed address %s", strna(pretty));
                link_check_ready(link);
                break;

        case SD_IPV4ACD_EVENT_CONFLICT:
                log_link_warning(link, "DAD conflict. Dropping address %s", strna(pretty));
                r = address_remove(address, link, NULL);
                if (r < 0)
                        log_link_error_errno(link, r, "Failed to drop DAD conflicted address %s", strna(pretty));;

                link_check_ready(link);
                break;

        default:
                assert_not_reached("Invalid IPv4ACD event.");
        }

        (void) sd_ipv4acd_stop(acd);

        return;
}

static int ipv4_dad_configure(Address *address) {
        int r;

        assert(address);
        assert(address->link);

        if (address->family != AF_INET)
                return 0;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *pretty = NULL;

                (void) in_addr_to_string(address->family, &address->in_addr, &pretty);
                log_link_debug(address->link, "Starting IPv4ACD client. Probing address %s", strna(pretty));
        }

        if (!address->acd) {
                r = sd_ipv4acd_new(&address->acd);
                if (r < 0)
                        return r;

                r = sd_ipv4acd_attach_event(address->acd, address->link->manager->event, 0);
                if (r < 0)
                        return r;
        }

        r = sd_ipv4acd_set_ifindex(address->acd, address->link->ifindex);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_mac(address->acd, &address->link->hw_addr.addr.ether);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_address(address->acd, &address->in_addr.in);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_callback(address->acd, static_address_on_acd, address);
        if (r < 0)
                return r;

        return sd_ipv4acd_start(address->acd, true);
}

static int ipv4_dad_update_mac_one(Address *address) {
        bool running;
        int r;

        assert(address);

        if (!address->acd)
                return 0;

        running = sd_ipv4acd_is_running(address->acd);

        r = sd_ipv4acd_stop(address->acd);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_mac(address->acd, &address->link->hw_addr.addr.ether);
        if (r < 0)
                return r;

        if (running) {
                r = sd_ipv4acd_start(address->acd, true);
                if (r < 0)
                        return r;
        }

        return 0;
}

int ipv4_dad_update_mac(Link *link) {
        Address *address;
        int k, r = 0;

        assert(link);

        SET_FOREACH(address, link->addresses) {
                k = ipv4_dad_update_mac_one(address);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

int ipv4_dad_stop(Link *link) {
        Address *address;
        int k, r = 0;

        assert(link);

        SET_FOREACH(address, link->addresses) {
                k = sd_ipv4acd_stop(address->acd);
                if (k < 0 && r >= 0)
                        r = k;
        }

        return r;
}

void ipv4_dad_unref(Link *link) {
        Address *address;

        assert(link);

        SET_FOREACH(address, link->addresses)
                address->acd = sd_ipv4acd_unref(address->acd);
}

int config_parse_broadcast(
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

        Network *network = userdata;
        _cleanup_(address_free_or_set_invalidp) Address *n = NULL;
        union in_addr_union u;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = address_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate new address, ignoring assignment: %m");
                return 0;
        }

        if (isempty(rvalue)) {
                /* The broadcast address will be calculated based on Address=, and set if the link is
                 * not a wireguard interface. Here, we do not check or set n->family. */
                n->broadcast = (struct in_addr) {};
                n->set_broadcast = -1;
                TAKE_PTR(n);
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r >= 0) {
                /* The broadcast address will be calculated based on Address=. Here, we do not check or
                 * set n->family. */
                n->broadcast = (struct in_addr) {};
                n->set_broadcast = r;
                TAKE_PTR(n);
                return 0;
        }

        if (n->family == AF_INET6) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Broadcast is not valid for IPv6 addresses, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = in_addr_from_string(AF_INET, rvalue, &u);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Broadcast is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }
        if (in4_addr_is_null(&u.in)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Broadcast cannot be ANY address, ignoring assignment: %s", rvalue);
                return 0;
        }

        n->broadcast = u.in;
        n->set_broadcast = true;
        n->family = AF_INET;
        TAKE_PTR(n);

        return 0;
}

int config_parse_address(
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

        Network *network = userdata;
        _cleanup_(address_free_or_set_invalidp) Address *n = NULL;
        union in_addr_union buffer;
        unsigned char prefixlen;
        int r, f;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(section, "Network"))
                /* we are not in an Address section, so use line number instead. */
                r = address_new_static(network, filename, line, &n);
        else
                r = address_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate new address, ignoring assignment: %m");
                return 0;
        }

        /* Address=address/prefixlen */
        r = in_addr_prefix_from_string_auto_internal(rvalue, PREFIXLEN_REFUSE, &f, &buffer, &prefixlen);
        if (r == -ENOANO) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "An address '%s' is specified without prefix length. "
                           "The behavior of parsing addresses without prefix length will be changed in the future release. "
                           "Please specify prefix length explicitly.", rvalue);

                r = in_addr_prefix_from_string_auto_internal(rvalue, PREFIXLEN_LEGACY, &f, &buffer, &prefixlen);
        }
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid address '%s', ignoring assignment: %m", rvalue);
                return 0;
        }

        if (n->family != AF_UNSPEC && f != n->family) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Address is incompatible, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (in_addr_is_null(f, &buffer)) {
                /* Will use address from address pool. Note that for ipv6 case, prefix of the address
                 * pool is 8, but 40 bit is used by the global ID and 16 bit by the subnet ID. So,
                 * let's limit the prefix length to 64 or larger. See RFC4193. */
                if ((f == AF_INET && prefixlen < 8) ||
                    (f == AF_INET6 && prefixlen < 64)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Null address with invalid prefixlen='%u', ignoring assignment: %s",
                                   prefixlen, rvalue);
                        return 0;
                }
        }

        n->family = f;
        n->prefixlen = prefixlen;

        if (streq(lvalue, "Address"))
                n->in_addr = buffer;
        else
                n->in_addr_peer = buffer;

        TAKE_PTR(n);
        return 0;
}

int config_parse_label(
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

        _cleanup_(address_free_or_set_invalidp) Address *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = address_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate new address, ignoring assignment: %m");
                return 0;
        }

        if (!address_label_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Interface label is too long or invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = free_and_strdup(&n->label, rvalue);
        if (r < 0)
                return log_oom();

        TAKE_PTR(n);
        return 0;
}

int config_parse_lifetime(
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

        Network *network = userdata;
        _cleanup_(address_free_or_set_invalidp) Address *n = NULL;
        uint32_t k;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = address_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate new address, ignoring assignment: %m");
                return 0;
        }

        /* We accept only "forever", "infinity", empty, or "0". */
        if (STR_IN_SET(rvalue, "forever", "infinity", ""))
                k = CACHE_INFO_INFINITY_LIFE_TIME;
        else if (streq(rvalue, "0"))
                k = 0;
        else {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid PreferredLifetime= value, ignoring: %s", rvalue);
                return 0;
        }

        n->cinfo.ifa_prefered = k;
        TAKE_PTR(n);

        return 0;
}

int config_parse_address_flags(
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

        Network *network = userdata;
        _cleanup_(address_free_or_set_invalidp) Address *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = address_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate new address, ignoring assignment: %m");
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (streq(lvalue, "AddPrefixRoute"))
                r = !r;

        SET_FLAG(n->flags, ltype, r);

        TAKE_PTR(n);
        return 0;
}

int config_parse_address_scope(
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

        Network *network = userdata;
        _cleanup_(address_free_or_set_invalidp) Address *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = address_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate new address, ignoring assignment: %m");
                return 0;
        }

        if (streq(rvalue, "host"))
                n->scope = RT_SCOPE_HOST;
        else if (streq(rvalue, "link"))
                n->scope = RT_SCOPE_LINK;
        else if (streq(rvalue, "global"))
                n->scope = RT_SCOPE_UNIVERSE;
        else {
                r = safe_atou8(rvalue , &n->scope);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Could not parse address scope \"%s\", ignoring assignment: %m", rvalue);
                        return 0;
                }
        }

        n->scope_set = true;
        TAKE_PTR(n);
        return 0;
}

int config_parse_duplicate_address_detection(
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

        Network *network = userdata;
        _cleanup_(address_free_or_set_invalidp) Address *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = address_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate new address, ignoring assignment: %m");
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r >= 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "For historical reasons, %s=%s means %s=%s. "
                           "Please use 'both', 'ipv4', 'ipv6' or 'none' instead.",
                           lvalue, rvalue, lvalue, r ? "none" : "both");
                n->duplicate_address_detection = r ? ADDRESS_FAMILY_NO : ADDRESS_FAMILY_YES;
                n = NULL;
                return 0;
        }

        AddressFamily a = duplicate_address_detection_address_family_from_string(rvalue);
        if (a < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, a,
                           "Failed to parse %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }
        n->duplicate_address_detection = a;

        TAKE_PTR(n);
        return 0;
}

bool address_is_ready(const Address *a) {
        assert(a);

        return !(a->flags & IFA_F_TENTATIVE);
}

static int address_section_verify(Address *address) {
        if (section_is_invalid(address->section))
                return -EINVAL;

        if (address->family == AF_UNSPEC) {
                assert(address->section);

                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Address section without Address= field configured. "
                                         "Ignoring [Address] section from line %u.",
                                         address->section->filename, address->section->line);
        }

        if (address_may_have_broadcast(address)) {
                if (address->broadcast.s_addr == 0 && address->set_broadcast != 0)
                        address->broadcast.s_addr = address->in_addr.in.s_addr | htobe32(0xfffffffflu >> address->prefixlen);
        } else if (address->broadcast.s_addr != 0) {
                log_warning("%s: broadcast address is set for IPv6 address or IPv4 address with prefixlength larger than 30. "
                            "Ignoring Broadcast= setting in the [Address] section from line %u.",
                            address->section->filename, address->section->line);

                address->broadcast.s_addr = 0;
        }

        if (address->family == AF_INET6 && address->label) {
                log_warning("%s: address label is set for IPv6 address in the [Address] section from line %u. "
                            "Ignoring Label= setting.",
                            address->section->filename, address->section->line);

                address->label = mfree(address->label);
        }

        if (in_addr_is_localhost(address->family, &address->in_addr) > 0 &&
            (address->family == AF_INET || !address->scope_set)) {
                /* For IPv4, scope must be always RT_SCOPE_HOST.
                 * For IPv6, use RT_SCOPE_HOST only when it is not explicitly specified. */

                if (address->scope_set && address->scope != RT_SCOPE_HOST)
                        log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                          "%s: non-host scope is set in the [Address] section from line %u. "
                                          "Ignoring Scope= setting.",
                                          address->section->filename, address->section->line);

                address->scope = RT_SCOPE_HOST;
        }

        if (!FLAGS_SET(address->duplicate_address_detection, ADDRESS_FAMILY_IPV6))
                address->flags |= IFA_F_NODAD;

        return 0;
}

void network_drop_invalid_addresses(Network *network) {
        Address *address;

        assert(network);

        ORDERED_HASHMAP_FOREACH(address, network->addresses_by_section)
                if (address_section_verify(address) < 0)
                        address_free(address);
}
