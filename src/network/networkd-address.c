/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <net/if_arp.h>

#include "alloc-util.h"
#include "firewall-util.h"
#include "memory-util.h"
#include "netlink-util.h"
#include "networkd-address-pool.h"
#include "networkd-address.h"
#include "networkd-ipv4acd.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"

#define ADDRESSES_PER_LINK_MAX 2048U
#define STATIC_ADDRESSES_PER_NETWORK_MAX 1024U

static int address_flags_to_string_alloc(uint32_t flags, int family, char **ret) {
        _cleanup_free_ char *str = NULL;
        static const struct {
                uint32_t flag;
                const char *name;
        } map[] = {
                { IFA_F_SECONDARY,      "secondary"                }, /* This is also called "temporary" for ipv6. */
                { IFA_F_NODAD,          "nodad"                    },
                { IFA_F_OPTIMISTIC,     "optimistic"               },
                { IFA_F_DADFAILED,      "dadfailed"                },
                { IFA_F_HOMEADDRESS,    "home-address"             },
                { IFA_F_DEPRECATED,     "deprecated"               },
                { IFA_F_TENTATIVE,      "tentative"                },
                { IFA_F_PERMANENT,      "permanent"                },
                { IFA_F_MANAGETEMPADDR, "manage-temporary-address" },
                { IFA_F_NOPREFIXROUTE,  "no-prefixroute"           },
                { IFA_F_MCAUTOJOIN,     "auto-join"                },
                { IFA_F_STABLE_PRIVACY, "stable-privacy"           },
        };

        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(ret);

        for (size_t i = 0; i < ELEMENTSOF(map); i++)
                if (flags & map[i].flag &&
                    !strextend_with_separator(
                                &str, ",",
                                map[i].flag == IFA_F_SECONDARY && family == AF_INET6 ? "temporary" : map[i].name))
                        return -ENOMEM;

        *ret = TAKE_PTR(str);
        return 0;
}

int generate_ipv6_eui_64_address(const Link *link, struct in6_addr *ret) {
        assert(link);
        assert(ret);

        if (link->iftype == ARPHRD_INFINIBAND) {
                /* see RFC4391 section 8 */
                memcpy(&ret->s6_addr[8], &link->hw_addr.infiniband[12], 8);
                ret->s6_addr[8] ^= 1 << 1;

                return 0;
        }

        /* see RFC4291 section 2.5.1 */
        ret->s6_addr[8]  = link->hw_addr.ether.ether_addr_octet[0];
        ret->s6_addr[8] ^= 1 << 1;
        ret->s6_addr[9]  = link->hw_addr.ether.ether_addr_octet[1];
        ret->s6_addr[10] = link->hw_addr.ether.ether_addr_octet[2];
        ret->s6_addr[11] = 0xff;
        ret->s6_addr[12] = 0xfe;
        ret->s6_addr[13] = link->hw_addr.ether.ether_addr_octet[3];
        ret->s6_addr[14] = link->hw_addr.ether.ether_addr_octet[4];
        ret->s6_addr[15] = link->hw_addr.ether.ether_addr_octet[5];

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
        address->is_static = true;

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
                set_remove(address->link->addresses_ipv4acd, address);
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
                        if (address_equal(n->address, address))
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

        if (a->family != AF_INET)
                return false;

        if (in4_addr_is_set(&a->in_addr_peer.in))
                return false;

        /* A /31 or /32 IPv4 address does not have a broadcast address.
         * See https://tools.ietf.org/html/rfc3021 */
        if (a->prefixlen > 30)
                return false;

        if (a->set_broadcast >= 0)
                return a->set_broadcast;

        return true; /* Defaults to true. */
}

void address_set_broadcast(Address *a) {
        assert(a);

        if (!address_may_have_broadcast(a))
                return;

        /* If explicitly configured, do not update the address. */
        if (in4_addr_is_set(&a->broadcast))
                return;

        /* If Address= is 0.0.0.0, then the broadcast address will be set later in address_acquire(). */
        if (in4_addr_is_null(&a->in_addr.in))
                return;

        a->broadcast.s_addr = a->in_addr.in.s_addr | htobe32(UINT32_C(0xffffffff) >> a->prefixlen);
}

static bool address_may_set_broadcast(const Address *a, const Link *link) {
        assert(a);
        assert(link);

        if (!address_may_have_broadcast(a))
                return false;

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

int address_dup(const Address *src, Address **ret) {
        _cleanup_(address_freep) Address *dest = NULL;
        int r;

        assert(src);
        assert(ret);

        dest = newdup(Address, src, 1);
        if (!dest)
                return -ENOMEM;

        /* clear all pointers */
        dest->network = NULL;
        dest->section = NULL;
        dest->link = NULL;
        dest->label = NULL;
        dest->acd = NULL;

        if (src->family == AF_INET) {
                r = free_and_strdup(&dest->label, src->label);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(dest);
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

        r = address_dup(in, &address);
        if (r < 0)
                return r;

        /* Consider address tentative until we get the real flags from the kernel */
        address->flags |= IFA_F_TENTATIVE;

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
        return 0;
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
                    in6_addr_is_link_local(&address->in_addr.in6) > 0 &&
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

int link_get_ipv6_address(Link *link, const struct in6_addr *address, Address **ret) {
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

        return address_get(link, a, ret);
}

static int addresses_get_ipv4_address(Set *addresses, const struct in_addr *address, Address **ret) {
        Address *a;

        assert(address);

        SET_FOREACH(a, addresses) {
                if (a->family != AF_INET)
                        continue;

                if (!in4_addr_equal(&a->in_addr.in, address))
                        continue;

                if (ret)
                        *ret = a;

                return 0;
        }

        return -ENOENT;
}

int link_get_ipv4_address(Link *link, const struct in_addr *address, unsigned char prefixlen, Address **ret) {
        int r;

        assert(link);
        assert(address);

        if (prefixlen != 0) {
                _cleanup_(address_freep) Address *a = NULL;

                /* If prefixlen is set, then we can use address_get(). */

                r = address_new(&a);
                if (r < 0)
                        return r;

                a->family = AF_INET;
                a->in_addr.in = *address;
                a->prefixlen = prefixlen;

                return address_get(link, a, ret);
        }

        if (addresses_get_ipv4_address(link->addresses, address, ret) >= 0)
                return 0;
        return addresses_get_ipv4_address(link->addresses_foreign, address, ret);
}

int manager_has_address(Manager *manager, int family, const union in_addr_union *address, bool check_ready) {
        Address *a;
        Link *link;
        int r;

        assert(manager);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(address);

        if (family == AF_INET) {
                HASHMAP_FOREACH(link, manager->links_by_index)
                        if (link_get_ipv4_address(link, &address->in, 0, &a) >= 0)
                                return !check_ready || address_is_ready(a);
        } else {
                _cleanup_(address_freep) Address *tmp = NULL;

                r = address_new(&tmp);
                if (r < 0)
                        return r;

                tmp->family = family;
                tmp->in_addr = *address;

                HASHMAP_FOREACH(link, manager->links_by_index)
                        if (address_get(link, tmp, &a) >= 0)
                                return !check_ready || address_is_ready(a);
        }

        return false;
}

static void log_address_debug(const Address *address, const char *str, const Link *link) {
        _cleanup_free_ char *addr = NULL, *peer = NULL, *flags_str = NULL;
        char valid_buf[FORMAT_TIMESPAN_MAX], preferred_buf[FORMAT_TIMESPAN_MAX];
        const char *valid_str = NULL, *preferred_str = NULL;
        bool has_peer;

        assert(address);
        assert(str);
        assert(link);

        if (!DEBUG_LOGGING)
                return;

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

        (void) address_flags_to_string_alloc(address->flags, address->family, &flags_str);

        log_link_debug(link, "%s address: %s%s%s/%u (valid %s%s, preferred %s%s), flags: %s",
                       str, strnull(addr), has_peer ? " peer " : "",
                       has_peer ? strnull(peer) : "", address->prefixlen,
                       valid_str ? "for " : "forever", strempty(valid_str),
                       preferred_str ? "for " : "forever", strempty(preferred_str),
                       strna(flags_str));
}

static int address_set_netlink_message(const Address *address, sd_netlink_message *req, Link *link) {
        uint32_t flags;
        int r;

        assert(address);
        assert(req);
        assert(link);

        r = sd_rtnl_message_addr_set_prefixlen(req, address->prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set prefixlen: %m");

        /* On remove, only IFA_F_MANAGETEMPADDR flag for IPv6 addresses are used. But anyway, set all
         * flags except tentative flag here unconditionally. Without setting the flag, the template
         * addresses generated by kernel will not be removed automatically when the main address is
         * removed. */
        flags = address->flags & ~IFA_F_TENTATIVE;
        r = sd_rtnl_message_addr_set_flags(req, flags & 0xff);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set flags: %m");

        if ((flags & ~0xff) != 0) {
                r = sd_netlink_message_append_u32(req, IFA_FLAGS, flags);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set extended flags: %m");
        }

        r = netlink_message_append_in_addr_union(req, IFA_LOCAL, address->family, &address->in_addr);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFA_LOCAL attribute: %m");

        return 0;
}

static int address_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(rtnl);
        assert(m);
        assert(link);
        assert(link->address_remove_messages > 0);

        link->address_remove_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EADDRNOTAVAIL)
                log_link_message_warning_errno(link, m, r, "Could not drop address");

        return 1;
}

int address_remove(const Address *address, Link *link) {
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
                               address_remove_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);
        link->address_remove_messages++;

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

int link_drop_ipv6ll_addresses(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);

        /* IPv6LL address may be in the tentative state, and in that case networkd has not received it.
         * So, we need to dump all IPv6 addresses. */

        if (link_ipv6ll_enabled(link))
                return 0;

        r = sd_rtnl_message_new_addr(link->manager->rtnl, &req, RTM_GETADDR, link->ifindex, AF_INET6);
        if (r < 0)
                return r;

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(link->manager->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *addr = reply; addr; addr = sd_netlink_message_next(addr)) {
                _cleanup_(address_freep) Address *a = NULL;
                unsigned char flags, prefixlen;
                struct in6_addr address;
                int ifindex;

                /* NETLINK_GET_STRICT_CHK socket option is supported since kernel 4.20. To support
                 * older kernels, we need to check ifindex here. */
                r = sd_rtnl_message_addr_get_ifindex(addr, &ifindex);
                if (r < 0) {
                        log_link_debug_errno(link, r, "rtnl: received address message without valid ifindex, ignoring: %m");
                        continue;
                } else if (link->ifindex != ifindex)
                        continue;

                r = sd_rtnl_message_addr_get_flags(addr, &flags);
                if (r < 0) {
                        log_link_debug_errno(link, r, "rtnl: received address message without valid flags, ignoring: %m");
                        continue;
                }

                r = sd_rtnl_message_addr_get_prefixlen(addr, &prefixlen);
                if (r < 0) {
                        log_link_debug_errno(link, r, "rtnl: received address message without prefixlen, ignoring: %m");
                        continue;
                }

                if (sd_netlink_message_read_in6_addr(addr, IFA_LOCAL, NULL) >= 0)
                        /* address with peer, ignoring. */
                        continue;

                r = sd_netlink_message_read_in6_addr(addr, IFA_ADDRESS, &address);
                if (r < 0) {
                        log_link_debug_errno(link, r, "rtnl: received address message without valid address, ignoring: %m");
                        continue;
                }

                if (!in6_addr_is_link_local(&address))
                         continue;

                r = address_new(&a);
                if (r < 0)
                        return -ENOMEM;

                a->family = AF_INET6;
                a->in_addr.in6 = address;
                a->prefixlen = prefixlen;
                a->flags = flags;

                r = address_remove(a, link);
                if (r < 0)
                        return r;
        }

        return 0;
}

int link_drop_foreign_addresses(Link *link) {
        Address *address;
        int k, r = 0;

        assert(link);

        SET_FOREACH(address, link->addresses_foreign) {
                /* We consider IPv6LL addresses to be managed by the kernel, or dropped in link_drop_ipv6ll_addresses() */
                if (address->family == AF_INET6 && in6_addr_is_link_local(&address->in_addr.in6) == 1)
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
                        k = address_remove(address, link);
                        if (k < 0 && r >= 0)
                                r = k;
                }
        }

        return r;
}

int link_drop_addresses(Link *link) {
        Address *address, *pool_address;
        int k, r = 0;

        assert(link);

        SET_FOREACH(address, link->addresses) {
                /* we consider IPv6LL addresses to be managed by the kernel */
                if (address->family == AF_INET6 && in6_addr_is_link_local(&address->in_addr.in6) == 1 && link_ipv6ll_enabled(link))
                        continue;

                k = address_remove(address, link);
                if (k < 0 && r >= 0) {
                        r = k;
                        continue;
                }

                SET_FOREACH(pool_address, link->pool_addresses)
                        if (address_equal(address, pool_address))
                                address_free(set_remove(link->pool_addresses, pool_address));
        }

        return r;
}

static int address_acquire(Link *link, const Address *original, Address **ret) {
        union in_addr_union in_addr = IN_ADDR_NULL;
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

        /* Pick first address in range for ourselves. */
        if (original->family == AF_INET)
                in_addr.in.s_addr = in_addr.in.s_addr | htobe32(1);
        else if (original->family == AF_INET6)
                in_addr.in6.s6_addr[15] |= 1;

        r = address_dup(original, &na);
        if (r < 0)
                return r;

        na->in_addr = in_addr;
        address_set_broadcast(na);

        r = set_ensure_put(&link->pool_addresses, &address_hash_ops, na);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        *ret = TAKE_PTR(na);
        return 1;
}

int address_configure_handler_internal(sd_netlink *rtnl, sd_netlink_message *m, Link *link, const char *error_msg) {
        int r;

        assert(rtnl);
        assert(m);
        assert(link);
        assert(error_msg);

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, error_msg);
                link_enter_failed(link);
                return 0;
        }

        return 1;
}

static int address_configure(
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
        assert(callback);

        log_address_debug(address, "Configuring", link);

        r = sd_rtnl_message_new_addr_update(link->manager->rtnl, &req,
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

        r = sd_netlink_message_append_u32(req, IFA_RT_PRIORITY, address->route_metric);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFA_RT_PRIORITY attribute: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback, link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);
        return 0;
}

static int static_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->static_address_messages > 0);

        link->static_address_messages--;

        r = address_configure_handler_internal(rtnl, m, link, "Failed to set static address");
        if (r <= 0)
                return r;

        if (link->static_address_messages == 0) {
                log_link_debug(link, "Addresses set");
                link->static_addresses_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int static_address_after_configure(Request *req, void *object) {
        Address *address = object;
        Link *link;
        int r;

        assert(req);
        assert(req->link);
        assert(req->type == REQUEST_TYPE_ADDRESS);
        assert(address);

        link = req->link;

        r = set_ensure_put(&link->static_addresses, &address_hash_ops, address);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to store static address: %m");

        return 0;
}

int link_request_address(
                Link *link,
                Address *address,
                bool consume_object,
                unsigned *message_counter,
                link_netlink_message_handler_t netlink_handler,
                Request **ret) {

        Address *acquired;
        int r;

        assert(link);
        assert(address);

        r = address_acquire(link, address, &acquired);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to acquire an address from pool: %m");
        if (r > 0) {
                if (consume_object) {
                        address_free(address);
                        consume_object = false; /* address from pool is already managed by Link. */
                }
                address = acquired;
        }

        log_address_debug(address, "Requesting", link);
        r = link_queue_request(link, REQUEST_TYPE_ADDRESS, address, consume_object,
                               message_counter, netlink_handler, ret);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request address: %m");
        return r;
}

int link_request_static_address(Link *link, Address *address, bool consume) {
        Request *req;
        int r;

        assert(link);
        assert(address);

        r = link_request_address(link, address, consume, &link->static_address_messages,
                                 static_address_handler, &req);
        if (r <= 0)
                return r;

        req->after_configure = static_address_after_configure;
        return 0;
}

int link_request_static_addresses(Link *link) {
        Address *a;
        Prefix *p;
        int r;

        assert(link);
        assert(link->network);

        link->static_addresses_configured = false;

        ORDERED_HASHMAP_FOREACH(a, link->network->addresses_by_section) {
                r = link_request_static_address(link, a, false);
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
                address->route_metric = p->route_metric;

                r = link_request_static_address(link, TAKE_PTR(address), true);
                if (r < 0)
                        return r;
        }

        if (in4_addr_is_set(&link->network->dhcp_server_address)) {
                _cleanup_(address_freep) Address *address = NULL;

                r = address_new(&address);
                if (r < 0)
                        return log_oom();

                address->family = AF_INET;
                address->in_addr.in = link->network->dhcp_server_address;
                address->prefixlen = link->network->dhcp_server_address_prefixlen;
                address_set_broadcast(address);

                /* The same address may be explicitly configured in [Address] or [Network] section.
                 * Configure the DHCP server address only when it is not. */
                if (!link_is_static_address_configured(link, address)) {
                        r = link_request_static_address(link, TAKE_PTR(address), true);
                        if (r < 0)
                                return r;
                }
        }

        if (link->static_address_messages == 0) {
                link->static_addresses_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting addresses");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

static int address_is_ready_to_configure(Link *link, const Address *address) {
        int r;

        assert(link);
        assert(address);

        if (!link_is_ready_to_configure(link, false))
                return false;

        if (link->address_remove_messages > 0)
                return false;

        if (address_get(link, address, NULL) >= 0)
                return true;

        /* If this is a new address, then refuse adding more than the limit */
        if (set_size(link->addresses) >= ADDRESSES_PER_LINK_MAX)
                return log_link_warning_errno(link, SYNTHETIC_ERRNO(E2BIG),
                                              "Too many addresses are configured, refusing: %m");

        if (address->family == AF_INET &&
            address->duplicate_address_detection & ADDRESS_FAMILY_IPV4 &&
            link->hw_addr.length == ETH_ALEN &&
            !ether_addr_is_null(&link->hw_addr.ether))
                return ipv4acd_address_is_ready_to_configure(link, address);

        r = address_add(link, address, NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not add address: %m");;

        return true;
}

int request_process_address(Request *req) {
        Address *a;
        Link *link;
        int r;

        assert(req);
        assert(req->link);
        assert(req->address);
        assert(req->type == REQUEST_TYPE_ADDRESS);

        link = req->link;

        r = address_is_ready_to_configure(link, req->address);
        if (r <= 0)
                return r;

        r = address_configure(req->address, link, req->netlink_handler);
        if (r < 0)
                return r;

        /* To prevent a double decrement on failure in after_configure(). */
        req->message_counter = NULL;

        r = address_get(link, req->address, &a);
        if (r < 0)
                return r;

        if (req->after_configure) {
                r = req->after_configure(req, a);
                if (r < 0)
                        return r;
        }

        r = address_set_masquerade(a, true);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not enable IP masquerading, ignoring: %m");

        return 1;
}

int manager_rtnl_process_address(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(address_freep) Address *tmp = NULL;
        Link *link = NULL;
        uint16_t type;
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

        r = link_get_by_index(m, ifindex, &link);
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

        r = sd_netlink_message_read_u32(message, IFA_FLAGS, &tmp->flags);
        if (r < 0) {
                log_link_warning_errno(link, r, "rtnl: received address message without flags, ignoring: %m");
                return 0;
        }

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

int config_parse_address_route_metric(
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

        r = safe_atou32(rvalue, &n->route_metric);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

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

        if (address_may_have_broadcast(address))
                address_set_broadcast(address);
        else if (address->broadcast.s_addr != 0) {
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

        if (address->family == AF_INET6 &&
            !FLAGS_SET(address->duplicate_address_detection, ADDRESS_FAMILY_IPV6))
                address->flags |= IFA_F_NODAD;

        if (address->family == AF_INET && in4_addr_is_link_local(&address->in_addr.in) &&
            !FLAGS_SET(address->duplicate_address_detection, ADDRESS_FAMILY_IPV4)) {
                log_debug("%s: An IPv4 link-local address is specified, enabling IPv4 Address Conflict Detection (ACD).",
                          address->section->filename);
                address->duplicate_address_detection |= ADDRESS_FAMILY_IPV4;
        }

        return 0;
}

void network_drop_invalid_addresses(Network *network) {
        Address *address;

        assert(network);

        ORDERED_HASHMAP_FOREACH(address, network->addresses_by_section)
                if (address_section_verify(address) < 0)
                        address_free(address);
}
