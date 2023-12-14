/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <net/if_arp.h>

#include "alloc-util.h"
#include "firewall-util.h"
#include "logarithm.h"
#include "memory-util.h"
#include "netlink-util.h"
#include "networkd-address-pool.h"
#include "networkd-address.h"
#include "networkd-dhcp-server.h"
#include "networkd-ipv4acd.h"
#include "networkd-manager.h"
#include "networkd-netlabel.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "networkd-route-util.h"
#include "networkd-route.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"

#define ADDRESSES_PER_LINK_MAX 2048U
#define STATIC_ADDRESSES_PER_NETWORK_MAX 1024U

#define KNOWN_FLAGS                             \
        (IFA_F_SECONDARY |                      \
         IFA_F_NODAD |                          \
         IFA_F_OPTIMISTIC |                     \
         IFA_F_DADFAILED |                      \
         IFA_F_HOMEADDRESS |                    \
         IFA_F_DEPRECATED |                     \
         IFA_F_TENTATIVE |                      \
         IFA_F_PERMANENT |                      \
         IFA_F_MANAGETEMPADDR |                 \
         IFA_F_NOPREFIXROUTE |                  \
         IFA_F_MCAUTOJOIN |                     \
         IFA_F_STABLE_PRIVACY)

/* From net/ipv4/devinet.c */
#define IPV6ONLY_FLAGS                          \
        (IFA_F_NODAD |                          \
         IFA_F_OPTIMISTIC |                     \
         IFA_F_DADFAILED |                      \
         IFA_F_HOMEADDRESS |                    \
         IFA_F_TENTATIVE |                      \
         IFA_F_MANAGETEMPADDR |                 \
         IFA_F_STABLE_PRIVACY)

/* We do not control the following flags. */
#define UNMANAGED_FLAGS                         \
        (IFA_F_SECONDARY |                      \
         IFA_F_DADFAILED |                      \
         IFA_F_DEPRECATED |                     \
         IFA_F_TENTATIVE |                      \
         IFA_F_PERMANENT |                      \
         IFA_F_STABLE_PRIVACY)

int address_flags_to_string_alloc(uint32_t flags, int family, char **ret) {
        _cleanup_free_ char *str = NULL;
        static const char* map[] = {
                [LOG2U(IFA_F_SECONDARY)]      = "secondary", /* This is also called "temporary" for ipv6. */
                [LOG2U(IFA_F_NODAD)]          = "nodad",
                [LOG2U(IFA_F_OPTIMISTIC)]     = "optimistic",
                [LOG2U(IFA_F_DADFAILED)]      = "dadfailed",
                [LOG2U(IFA_F_HOMEADDRESS)]    = "home-address",
                [LOG2U(IFA_F_DEPRECATED)]     = "deprecated",
                [LOG2U(IFA_F_TENTATIVE)]      = "tentative",
                [LOG2U(IFA_F_PERMANENT)]      = "permanent",
                [LOG2U(IFA_F_MANAGETEMPADDR)] = "manage-temporary-address",
                [LOG2U(IFA_F_NOPREFIXROUTE)]  = "no-prefixroute",
                [LOG2U(IFA_F_MCAUTOJOIN)]     = "auto-join",
                [LOG2U(IFA_F_STABLE_PRIVACY)] = "stable-privacy",
        };

        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(ret);

        for (size_t i = 0; i < ELEMENTSOF(map); i++)
                if (FLAGS_SET(flags, 1 << i) && map[i])
                        if (!strextend_with_separator(
                                            &str, ",",
                                            family == AF_INET6 && (1 << i) == IFA_F_SECONDARY ? "temporary" : map[i]))
                                return -ENOMEM;

        *ret = TAKE_PTR(str);
        return 0;
}

static LinkAddressState address_state_from_scope(uint8_t scope) {
        if (scope < RT_SCOPE_SITE)
                /* universally accessible addresses found */
                return LINK_ADDRESS_STATE_ROUTABLE;

        if (scope < RT_SCOPE_HOST)
                /* only link or site local addresses found */
                return LINK_ADDRESS_STATE_DEGRADED;

        /* no useful addresses found */
        return LINK_ADDRESS_STATE_OFF;
}

void link_get_address_states(
                Link *link,
                LinkAddressState *ret_ipv4,
                LinkAddressState *ret_ipv6,
                LinkAddressState *ret_all) {

        uint8_t ipv4_scope = RT_SCOPE_NOWHERE, ipv6_scope = RT_SCOPE_NOWHERE;
        Address *address;

        assert(link);

        SET_FOREACH(address, link->addresses) {
                if (!address_is_ready(address))
                        continue;

                if (address->family == AF_INET)
                        ipv4_scope = MIN(ipv4_scope, address->scope);

                if (address->family == AF_INET6)
                        ipv6_scope = MIN(ipv6_scope, address->scope);
        }

        if (ret_ipv4)
                *ret_ipv4 = address_state_from_scope(ipv4_scope);
        if (ret_ipv6)
                *ret_ipv6 = address_state_from_scope(ipv6_scope);
        if (ret_all)
                *ret_all = address_state_from_scope(MIN(ipv4_scope, ipv6_scope));
}

static void address_hash_func(const Address *a, struct siphash *state);
static int address_compare_func(const Address *a1, const Address *a2);
static void address_detach(Address *address);

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
        address_hash_ops_detach,
        Address,
        address_hash_func,
        address_compare_func,
        address_detach);

DEFINE_HASH_OPS(
        address_hash_ops,
        Address,
        address_hash_func,
        address_compare_func);

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        address_section_hash_ops,
        ConfigSection,
        config_section_hash_func,
        config_section_compare_func,
        Address,
        address_detach);

int address_new(Address **ret) {
        _cleanup_(address_unrefp) Address *address = NULL;

        address = new(Address, 1);
        if (!address)
                return -ENOMEM;

        *address = (Address) {
                .n_ref = 1,
                .family = AF_UNSPEC,
                .scope = RT_SCOPE_UNIVERSE,
                .lifetime_valid_usec = USEC_INFINITY,
                .lifetime_preferred_usec = USEC_INFINITY,
                .set_broadcast = -1,
        };

        *ret = TAKE_PTR(address);

        return 0;
}

int address_new_static(Network *network, const char *filename, unsigned section_line, Address **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(address_unrefp) Address *address = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
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
        address->source = NETWORK_CONFIG_SOURCE_STATIC;
        /* This will be adjusted in address_section_verify(). */
        address->duplicate_address_detection = _ADDRESS_FAMILY_INVALID;

        r = ordered_hashmap_ensure_put(&network->addresses_by_section, &address_section_hash_ops, address->section, address);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(address);
        return 0;
}

static Address* address_detach_impl(Address *address) {
        assert(address);
        assert(!address->link || !address->network);

        if (address->network) {
                assert(address->section);
                ordered_hashmap_remove(address->network->addresses_by_section, address->section);

                if (address->network->dhcp_server_address == address)
                        address->network->dhcp_server_address = NULL;

                address->network = NULL;
                return address;
        }

        if (address->link) {
                set_remove(address->link->addresses, address);

                address->link = NULL;
                return address;
        }

        return NULL;
}

static void address_detach(Address *address) {
        assert(address);

        address_unref(address_detach_impl(address));
}

static Address* address_free(Address *address) {
        if (!address)
                return NULL;

        address_detach_impl(address);

        config_section_free(address->section);
        free(address->label);
        free(address->netlabel);
        nft_set_context_clear(&address->nft_set_context);
        return mfree(address);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Address, address, address_free);

static bool address_lifetime_is_valid(const Address *a) {
        assert(a);

        return
                a->lifetime_valid_usec == USEC_INFINITY ||
                a->lifetime_valid_usec > now(CLOCK_BOOTTIME);
}

bool address_is_ready(const Address *a) {
        assert(a);
        assert(a->link);

        if (!ipv4acd_bound(a->link, a))
                return false;

        if (FLAGS_SET(a->flags, IFA_F_TENTATIVE))
                return false;

        if (FLAGS_SET(a->state, NETWORK_CONFIG_STATE_REMOVING))
                return false;

        if (!FLAGS_SET(a->state, NETWORK_CONFIG_STATE_CONFIGURED))
                return false;

        return address_lifetime_is_valid(a);
}

bool link_check_addresses_ready(Link *link, NetworkConfigSource source) {
        Address *a;
        bool has = false;

        assert(link);

        /* Check if all addresses on the interface are ready. If there is no address, this will return false. */

        SET_FOREACH(a, link->addresses) {
                if (source >= 0 && a->source != source)
                        continue;
                if (address_is_marked(a))
                        continue;
                if (!address_exists(a))
                        continue;
                if (!address_is_ready(a))
                        return false;
                has = true;
        }

        return has;
}

void link_mark_addresses(Link *link, NetworkConfigSource source) {
        Address *a;

        assert(link);

        SET_FOREACH(a, link->addresses) {
                if (a->source != source)
                        continue;

                address_mark(a);
        }
}

static int address_get_broadcast(const Address *a, Link *link, struct in_addr *ret) {
        struct in_addr b_addr = {};

        assert(a);
        assert(link);

        /* Returns 0 when broadcast address is null, 1 when non-null broadcast address, -EAGAIN when the main
         * address is null. */

        /* broadcast is only for IPv4. */
        if (a->family != AF_INET)
                goto finalize;

        /* broadcast address cannot be used when peer address is specified. */
        if (in4_addr_is_set(&a->in_addr_peer.in))
                goto finalize;

        /* A /31 or /32 IPv4 address does not have a broadcast address.
         * See https://tools.ietf.org/html/rfc3021 */
        if (a->prefixlen > 30)
                goto finalize;

        /* If explicitly configured, use the address as is. */
        if (in4_addr_is_set(&a->broadcast)) {
                b_addr = a->broadcast;
                goto finalize;
        }

        /* If explicitly disabled, then return null address. */
        if (a->set_broadcast == 0)
                goto finalize;

        /* For wireguard interfaces, broadcast is disabled by default. */
        if (a->set_broadcast < 0 && streq_ptr(link->kind, "wireguard"))
                goto finalize;

        /* If the main address is null, e.g. Address=0.0.0.0/24, the broadcast address will be automatically
         * determined after an address is acquired. */
        if (!in4_addr_is_set(&a->in_addr.in))
                return -EAGAIN;

        /* Otherwise, generate a broadcast address from the main address and prefix length. */
        b_addr.s_addr = a->in_addr.in.s_addr | htobe32(UINT32_C(0xffffffff) >> a->prefixlen);

finalize:
        if (ret)
                *ret = b_addr;

        return in4_addr_is_set(&b_addr);
}

static void address_set_broadcast(Address *a, Link *link) {
        assert(a);
        assert_se(address_get_broadcast(a, link, &a->broadcast) >= 0);
}

static void address_set_cinfo(Manager *m, const Address *a, struct ifa_cacheinfo *cinfo) {
        usec_t now_usec;

        assert(m);
        assert(a);
        assert(cinfo);

        assert_se(sd_event_now(m->event, CLOCK_BOOTTIME, &now_usec) >= 0);

        *cinfo = (struct ifa_cacheinfo) {
                .ifa_valid = usec_to_sec(a->lifetime_valid_usec, now_usec),
                .ifa_prefered = usec_to_sec(a->lifetime_preferred_usec, now_usec),
        };
}

static void address_set_lifetime(Manager *m, Address *a, const struct ifa_cacheinfo *cinfo) {
        usec_t now_usec;

        assert(m);
        assert(a);
        assert(cinfo);

        assert_se(sd_event_now(m->event, CLOCK_BOOTTIME, &now_usec) >= 0);

        a->lifetime_valid_usec = sec_to_usec(cinfo->ifa_valid, now_usec);
        a->lifetime_preferred_usec = sec_to_usec(cinfo->ifa_prefered, now_usec);
}

static bool address_is_static_null(const Address *address) {
        assert(address);

        if (!address->network)
                return false;

        if (!address->requested_as_null)
                return false;

        assert(!in_addr_is_set(address->family, &address->in_addr));
        return true;
}

static int address_ipv4_prefix(const Address *a, struct in_addr *ret) {
        struct in_addr p;
        int r;

        assert(a);
        assert(a->family == AF_INET);
        assert(ret);

        p = in4_addr_is_set(&a->in_addr_peer.in) ? a->in_addr_peer.in : a->in_addr.in;
        r = in4_addr_mask(&p, a->prefixlen);
        if (r < 0)
                return r;

        *ret = p;
        return 0;
}

static void address_hash_func(const Address *a, struct siphash *state) {
        assert(a);

        siphash24_compress_typesafe(a->family, state);

        switch (a->family) {
        case AF_INET: {
                struct in_addr prefix;

                siphash24_compress_typesafe(a->prefixlen, state);

                assert_se(address_ipv4_prefix(a, &prefix) >= 0);
                siphash24_compress_typesafe(prefix, state);

                siphash24_compress_typesafe(a->in_addr.in, state);
                break;
        }
        case AF_INET6:
                siphash24_compress_typesafe(a->in_addr.in6, state);

                if (in6_addr_is_null(&a->in_addr.in6))
                        siphash24_compress_typesafe(a->prefixlen, state);
                break;

        default:
                /* treat any other address family as AF_UNSPEC */
                break;
        }
}

static int address_compare_func(const Address *a1, const Address *a2) {
        int r;

        r = CMP(a1->family, a2->family);
        if (r != 0)
                return r;

        switch (a1->family) {
        case AF_INET: {
                struct in_addr p1, p2;

                /* See kernel's find_matching_ifa() in net/ipv4/devinet.c */
                r = CMP(a1->prefixlen, a2->prefixlen);
                if (r != 0)
                        return r;

                assert_se(address_ipv4_prefix(a1, &p1) >= 0);
                assert_se(address_ipv4_prefix(a2, &p2) >= 0);
                r = memcmp(&p1, &p2, sizeof(p1));
                if (r != 0)
                        return r;

                return memcmp(&a1->in_addr.in, &a2->in_addr.in, sizeof(a1->in_addr.in));
        }
        case AF_INET6:
                /* See kernel's ipv6_get_ifaddr() in net/ipv6/addrconf.c */
                r = memcmp(&a1->in_addr.in6, &a2->in_addr.in6, sizeof(a1->in_addr.in6));
                if (r != 0)
                        return r;

                /* To distinguish IPv6 null addresses with different prefixlen, e.g. ::48 vs ::64, let's
                 * compare the prefix length. */
                if (in6_addr_is_null(&a1->in_addr.in6))
                        r = CMP(a1->prefixlen, a2->prefixlen);

                return r;

        default:
                /* treat any other address family as AF_UNSPEC */
                return 0;
        }
}

static bool address_can_update(const Address *la, const Address *na) {
        assert(la);
        assert(la->link);
        assert(na);
        assert(na->network);

        /*
         * property     |    IPv4     |  IPv6
         * -----------------------------------------
         * family       |      ✗      |     ✗
         * prefixlen    |      ✗      |     ✗
         * address      |      ✗      |     ✗
         * scope        |      ✗      |     -
         * label        |      ✗      |     -
         * broadcast    |      ✗      |     -
         * peer         |      ✗      |     ✓
         * flags        |      ✗      |     ✓
         * lifetime     |      ✓      |     ✓
         * route metric |      ✓      |     ✓
         * protocol     |      ✓      |     ✓
         *
         * ✗ : cannot be changed
         * ✓ : can be changed
         * - : unused
         *
         * IPv4 : See inet_rtm_newaddr() in net/ipv4/devinet.c.
         * IPv6 : See inet6_addr_modify() in net/ipv6/addrconf.c.
         */

        if (la->family != na->family)
                return false;

        if (la->prefixlen != na->prefixlen)
                return false;

        /* When a null address is requested, the address to be assigned/updated will be determined later. */
        if (!address_is_static_null(na) &&
            in_addr_equal(la->family, &la->in_addr, &na->in_addr) <= 0)
                return false;

        switch (la->family) {
        case AF_INET: {
                struct in_addr bcast;

                if (la->scope != na->scope)
                        return false;
                if (((la->flags ^ na->flags) & KNOWN_FLAGS & ~IPV6ONLY_FLAGS & ~UNMANAGED_FLAGS) != 0)
                        return false;
                if (!streq_ptr(la->label, na->label))
                        return false;
                if (!in4_addr_equal(&la->in_addr_peer.in, &na->in_addr_peer.in))
                        return false;
                if (address_get_broadcast(na, la->link, &bcast) >= 0) {
                        /* If the broadcast address can be determined now, check if they match. */
                        if (!in4_addr_equal(&la->broadcast, &bcast))
                                return false;
                } else {
                        /* When a null address is requested, then the broadcast address will be
                         * automatically calculated from the acquired address, e.g.
                         *     192.168.0.10/24 -> 192.168.0.255
                         * So, here let's only check if the broadcast is the last address in the range, e.g.
                         *     0.0.0.0/24 -> 0.0.0.255 */
                        if (!FLAGS_SET(la->broadcast.s_addr, htobe32(UINT32_C(0xffffffff) >> la->prefixlen)))
                                return false;
                }
                break;
        }
        case AF_INET6:
                break;

        default:
                assert_not_reached();
        }

        return true;
}

int address_dup(const Address *src, Address **ret) {
        _cleanup_(address_unrefp) Address *dest = NULL;
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
        dest->netlabel = NULL;
        dest->nft_set_context.sets = NULL;
        dest->nft_set_context.n_sets = 0;

        if (src->family == AF_INET) {
                r = free_and_strdup(&dest->label, src->label);
                if (r < 0)
                        return r;
        }

        r = free_and_strdup(&dest->netlabel, src->netlabel);
        if (r < 0)
                return r;

        r = nft_set_context_dup(&src->nft_set_context, &dest->nft_set_context);
        if (r < 0)
                return r;

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

static void address_modify_nft_set_context(Address *address, bool add, NFTSetContext *nft_set_context) {
        int r;

        assert(address);
        assert(address->link);
        assert(address->link->manager);
        assert(nft_set_context);

        if (!address->link->manager->fw_ctx) {
                r = fw_ctx_new_full(&address->link->manager->fw_ctx, /* init_tables= */ false);
                if (r < 0)
                        return;
        }

        FOREACH_ARRAY(nft_set, nft_set_context->sets, nft_set_context->n_sets) {
                uint32_t ifindex;

                assert(nft_set);

                switch (nft_set->source) {
                case NFT_SET_SOURCE_ADDRESS:
                        r = nft_set_element_modify_ip(address->link->manager->fw_ctx, add, nft_set->nfproto, address->family, nft_set->table, nft_set->set,
                                                      &address->in_addr);
                        break;
                case NFT_SET_SOURCE_PREFIX:
                        r = nft_set_element_modify_iprange(address->link->manager->fw_ctx, add, nft_set->nfproto, address->family, nft_set->table, nft_set->set,
                                                           &address->in_addr, address->prefixlen);
                        break;
                case NFT_SET_SOURCE_IFINDEX:
                        ifindex = address->link->ifindex;
                        r = nft_set_element_modify_any(address->link->manager->fw_ctx, add, nft_set->nfproto, nft_set->table, nft_set->set,
                                                       &ifindex, sizeof(ifindex));
                        break;
                default:
                        assert_not_reached();
                }

                if (r < 0)
                        log_warning_errno(r, "Failed to %s NFT set: family %s, table %s, set %s, IP address %s, ignoring: %m",
                                          add ? "add" : "delete",
                                          nfproto_to_string(nft_set->nfproto), nft_set->table, nft_set->set,
                                          IN_ADDR_PREFIX_TO_STRING(address->family, &address->in_addr, address->prefixlen));
                else
                        log_debug("%s NFT set: family %s, table %s, set %s, IP address %s",
                                  add ? "Added" : "Deleted",
                                  nfproto_to_string(nft_set->nfproto), nft_set->table, nft_set->set,
                                  IN_ADDR_PREFIX_TO_STRING(address->family, &address->in_addr, address->prefixlen));
        }
}

static void address_modify_nft_set(Address *address, bool add) {
        assert(address);
        assert(address->link);

        if (!IN_SET(address->family, AF_INET, AF_INET6))
                return;

        if (!address->link->network)
                return;

        switch (address->source) {
        case NETWORK_CONFIG_SOURCE_DHCP4:
                return address_modify_nft_set_context(address, add, &address->link->network->dhcp_nft_set_context);
        case NETWORK_CONFIG_SOURCE_DHCP6:
                return address_modify_nft_set_context(address, add, &address->link->network->dhcp6_nft_set_context);
        case NETWORK_CONFIG_SOURCE_DHCP_PD:
                return address_modify_nft_set_context(address, add, &address->link->network->dhcp_pd_nft_set_context);
        case NETWORK_CONFIG_SOURCE_NDISC:
                return address_modify_nft_set_context(address, add, &address->link->network->ndisc_nft_set_context);
        case NETWORK_CONFIG_SOURCE_STATIC:
                return address_modify_nft_set_context(address, add, &address->nft_set_context);
        default:
                return;
        }
}

static int address_add(Link *link, Address *address) {
        int r;

        assert(link);
        assert(address);

        r = set_ensure_put(&link->addresses, &address_hash_ops_detach, address);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        address->link = link;
        return 0;
}

static int address_update(Address *address) {
        Link *link = ASSERT_PTR(ASSERT_PTR(address)->link);
        int r;

        if (address_is_ready(address) &&
            address->family == AF_INET6 &&
            in6_addr_is_link_local(&address->in_addr.in6) &&
            in6_addr_is_null(&link->ipv6ll_address)) {

                link->ipv6ll_address = address->in_addr.in6;

                r = link_ipv6ll_gained(link);
                if (r < 0)
                        return r;
        }

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 0;

        r = address_set_masquerade(address, /* add = */ true);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not enable IP masquerading: %m");

        address_add_netlabel(address);

        address_modify_nft_set(address, /* add = */ true);

        if (address_is_ready(address) && address->callback) {
                r = address->callback(address);
                if (r < 0)
                        return r;
        }

        link_update_operstate(link, /* also_update_master = */ true);
        link_check_ready(link);
        return 0;
}

static int address_drop(Address *address) {
        Link *link = ASSERT_PTR(ASSERT_PTR(address)->link);
        int r;

        r = address_set_masquerade(address, /* add = */ false);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to disable IP masquerading, ignoring: %m");

        address_modify_nft_set(address, /* add = */ false);

        address_del_netlabel(address);

        /* FIXME: if the IPv6LL address is dropped, stop DHCPv6, NDISC, RADV. */
        if (address->family == AF_INET6 &&
            in6_addr_equal(&address->in_addr.in6, &link->ipv6ll_address))
                link->ipv6ll_address = (const struct in6_addr) {};

        ipv4acd_detach(link, address);

        address_detach(address);

        link_update_operstate(link, /* also_update_master = */ true);
        link_check_ready(link);
        return 0;
}

static bool address_match_null(const Address *a, const Address *null_address) {
        assert(a);
        assert(null_address);

        if (!a->requested_as_null)
                return false;

        /* Currently, null address is supported only by static addresses. Note that static
         * address may be set as foreign during reconfiguring the interface. */
        if (!IN_SET(a->source, NETWORK_CONFIG_SOURCE_FOREIGN, NETWORK_CONFIG_SOURCE_STATIC))
                return false;

        if (a->family != null_address->family)
                return false;

        if (a->prefixlen != null_address->prefixlen)
                return false;

        return true;
}

static int address_get_request(Link *link, const Address *address, Request **ret) {
        Request *req;

        assert(link);
        assert(link->manager);
        assert(address);

        req = ordered_set_get(
                        link->manager->request_queue,
                        &(Request) {
                                .link = link,
                                .type = REQUEST_TYPE_ADDRESS,
                                .userdata = (void*) address,
                                .hash_func = (hash_func_t) address_hash_func,
                                .compare_func = (compare_func_t) address_compare_func,
                        });
        if (req) {
                if (ret)
                        *ret = req;
                return 0;
        }

        if (address_is_static_null(address))
                ORDERED_SET_FOREACH(req, link->manager->request_queue) {
                        if (req->link != link)
                                continue;
                        if (req->type != REQUEST_TYPE_ADDRESS)
                                continue;

                        if (!address_match_null(req->userdata, address))
                                continue;

                        if (ret)
                                *ret = req;

                        return 0;
                }

        return -ENOENT;
}

int address_get(Link *link, const Address *in, Address **ret) {
        Address *a;

        assert(link);
        assert(in);

        a = set_get(link->addresses, in);
        if (a) {
                if (ret)
                        *ret = a;
                return 0;
        }

        /* Find matching address that originally requested as null address. */
        if (address_is_static_null(in))
                SET_FOREACH(a, link->addresses) {
                        if (!address_match_null(a, in))
                                continue;

                        if (ret)
                                *ret = a;
                        return 0;
                }

        return -ENOENT;
}

int address_get_harder(Link *link, const Address *in, Address **ret) {
        Request *req;
        int r;

        assert(link);
        assert(in);

        if (address_get(link, in, ret) >= 0)
                return 0;

        r = address_get_request(link, in, &req);
        if (r < 0)
                return r;

        if (ret)
                *ret = ASSERT_PTR(req->userdata);

        return 0;
}

int link_get_address(Link *link, int family, const union in_addr_union *address, unsigned char prefixlen, Address **ret) {
        Address *a;
        int r;

        assert(link);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(address);

        /* This find an Address object on the link which matches the given address and prefix length
         * and does not have peer address. When the prefixlen is zero, then an Address object with an
         * arbitrary prefixlen will be returned. */

        if (family == AF_INET6 || prefixlen != 0) {
                _cleanup_(address_unrefp) Address *tmp = NULL;

                /* In this case, we can use address_get(). */

                r = address_new(&tmp);
                if (r < 0)
                        return r;

                tmp->family = family;
                tmp->in_addr = *address;
                tmp->prefixlen = prefixlen;

                r = address_get(link, tmp, &a);
                if (r < 0)
                        return r;

                if (family == AF_INET6) {
                        /* IPv6 addresses are managed without peer address and prefix length. Hence, we need
                         * to check them explicitly. */
                        if (in_addr_is_set(family, &a->in_addr_peer))
                                return -ENOENT;
                        if (prefixlen != 0 && a->prefixlen != prefixlen)
                                return -ENOENT;
                }

                if (ret)
                        *ret = a;

                return 0;
        }

        SET_FOREACH(a, link->addresses) {
                if (a->family != family)
                        continue;

                if (!in_addr_equal(family, &a->in_addr, address))
                        continue;

                if (in_addr_is_set(family, &a->in_addr_peer))
                        continue;

                if (ret)
                        *ret = a;

                return 0;
        }

        return -ENOENT;
}

int manager_get_address(Manager *manager, int family, const union in_addr_union *address, unsigned char prefixlen, Address **ret) {
        Link *link;

        assert(manager);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(address);

        HASHMAP_FOREACH(link, manager->links_by_index) {
                if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                        continue;

                if (link_get_address(link, family, address, prefixlen, ret) >= 0)
                        return 0;
        }

        return -ENOENT;
}

bool manager_has_address(Manager *manager, int family, const union in_addr_union *address) {
        Address *a;

        assert(manager);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(address);

        if (manager_get_address(manager, family, address, 0, &a) < 0)
                return false;

        return address_is_ready(a);
}

const char* format_lifetime(char *buf, size_t l, usec_t lifetime_usec) {
        assert(buf);
        assert(l > 4);

        if (lifetime_usec == USEC_INFINITY)
                return "forever";

        sprintf(buf, "for ");
        /* format_timespan() never fails */
        assert_se(format_timespan(buf + 4, l - 4, usec_sub_unsigned(lifetime_usec, now(CLOCK_BOOTTIME)), USEC_PER_SEC));
        return buf;
}

static void log_address_debug(const Address *address, const char *str, const Link *link) {
        _cleanup_free_ char *state = NULL, *flags_str = NULL, *scope_str = NULL;

        assert(address);
        assert(str);
        assert(link);

        if (!DEBUG_LOGGING)
                return;

        (void) network_config_state_to_string_alloc(address->state, &state);

        const char *peer = in_addr_is_set(address->family, &address->in_addr_peer) ?
                IN_ADDR_TO_STRING(address->family, &address->in_addr_peer) : NULL;

        const char *broadcast = (address->family == AF_INET && in4_addr_is_set(&address->broadcast)) ?
                IN4_ADDR_TO_STRING(&address->broadcast) : NULL;

        (void) address_flags_to_string_alloc(address->flags, address->family, &flags_str);
        (void) route_scope_to_string_alloc(address->scope, &scope_str);

        log_link_debug(link, "%s %s address (%s): %s%s%s/%u%s%s (valid %s, preferred %s), flags: %s, scope: %s%s%s",
                       str, strna(network_config_source_to_string(address->source)), strna(state),
                       IN_ADDR_TO_STRING(address->family, &address->in_addr),
                       peer ? " peer " : "", strempty(peer), address->prefixlen,
                       broadcast ? " broadcast " : "", strempty(broadcast),
                       FORMAT_LIFETIME(address->lifetime_valid_usec),
                       FORMAT_LIFETIME(address->lifetime_preferred_usec),
                       strna(flags_str), strna(scope_str),
                       address->family == AF_INET ? ", label: " : "",
                       address->family == AF_INET ? strna(address->label) : "");
}

static int address_set_netlink_message(const Address *address, sd_netlink_message *m, Link *link) {
        uint32_t flags;
        int r;

        assert(address);
        assert(m);
        assert(link);

        r = sd_rtnl_message_addr_set_prefixlen(m, address->prefixlen);
        if (r < 0)
                return r;

        /* On remove, only IFA_F_MANAGETEMPADDR flag for IPv6 addresses are used. But anyway, set all
         * flags except tentative flag here unconditionally. Without setting the flag, the template
         * addresses generated by kernel will not be removed automatically when the main address is
         * removed. */
        flags = address->flags & ~IFA_F_TENTATIVE;
        r = sd_rtnl_message_addr_set_flags(m, flags & 0xff);
        if (r < 0)
                return r;

        if ((flags & ~0xff) != 0) {
                r = sd_netlink_message_append_u32(m, IFA_FLAGS, flags);
                if (r < 0)
                        return r;
        }

        r = netlink_message_append_in_addr_union(m, IFA_LOCAL, address->family, &address->in_addr);
        if (r < 0)
                return r;

        return 0;
}

static int address_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, RemoveRequest *rreq) {
        int r;

        assert(m);
        assert(rreq);

        Link *link = ASSERT_PTR(rreq->link);
        Address *address = ASSERT_PTR(rreq->userdata);

        if (link->state == LINK_STATE_LINGER)
                return 0;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_link_message_full_errno(link, m,
                                            (r == -EADDRNOTAVAIL || !address->link) ? LOG_DEBUG : LOG_WARNING,
                                            r, "Could not drop address");

                if (address->link) {
                        /* If the address cannot be removed, then assume the address is already removed. */
                        log_address_debug(address, "Forgetting", link);

                        Request *req;
                        if (address_get_request(link, address, &req) >= 0)
                                address_enter_removed(req->userdata);

                        (void) address_drop(address);
                }
        }

        return 1;
}

int address_remove(Address *address) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        Request *req;
        Link *link;
        int r;

        assert(address);
        assert(IN_SET(address->family, AF_INET, AF_INET6));
        assert(address->link);
        assert(address->link->ifindex > 0);
        assert(address->link->manager);
        assert(address->link->manager->rtnl);

        link = address->link;

        log_address_debug(address, "Removing", link);

        r = sd_rtnl_message_new_addr(link->manager->rtnl, &m, RTM_DELADDR,
                                     link->ifindex, address->family);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not allocate RTM_DELADDR message: %m");

        r = address_set_netlink_message(address, m, link);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not set netlink attributes: %m");

        r = link_remove_request_add(link, address, address, link->manager->rtnl, m, address_remove_handler);
        if (r < 0)
                return log_link_warning_errno(link, r, "Could not queue rtnetlink message: %m");

        address_enter_removing(address);
        if (address_get_request(link, address, &req) >= 0)
                address_enter_removing(req->userdata);

        /* The operational state is determined by address state and carrier state. Hence, if we remove
         * an address, the operational state may be changed. */
        link_update_operstate(link, true);
        return 0;
}

int address_remove_and_drop(Address *address) {
        if (!address)
                return 0;

        address_cancel_request(address);

        if (address_exists(address))
                return address_remove(address);

        return address_drop(address);
}

bool link_address_is_dynamic(const Link *link, const Address *address) {
        Route *route;

        assert(link);
        assert(address);

        if (address->lifetime_preferred_usec != USEC_INFINITY)
                return true;

        /* Even when the address is leased from a DHCP server, networkd assign the address
         * without lifetime when KeepConfiguration=dhcp. So, let's check that we have
         * corresponding routes with RTPROT_DHCP. */
        SET_FOREACH(route, link->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_FOREIGN)
                        continue;

                /* The route is not assigned yet, or already removed. Ignoring. */
                if (!route_exists(route))
                        continue;

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

        if (link_may_have_ipv6ll(link, /* check_multicast = */ false))
                return 0;

        r = sd_rtnl_message_new_addr(link->manager->rtnl, &req, RTM_GETADDR, link->ifindex, AF_INET6);
        if (r < 0)
                return r;

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(link->manager->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *addr = reply; addr; addr = sd_netlink_message_next(addr)) {
                _cleanup_(address_unrefp) Address *a = NULL;
                unsigned char flags, prefixlen;
                struct in6_addr address;
                Address *existing;
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

                if (address_get(link, a, &existing) < 0) {
                        r = address_add(link, a);
                        if (r < 0)
                                return r;

                        existing = TAKE_PTR(a);
                }

                r = address_remove(existing);
                if (r < 0)
                        return r;
        }

        return 0;
}

int link_drop_foreign_addresses(Link *link) {
        Address *address;
        int r = 0;

        assert(link);
        assert(link->network);

        /* First, mark all addresses. */
        SET_FOREACH(address, link->addresses) {
                /* We consider IPv6LL addresses to be managed by the kernel, or dropped in link_drop_ipv6ll_addresses() */
                if (address->family == AF_INET6 && in6_addr_is_link_local(&address->in_addr.in6))
                        continue;

                /* Do not remove localhost address (127.0.0.1 and ::1) */
                if (link->flags & IFF_LOOPBACK && in_addr_is_localhost_one(address->family, &address->in_addr) > 0)
                        continue;

                /* Ignore addresses we configured. */
                if (address->source != NETWORK_CONFIG_SOURCE_FOREIGN)
                        continue;

                /* Ignore addresses not assigned yet or already removing. */
                if (!address_exists(address))
                        continue;

                /* link_address_is_dynamic() is slightly heavy. Let's call the function only when KeepConfiguration= is set. */
                if (IN_SET(link->network->keep_configuration, KEEP_CONFIGURATION_DHCP, KEEP_CONFIGURATION_STATIC) &&
                    link_address_is_dynamic(link, address) == (link->network->keep_configuration == KEEP_CONFIGURATION_DHCP))
                        continue;

                address_mark(address);
        }

        /* Then, unmark requested addresses. */
        ORDERED_HASHMAP_FOREACH(address, link->network->addresses_by_section) {
                Address *existing;

                if (address_get(link, address, &existing) < 0)
                        continue;

                if (!address_can_update(existing, address))
                        continue;

                /* Found matching static configuration. Keep the existing address. */
                address_unmark(existing);
        }

        /* Finally, remove all marked addresses. */
        SET_FOREACH(address, link->addresses) {
                if (!address_is_marked(address))
                        continue;

                RET_GATHER(r, address_remove(address));
        }

        return r;
}

int link_drop_managed_addresses(Link *link) {
        Address *address;
        int r = 0;

        assert(link);

        SET_FOREACH(address, link->addresses) {
                /* Do not touch addresses managed by kernel or other tools. */
                if (address->source == NETWORK_CONFIG_SOURCE_FOREIGN)
                        continue;

                /* Ignore addresses not assigned yet or already removing. */
                if (!address_exists(address))
                        continue;

                RET_GATHER(r, address_remove(address));
        }

        return r;
}

void link_foreignize_addresses(Link *link) {
        Address *address;

        assert(link);

        SET_FOREACH(address, link->addresses)
                address->source = NETWORK_CONFIG_SOURCE_FOREIGN;
}

static int address_acquire(Link *link, const Address *original, Address **ret) {
        _cleanup_(address_unrefp) Address *na = NULL;
        union in_addr_union in_addr;
        int r;

        assert(link);
        assert(original);
        assert(ret);

        /* Something useful was configured? just use it */
        if (in_addr_is_set(original->family, &original->in_addr))
                return address_dup(original, ret);

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

        *ret = TAKE_PTR(na);
        return 0;
}

int address_configure_handler_internal(sd_netlink *rtnl, sd_netlink_message *m, Link *link, const char *error_msg) {
        int r;

        assert(rtnl);
        assert(m);
        assert(link);
        assert(error_msg);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, error_msg);
                link_enter_failed(link);
                return 0;
        }

        return 1;
}

static int address_configure(const Address *address, const struct ifa_cacheinfo *c, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(address);
        assert(IN_SET(address->family, AF_INET, AF_INET6));
        assert(c);
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(req);

        log_address_debug(address, "Configuring", link);

        r = sd_rtnl_message_new_addr_update(link->manager->rtnl, &m, link->ifindex, address->family);
        if (r < 0)
                return r;

        r = address_set_netlink_message(address, m, link);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_scope(m, address->scope);
        if (r < 0)
                return r;

        if (address->family == AF_INET6 || in_addr_is_set(address->family, &address->in_addr_peer)) {
                r = netlink_message_append_in_addr_union(m, IFA_ADDRESS, address->family, &address->in_addr_peer);
                if (r < 0)
                        return r;
        } else if (in4_addr_is_set(&address->broadcast)) {
                r = sd_netlink_message_append_in_addr(m, IFA_BROADCAST, &address->broadcast);
                if (r < 0)
                        return r;
        }

        if (address->family == AF_INET && address->label) {
                r = sd_netlink_message_append_string(m, IFA_LABEL, address->label);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_cache_info(m, IFA_CACHEINFO, c);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, IFA_RT_PRIORITY, address->route_metric);
        if (r < 0)
                return r;

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static bool address_is_ready_to_configure(Link *link, const Address *address) {
        assert(link);
        assert(address);

        if (!link_is_ready_to_configure(link, false))
                return false;

        if (!ipv4acd_bound(link, address))
                return false;

        /* Refuse adding more than the limit */
        if (set_size(link->addresses) >= ADDRESSES_PER_LINK_MAX)
                return false;

        return true;
}

static int address_process_request(Request *req, Link *link, Address *address) {
        Address *existing;
        struct ifa_cacheinfo c;
        int r;

        assert(req);
        assert(link);
        assert(address);

        if (!address_is_ready_to_configure(link, address))
                return 0;

        address_set_cinfo(link->manager, address, &c);
        if (c.ifa_valid == 0) {
                log_link_debug(link, "Refuse to configure %s address %s, as its valid lifetime is zero.",
                               network_config_source_to_string(address->source),
                               IN_ADDR_PREFIX_TO_STRING(address->family, &address->in_addr, address->prefixlen));

                address_cancel_requesting(address);
                if (address_get(link, address, &existing) >= 0)
                        address_cancel_requesting(existing);
                return 1;
        }

        r = address_configure(address, &c, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure address: %m");

        address_enter_configuring(address);
        if (address_get(link, address, &existing) >= 0)
                address_enter_configuring(existing);

        return 1;
}

int link_request_address(
                Link *link,
                const Address *address,
                unsigned *message_counter,
                address_netlink_handler_t netlink_handler,
                Request **ret) {

        _cleanup_(address_unrefp) Address *tmp = NULL;
        Address *existing = NULL;
        int r;

        assert(link);
        assert(address);
        assert(address->source != NETWORK_CONFIG_SOURCE_FOREIGN);

        if (address->lifetime_valid_usec == 0)
                /* The requested address is outdated. Let's ignore the request. */
                return 0;

        if (address_get(link, address, &existing) < 0) {
                if (address_get_request(link, address, NULL) >= 0)
                        return 0; /* already requested, skipping. */

                r = address_acquire(link, address, &tmp);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to acquire an address from pool: %m");

                /* Consider address tentative until we get the real flags from the kernel */
                tmp->flags |= IFA_F_TENTATIVE;

        } else {
                r = address_dup(address, &tmp);
                if (r < 0)
                        return log_oom();

                /* Copy already assigned address when it is requested as a null address. */
                if (address_is_static_null(address))
                        tmp->in_addr = existing->in_addr;

                /* Copy state for logging below. */
                tmp->state = existing->state;
        }

        address_set_broadcast(tmp, link);

        r = ipv4acd_configure(link, tmp);
        if (r < 0)
                return r;

        log_address_debug(tmp, "Requesting", link);
        r = link_queue_request_safe(link, REQUEST_TYPE_ADDRESS,
                                    tmp,
                                    address_unref,
                                    address_hash_func,
                                    address_compare_func,
                                    address_process_request,
                                    message_counter, netlink_handler, ret);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to request address: %m");
        if (r == 0)
                return 0;

        address_enter_requesting(tmp);
        if (existing)
                address_enter_requesting(existing);

        TAKE_PTR(tmp);
        return 1;
}

static int static_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Address *address) {
        int r;

        assert(link);

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

int link_request_static_address(Link *link, const Address *address) {
        assert(link);
        assert(address);
        assert(address->source == NETWORK_CONFIG_SOURCE_STATIC);

        return link_request_address(link, address, &link->static_address_messages,
                                    static_address_handler, NULL);
}

int link_request_static_addresses(Link *link) {
        Address *a;
        int r;

        assert(link);
        assert(link->network);

        link->static_addresses_configured = false;

        ORDERED_HASHMAP_FOREACH(a, link->network->addresses_by_section) {
                r = link_request_static_address(link, a);
                if (r < 0)
                        return r;
        }

        r = link_request_radv_addresses(link);
        if (r < 0)
                return r;

        if (link->static_address_messages == 0) {
                link->static_addresses_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting addresses");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

void address_cancel_request(Address *address) {
        Request req;

        assert(address);
        assert(address->link);

        if (!address_is_requesting(address))
                return;

        req = (Request) {
                .link = address->link,
                .type = REQUEST_TYPE_ADDRESS,
                .userdata = address,
                .hash_func = (hash_func_t) address_hash_func,
                .compare_func = (compare_func_t) address_compare_func,
        };

        request_detach(address->link->manager, &req);
        address_cancel_requesting(address);
}

int manager_rtnl_process_address(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(address_unrefp) Address *tmp = NULL;
        struct ifa_cacheinfo cinfo;
        Link *link;
        uint16_t type;
        Address *address = NULL;
        Request *req = NULL;
        bool is_new = false, update_dhcp4;
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
        if (r < 0) {
                /* when enumerating we might be out of sync, but we will get the address again, so just
                 * ignore it */
                if (!m->enumerating)
                        log_warning("rtnl: received address for link '%d' we don't know about, ignoring.", ifindex);
                return 0;
        }

        r = address_new(&tmp);
        if (r < 0)
                return log_oom();

        /* First, read minimal information to make address_get() work below. */

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
                assert_not_reached();
        }

        update_dhcp4 = tmp->family == AF_INET6;

        /* Then, find the managed Address and Request objects corresponding to the received address. */
        (void) address_get(link, tmp, &address);
        (void) address_get_request(link, tmp, &req);

        if (type == RTM_DELADDR) {
                if (address) {
                        address_enter_removed(address);
                        log_address_debug(address, "Forgetting removed", link);
                        (void) address_drop(address);
                } else
                        log_address_debug(tmp, "Kernel removed unknown", link);

                if (req)
                        address_enter_removed(req->userdata);

                goto finalize;
        }

        if (!address) {
                /* If we did not know the address, then save it. */
                r = address_add(link, tmp);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Failed to save received address %s, ignoring: %m",
                                               IN_ADDR_PREFIX_TO_STRING(tmp->family, &tmp->in_addr, tmp->prefixlen));
                        return 0;
                }
                address = TAKE_PTR(tmp);

                is_new = true;

        } else {
                /* Otherwise, update the managed Address object with the netlink notification. */
                address->prefixlen = tmp->prefixlen;
                address->in_addr_peer = tmp->in_addr_peer;
        }

        /* Also update information that cannot be obtained through netlink notification. */
        if (req && req->waiting_reply) {
                Address *a = ASSERT_PTR(req->userdata);

                address->source = a->source;
                address->provider = a->provider;
                (void) free_and_strdup_warn(&address->netlabel, a->netlabel);
                nft_set_context_clear(&address->nft_set_context);
                (void) nft_set_context_dup(&a->nft_set_context, &address->nft_set_context);
                address->requested_as_null = a->requested_as_null;
                address->callback = a->callback;
        }

        /* Then, update miscellaneous info. */
        r = sd_rtnl_message_addr_get_scope(message, &address->scope);
        if (r < 0)
                log_link_debug_errno(link, r, "rtnl: received address message without scope, ignoring: %m");

        if (address->family == AF_INET) {
                _cleanup_free_ char *label = NULL;

                r = sd_netlink_message_read_string_strdup(message, IFA_LABEL, &label);
                if (r >= 0) {
                        if (!streq_ptr(label, link->ifname))
                                free_and_replace(address->label, label);
                } else if (r != -ENODATA)
                        log_link_debug_errno(link, r, "rtnl: could not get label from address message, ignoring: %m");

                r = sd_netlink_message_read_in_addr(message, IFA_BROADCAST, &address->broadcast);
                if (r < 0 && r != -ENODATA)
                        log_link_debug_errno(link, r, "rtnl: could not get broadcast from address message, ignoring: %m");
        }

        r = sd_netlink_message_read_u32(message, IFA_FLAGS, &address->flags);
        if (r == -ENODATA) {
                unsigned char flags;

                /* For old kernels. */
                r = sd_rtnl_message_addr_get_flags(message, &flags);
                if (r >= 0)
                        address->flags = flags;
        } else if (r < 0)
                log_link_debug_errno(link, r, "rtnl: failed to read IFA_FLAGS attribute, ignoring: %m");

        r = sd_netlink_message_read_cache_info(message, IFA_CACHEINFO, &cinfo);
        if (r >= 0)
                address_set_lifetime(m, address, &cinfo);
        else if (r != -ENODATA)
                log_link_debug_errno(link, r, "rtnl: failed to read IFA_CACHEINFO attribute, ignoring: %m");

        r = sd_netlink_message_read_u32(message, IFA_RT_PRIORITY, &address->route_metric);
        if (r < 0 && r != -ENODATA)
                log_link_debug_errno(link, r, "rtnl: failed to read IFA_RT_PRIORITY attribute, ignoring: %m");

        address_enter_configured(address);
        if (req)
                address_enter_configured(req->userdata);

        log_address_debug(address, is_new ? "Received new": "Received updated", link);

        /* address_update() logs internally, so we don't need to here. */
        r = address_update(address);
        if (r < 0)
                link_enter_failed(link);

finalize:
        if (update_dhcp4) {
                r = dhcp4_update_ipv6_connectivity(link);
                if (r < 0) {
                        log_link_warning_errno(link, r, "Failed to notify IPv6 connectivity to DHCPv4 client: %m");
                        link_enter_failed(link);
                }
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
        _cleanup_(address_unref_or_set_invalidp) Address *n = NULL;
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
        _cleanup_(address_unref_or_set_invalidp) Address *n = NULL;
        union in_addr_union buffer;
        unsigned char prefixlen;
        int r, f;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(section, "Network")) {
                if (isempty(rvalue)) {
                        /* If an empty string specified in [Network] section, clear previously assigned addresses. */
                        network->addresses_by_section = ordered_hashmap_free(network->addresses_by_section);
                        return 0;
                }

                /* we are not in an Address section, so use line number instead. */
                r = address_new_static(network, filename, line, &n);
        } else
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
                r = in_addr_prefix_from_string_auto(rvalue, &f, &buffer, &prefixlen);
                if (r >= 0)
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Address '%s' is specified without prefix length. Assuming the prefix length is %u. "
                                   "Please specify the prefix length explicitly.", rvalue, prefixlen);
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

        if (streq(lvalue, "Address")) {
                n->in_addr = buffer;
                n->requested_as_null = !in_addr_is_set(n->family, &n->in_addr);
        } else
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

        _cleanup_(address_unref_or_set_invalidp) Address *n = NULL;
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

        if (isempty(rvalue)) {
                n->label = mfree(n->label);
                TAKE_PTR(n);
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
        _cleanup_(address_unref_or_set_invalidp) Address *n = NULL;
        usec_t k;
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
                k = USEC_INFINITY;
        else if (streq(rvalue, "0"))
                k = 0;
        else {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid PreferredLifetime= value, ignoring: %s", rvalue);
                return 0;
        }

        n->lifetime_preferred_usec = k;
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
        _cleanup_(address_unref_or_set_invalidp) Address *n = NULL;
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
        _cleanup_(address_unref_or_set_invalidp) Address *n = NULL;
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

        r = route_scope_from_string(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse address scope \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        n->scope = r;
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
        _cleanup_(address_unref_or_set_invalidp) Address *n = NULL;
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
        _cleanup_(address_unref_or_set_invalidp) Address *n = NULL;
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

int config_parse_address_netlabel(
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
        _cleanup_(address_unref_or_set_invalidp) Address *n = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);
        assert(network);

        r = address_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate new address, ignoring assignment: %m");
                return 0;
        }

        r = config_parse_string(unit, filename, line, section, section_line,
                                lvalue, CONFIG_PARSE_STRING_SAFE, rvalue, &n->netlabel, network);
        if (r < 0)
                return r;

        TAKE_PTR(n);
        return 0;
}

static void address_section_adjust_broadcast(Address *address) {
        assert(address);
        assert(address->section);

        if (!in4_addr_is_set(&address->broadcast))
                return;

        if (address->family == AF_INET6)
                log_warning("%s: broadcast address is set for an IPv6 address. "
                            "Ignoring Broadcast= setting in the [Address] section from line %u.",
                            address->section->filename, address->section->line);
        else if (address->prefixlen > 30)
                log_warning("%s: broadcast address is set for an IPv4 address with prefix length larger than 30. "
                            "Ignoring Broadcast= setting in the [Address] section from line %u.",
                            address->section->filename, address->section->line);
        else if (in4_addr_is_set(&address->in_addr_peer.in))
                log_warning("%s: broadcast address is set for an IPv4 address with peer address. "
                            "Ignoring Broadcast= setting in the [Address] section from line %u.",
                            address->section->filename, address->section->line);
        else if (!in4_addr_is_set(&address->in_addr.in))
                log_warning("%s: broadcast address is set for an IPv4 address with null address. "
                            "Ignoring Broadcast= setting in the [Address] section from line %u.",
                            address->section->filename, address->section->line);
        else
                /* Otherwise, keep the specified broadcast address. */
                return;

        address->broadcast.s_addr = 0;
}

int address_section_verify(Address *address) {
        if (section_is_invalid(address->section))
                return -EINVAL;

        if (address->family == AF_UNSPEC) {
                assert(address->section);

                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Address section without Address= field was configured. "
                                         "Ignoring [Address] section from line %u.",
                                         address->section->filename, address->section->line);
        }

        if (address->family == AF_INET6 && !socket_ipv6_is_supported())
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: an IPv6 address was configured, but the kernel does not support IPv6. "
                                         "Ignoring [Address] section from line %u.",
                                         address->section->filename, address->section->line);

        assert(IN_SET(address->family, AF_INET, AF_INET6));

        address_section_adjust_broadcast(address);

        if (address->family == AF_INET6 && address->label) {
                log_warning("%s: address label is set for IPv6 address in the [Address] section from line %u. "
                            "Ignoring Label= setting.",
                            address->section->filename, address->section->line);

                address->label = mfree(address->label);
        }

        if (!address->scope_set) {
                if (in_addr_is_localhost(address->family, &address->in_addr) > 0)
                        address->scope = RT_SCOPE_HOST;
                else if (in_addr_is_link_local(address->family, &address->in_addr) > 0)
                        address->scope = RT_SCOPE_LINK;
        }

        if (address->duplicate_address_detection < 0) {
                if (address->family == AF_INET6)
                        address->duplicate_address_detection = ADDRESS_FAMILY_IPV6;
                else if (in4_addr_is_link_local(&address->in_addr.in))
                        address->duplicate_address_detection = ADDRESS_FAMILY_IPV4;
                else
                        address->duplicate_address_detection = ADDRESS_FAMILY_NO;
        } else if (address->duplicate_address_detection == ADDRESS_FAMILY_IPV6 && address->family == AF_INET)
                log_warning("%s: DuplicateAddressDetection=ipv6 is specified for IPv4 address, ignoring.",
                            address->section->filename);
        else if (address->duplicate_address_detection == ADDRESS_FAMILY_IPV4 && address->family == AF_INET6)
                log_warning("%s: DuplicateAddressDetection=ipv4 is specified for IPv6 address, ignoring.",
                            address->section->filename);

        if (address->family == AF_INET6 &&
            !FLAGS_SET(address->duplicate_address_detection, ADDRESS_FAMILY_IPV6))
                address->flags |= IFA_F_NODAD;

        uint32_t filtered_flags = address->family == AF_INET ?
                address->flags & KNOWN_FLAGS & ~UNMANAGED_FLAGS & ~IPV6ONLY_FLAGS :
                address->flags & KNOWN_FLAGS & ~UNMANAGED_FLAGS;
        if (address->flags != filtered_flags) {
                _cleanup_free_ char *str = NULL;

                (void) address_flags_to_string_alloc(address->flags ^ filtered_flags, address->family, &str);
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: unexpected address flags \"%s\" were configured. "
                                         "Ignoring [Address] section from line %u.",
                                         address->section->filename, strna(str), address->section->line);
        }

        return 0;
}

int network_drop_invalid_addresses(Network *network) {
        _cleanup_set_free_ Set *addresses = NULL;
        Address *address;
        int r;

        assert(network);

        ORDERED_HASHMAP_FOREACH(address, network->addresses_by_section) {
                Address *dup;

                if (address_section_verify(address) < 0) {
                        /* Drop invalid [Address] sections or Address= settings in [Network].
                         * Note that address_detach() will drop the address from addresses_by_section. */
                        address_detach(address);
                        continue;
                }

                /* Always use the setting specified later. So, remove the previously assigned setting. */
                dup = set_remove(addresses, address);
                if (dup) {
                        log_warning("%s: Duplicated address %s is specified at line %u and %u, "
                                    "dropping the address setting specified at line %u.",
                                    dup->section->filename,
                                    IN_ADDR_PREFIX_TO_STRING(address->family, &address->in_addr, address->prefixlen),
                                    address->section->line,
                                    dup->section->line, dup->section->line);

                        /* address_detach() will drop the address from addresses_by_section. */
                        address_detach(dup);
                }

                /* Use address_hash_ops, instead of address_hash_ops_detach. Otherwise, the Address objects
                 * will be detached. */
                r = set_ensure_put(&addresses, &address_hash_ops, address);
                if (r < 0)
                        return log_oom();
                assert(r > 0);
        }

        r = network_adjust_dhcp_server(network, &addresses);
        if (r < 0)
                return r;

        return 0;
}

int config_parse_address_ip_nft_set(
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
        _cleanup_(address_unref_or_set_invalidp) Address *n = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(network);

        r = address_new_static(network, filename, section_line, &n);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to allocate a new address, ignoring assignment: %m");
                return 0;
        }

        r = config_parse_nft_set(unit, filename, line, section, section_line, lvalue, ltype, rvalue, &n->nft_set_context, network);
        if (r < 0)
                return r;

        TAKE_PTR(n);
        return 0;
}
