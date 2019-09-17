/* SPDX-License-Identifier: LGPL-2.1+ */

#include <net/if.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "firewall-util.h"
#include "memory-util.h"
#include "missing_network.h"
#include "netlink-util.h"
#include "networkd-address.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "set.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

#define ADDRESSES_PER_LINK_MAX 2048U
#define STATIC_ADDRESSES_PER_NETWORK_MAX 1024U

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
        assert(!!filename == (section_line > 0));

        if (filename) {
                r = network_config_section_new(filename, section_line, &n);
                if (r < 0)
                        return r;

                address = hashmap_get(network->addresses_by_section, n);
                if (address) {
                        *ret = TAKE_PTR(address);

                        return 0;
                }
        }

        if (network->n_static_addresses >= STATIC_ADDRESSES_PER_NETWORK_MAX)
                return -E2BIG;

        r = address_new(&address);
        if (r < 0)
                return r;

        address->network = network;
        LIST_APPEND(addresses, network->static_addresses, address);
        network->n_static_addresses++;

        if (filename) {
                address->section = TAKE_PTR(n);

                r = hashmap_ensure_allocated(&network->addresses_by_section, &network_config_hash_ops);
                if (r < 0)
                        return r;

                r = hashmap_put(network->addresses_by_section, address->section, address);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(address);

        return 0;
}

void address_free(Address *address) {
        if (!address)
                return;

        if (address->network) {
                LIST_REMOVE(addresses, address->network->static_addresses, address);
                assert(address->network->n_static_addresses > 0);
                address->network->n_static_addresses--;

                if (address->section)
                        hashmap_remove(address->network->addresses_by_section, address->section);
        }

        if (address->link) {
                set_remove(address->link->addresses, address);
                set_remove(address->link->addresses_foreign, address);

                if (in_addr_equal(AF_INET6, &address->in_addr, (const union in_addr_union *) &address->link->ipv6ll_address))
                        memzero(&address->link->ipv6ll_address, sizeof(struct in6_addr));
        }

        network_config_section_free(address->section);
        free(address->label);
        free(address);
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

static void address_hash_func(const Address *a, struct siphash *state) {
        assert(a);

        siphash24_compress(&a->family, sizeof(a->family), state);

        switch (a->family) {
        case AF_INET:
                siphash24_compress(&a->prefixlen, sizeof(a->prefixlen), state);

                /* peer prefix */
                uint32_t prefix = address_prefix(a);
                siphash24_compress(&prefix, sizeof(prefix), state);

                _fallthrough_;
        case AF_INET6:
                /* local address */
                siphash24_compress(&a->in_addr, FAMILY_ADDRESS_SIZE(a->family), state);

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
        /* use the same notion of equality as the kernel does */
        case AF_INET:
                r = CMP(a1->prefixlen, a2->prefixlen);
                if (r != 0)
                        return r;

                uint32_t prefix1 = address_prefix(a1);
                uint32_t prefix2 = address_prefix(a2);
                r = CMP(prefix1, prefix2);
                if (r != 0)
                        return r;

                _fallthrough_;
        case AF_INET6:
                return memcmp(&a1->in_addr, &a2->in_addr, FAMILY_ADDRESS_SIZE(a1->family));
        default:
                /* treat any other address family as AF_UNSPEC */
                return 0;
        }
}

DEFINE_PRIVATE_HASH_OPS(address_hash_ops, Address, address_hash_func, address_compare_func);

bool address_equal(Address *a1, Address *a2) {
        if (a1 == a2)
                return true;

        if (!a1 || !a2)
                return false;

        return address_compare_func(a1, a2) == 0;
}

static int address_establish(Address *address, Link *link) {
        bool masq;
        int r;

        assert(address);
        assert(link);

        masq = link->network &&
               link->network->ip_masquerade &&
               address->family == AF_INET &&
               address->scope < RT_SCOPE_LINK;

        /* Add firewall entry if this is requested */
        if (address->ip_masquerade_done != masq) {
                union in_addr_union masked = address->in_addr;
                in_addr_mask(address->family, &masked, address->prefixlen);

                r = fw_add_masquerade(masq, AF_INET, 0, &masked, address->prefixlen, NULL, NULL, 0);
                if (r < 0)
                        return r;

                address->ip_masquerade_done = masq;
        }

        return 0;
}

static int address_add_internal(Link *link, Set **addresses,
                                int family,
                                const union in_addr_union *in_addr,
                                unsigned char prefixlen,
                                Address **ret) {
        _cleanup_(address_freep) Address *address = NULL;
        int r;

        assert(link);
        assert(addresses);
        assert(in_addr);

        r = address_new(&address);
        if (r < 0)
                return r;

        address->family = family;
        address->in_addr = *in_addr;
        address->prefixlen = prefixlen;
        /* Consider address tentative until we get the real flags from the kernel */
        address->flags = IFA_F_TENTATIVE;

        r = set_ensure_allocated(addresses, &address_hash_ops);
        if (r < 0)
                return r;

        r = set_put(*addresses, address);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        address->link = link;

        if (ret)
                *ret = address;

        address = NULL;

        return 0;
}

int address_add_foreign(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret) {
        return address_add_internal(link, &link->addresses_foreign, family, in_addr, prefixlen, ret);
}

int address_add(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret) {
        Address *address;
        int r;

        r = address_get(link, family, in_addr, prefixlen, &address);
        if (r == -ENOENT) {
                /* Address does not exist, create a new one */
                r = address_add_internal(link, &link->addresses, family, in_addr, prefixlen, &address);
                if (r < 0)
                        return r;
        } else if (r == 0) {
                /* Take over a foreign address */
                r = set_ensure_allocated(&link->addresses, &address_hash_ops);
                if (r < 0)
                        return r;

                r = set_put(link->addresses, address);
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

static int address_release(Address *address) {
        int r;

        assert(address);
        assert(address->link);

        /* Remove masquerading firewall entry if it was added */
        if (address->ip_masquerade_done) {
                union in_addr_union masked = address->in_addr;
                in_addr_mask(address->family, &masked, address->prefixlen);

                r = fw_add_masquerade(false, AF_INET, 0, &masked, address->prefixlen, NULL, NULL, 0);
                if (r < 0)
                        return r;

                address->ip_masquerade_done = false;
        }

        return 0;
}

int address_update(
                Address *address,
                unsigned char flags,
                unsigned char scope,
                const struct ifa_cacheinfo *cinfo) {

        bool ready;
        int r;

        assert(address);
        assert(cinfo);
        assert_return(address->link, 1);

        if (IN_SET(address->link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        ready = address_is_ready(address);

        address->flags = flags;
        address->scope = scope;
        address->cinfo = *cinfo;

        link_update_operstate(address->link, true);
        link_check_ready(address->link);

        if (!ready &&
            address_is_ready(address) &&
            address->family == AF_INET6 &&
            in_addr_is_link_local(AF_INET6, &address->in_addr) > 0 &&
            in_addr_is_null(AF_INET6, (const union in_addr_union*) &address->link->ipv6ll_address) > 0) {

                r = link_ipv6ll_gained(address->link, &address->in_addr.in6);
                if (r < 0)
                        return r;
        }

        return 0;
}

int address_drop(Address *address) {
        Link *link;
        bool ready;
        int r;

        assert(address);

        ready = address_is_ready(address);
        link = address->link;

        r = address_release(address);
        if (r < 0)
                log_link_warning_errno(link, r, "Failed to disable IP masquerading, ignoring: %m");

        address_free(address);

        link_update_operstate(link, true);

        if (link && !ready)
                link_check_ready(link);

        return 0;
}

int address_get(Link *link,
                int family,
                const union in_addr_union *in_addr,
                unsigned char prefixlen,
                Address **ret) {

        Address address, *existing;

        assert(link);
        assert(in_addr);

        address = (Address) {
                .family = family,
                .in_addr = *in_addr,
                .prefixlen = prefixlen,
        };

        existing = set_get(link->addresses, &address);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 1;
        }

        existing = set_get(link->addresses_foreign, &address);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 0;
        }

        return -ENOENT;
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
                log_link_warning_errno(link, r, "Could not drop address: %m");

        return 1;
}

int address_remove(
                Address *address,
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

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *b = NULL;

                (void) in_addr_to_string(address->family, &address->in_addr, &b);
                log_link_debug(link, "Removing address %s", strna(b));
        }

        r = sd_rtnl_message_new_addr(link->manager->rtnl, &req, RTM_DELADDR,
                                     link->ifindex, address->family);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_DELADDR message: %m");

        r = sd_rtnl_message_addr_set_prefixlen(req, address->prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set prefixlen: %m");

        r = netlink_message_append_in_addr_union(req, IFA_LOCAL, address->family, &address->in_addr);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFA_LOCAL attribute: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req,
                               callback ?: address_remove_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static int address_acquire(Link *link, Address *original, Address **ret) {
        union in_addr_union in_addr = IN_ADDR_NULL;
        struct in_addr broadcast = {};
        _cleanup_(address_freep) Address *na = NULL;
        int r;

        assert(link);
        assert(original);
        assert(ret);

        /* Something useful was configured? just use it */
        r = in_addr_is_null(original->family, &original->in_addr);
        if (r <= 0)
                return r;

        /* The address is configured to be 0.0.0.0 or [::] by the user?
         * Then let's acquire something more useful from the pool. */
        r = manager_address_pool_acquire(link->manager, original->family, original->prefixlen, &in_addr);
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

        na->family = original->family;
        na->prefixlen = original->prefixlen;
        na->scope = original->scope;
        na->cinfo = original->cinfo;

        if (original->label) {
                na->label = strdup(original->label);
                if (!na->label)
                        return -ENOMEM;
        }

        na->broadcast = broadcast;
        na->in_addr = in_addr;

        LIST_PREPEND(addresses, link->pool_addresses, na);

        *ret = TAKE_PTR(na);

        return 0;
}

int address_configure(
                Address *address,
                Link *link,
                link_netlink_message_handler_t callback,
                bool update) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(address);
        assert(IN_SET(address->family, AF_INET, AF_INET6));
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(callback);

        /* If this is a new address, then refuse adding more than the limit */
        if (address_get(link, address->family, &address->in_addr, address->prefixlen, NULL) <= 0 &&
            set_size(link->addresses) >= ADDRESSES_PER_LINK_MAX)
                return log_link_error_errno(link, SYNTHETIC_ERRNO(E2BIG),
                                            "Too many addresses are configured, refusing: %m");

        r = address_acquire(link, address, &address);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to acquire an address from pool: %m");

        if (update)
                r = sd_rtnl_message_new_addr_update(link->manager->rtnl, &req,
                                                    link->ifindex, address->family);
        else
                r = sd_rtnl_message_new_addr(link->manager->rtnl, &req, RTM_NEWADDR,
                                             link->ifindex, address->family);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_NEWADDR message: %m");

        r = sd_rtnl_message_addr_set_prefixlen(req, address->prefixlen);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set prefixlen: %m");

        address->flags |= IFA_F_PERMANENT;

        if (address->home_address)
                address->flags |= IFA_F_HOMEADDRESS;

        if (address->duplicate_address_detection)
                address->flags |= IFA_F_NODAD;

        if (address->manage_temporary_address)
                address->flags |= IFA_F_MANAGETEMPADDR;

        if (address->prefix_route)
                address->flags |= IFA_F_NOPREFIXROUTE;

        if (address->autojoin)
                address->flags |= IFA_F_MCAUTOJOIN;

        r = sd_rtnl_message_addr_set_flags(req, (address->flags & 0xff));
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set flags: %m");

        if (address->flags & ~0xff) {
                r = sd_netlink_message_append_u32(req, IFA_FLAGS, address->flags);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set extended flags: %m");
        }

        r = sd_rtnl_message_addr_set_scope(req, address->scope);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set scope: %m");

        r = netlink_message_append_in_addr_union(req, IFA_LOCAL, address->family, &address->in_addr);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFA_LOCAL attribute: %m");

        if (in_addr_is_null(address->family, &address->in_addr_peer) == 0) {
                r = netlink_message_append_in_addr_union(req, IFA_ADDRESS, address->family, &address->in_addr_peer);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFA_ADDRESS attribute: %m");
        } else if (address->family == AF_INET && address->prefixlen <= 30) {
                r = sd_netlink_message_append_in_addr(req, IFA_BROADCAST, &address->broadcast);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFA_BROADCAST attribute: %m");
        }

        if (address->label) {
                r = sd_netlink_message_append_string(req, IFA_LABEL, address->label);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFA_LABEL attribute: %m");
        }

        r = sd_netlink_message_append_cache_info(req, IFA_CACHEINFO, &address->cinfo);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append IFA_CACHEINFO attribute: %m");

        r = address_establish(address, link);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not enable IP masquerading, ignoring: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, callback, link_netlink_destroy_callback, link);
        if (r < 0) {
                address_release(address);
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");
        }

        link_ref(link);

        if (address->family == AF_INET6 && !in_addr_is_null(address->family, &address->in_addr_peer))
                r = address_add(link, address->family, &address->in_addr_peer, address->prefixlen, NULL);
        else
                r = address_add(link, address->family, &address->in_addr, address->prefixlen, NULL);
        if (r < 0) {
                address_release(address);
                return log_link_error_errno(link, r, "Could not add address: %m");
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
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = address_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        if (n->family == AF_INET6) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Broadcast is not valid for IPv6 addresses, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = in_addr_from_string(AF_INET, rvalue, (union in_addr_union*) &n->broadcast);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Broadcast is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        n->family = AF_INET;
        n = NULL;

        return 0;
}

int config_parse_address(const char *unit,
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

        if (streq(section, "Network")) {
                /* we are not in an Address section, so treat
                 * this as the special '0' section */
                r = address_new_static(network, NULL, 0, &n);
        } else
                r = address_new_static(network, filename, section_line, &n);

        if (r < 0)
                return r;

        /* Address=address/prefixlen */
        r = in_addr_prefix_from_string_auto_internal(rvalue, PREFIXLEN_REFUSE, &f, &buffer, &prefixlen);
        if (r == -ENOANO) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "An address '%s' is specified without prefix length. "
                           "The behavior of parsing addresses without prefix length will be changed in the future release. "
                           "Please specify prefix length explicitly.", rvalue);

                r = in_addr_prefix_from_string_auto_internal(rvalue, PREFIXLEN_LEGACY, &f, &buffer, &prefixlen);
        }
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Invalid address '%s', ignoring assignment: %m", rvalue);
                return 0;
        }

        if (n->family != AF_UNSPEC && f != n->family) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "Address is incompatible, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (in_addr_is_null(f, &buffer)) {
                /* Will use address from address pool. Note that for ipv6 case, prefix of the address
                 * pool is 8, but 40 bit is used by the global ID and 16 bit by the subnet ID. So,
                 * let's limit the prefix length to 64 or larger. See RFC4193. */
                if ((f == AF_INET && prefixlen < 8) ||
                    (f == AF_INET6 && prefixlen < 64)) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
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

        if (n->family == AF_INET && n->broadcast.s_addr == 0 && n->prefixlen <= 30)
                n->broadcast.s_addr = n->in_addr.in.s_addr | htobe32(0xfffffffflu >> n->prefixlen);

        n = NULL;

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
        if (r < 0)
                return r;

        if (!address_label_valid(rvalue)) {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Interface label is too long or invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = free_and_strdup(&n->label, rvalue);
        if (r < 0)
                return log_oom();

        n = NULL;
        return 0;
}

int config_parse_lifetime(const char *unit,
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
        unsigned k;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = address_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        /* We accept only "forever", "infinity", or "0". */
        if (STR_IN_SET(rvalue, "forever", "infinity"))
                k = CACHE_INFO_INFINITY_LIFE_TIME;
        else if (streq(rvalue, "0"))
                k = 0;
        else {
                log_syntax(unit, LOG_ERR, filename, line, 0,
                           "Invalid PreferredLifetime= value, ignoring: %s", rvalue);
                return 0;
        }

        n->cinfo.ifa_prefered = k;
        n = NULL;

        return 0;
}

int config_parse_address_flags(const char *unit,
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
        if (r < 0)
                return r;

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Failed to parse address flag, ignoring: %s", rvalue);
                return 0;
        }

        if (streq(lvalue, "HomeAddress"))
                n->home_address = r;
        else if (streq(lvalue, "DuplicateAddressDetection"))
                n->duplicate_address_detection = r;
        else if (streq(lvalue, "ManageTemporaryAddress"))
                n->manage_temporary_address = r;
        else if (streq(lvalue, "PrefixRoute"))
                n->prefix_route = r;
        else if (streq(lvalue, "AutoJoin"))
                n->autojoin = r;
        else
                assert_not_reached("Invalid address flag type.");

        n = NULL;
        return 0;
}

int config_parse_address_scope(const char *unit,
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
        if (r < 0)
                return r;

        if (streq(rvalue, "host"))
                n->scope = RT_SCOPE_HOST;
        else if (streq(rvalue, "link"))
                n->scope = RT_SCOPE_LINK;
        else if (streq(rvalue, "global"))
                n->scope = RT_SCOPE_UNIVERSE;
        else {
                r = safe_atou8(rvalue , &n->scope);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Could not parse address scope \"%s\", ignoring assignment: %m", rvalue);
                        return 0;
                }
        }

        n = NULL;
        return 0;
}

bool address_is_ready(const Address *a) {
        assert(a);

        return !(a->flags & IFA_F_TENTATIVE);
}

int address_section_verify(Address *address) {
        if (section_is_invalid(address->section))
                return -EINVAL;

        if (address->family == AF_UNSPEC) {
                assert(address->section);

                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: Address section without Address= field configured. "
                                         "Ignoring [Address] section from line %u.",
                                         address->section->filename, address->section->line);
        }

        return 0;
}
