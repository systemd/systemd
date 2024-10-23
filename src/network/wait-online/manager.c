/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/ether.h>
#include <linux/if.h>
#include <fnmatch.h>

#include "sd-event.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "json-util.h"
#include "link.h"
#include "manager.h"
#include "netlink-util.h"
#include "set.h"
#include "strv.h"
#include "time-util.h"

static bool link_in_command_line_interfaces(Link *link, Manager *m) {
        assert(link);
        assert(m);

        if (hashmap_contains(m->command_line_interfaces_by_name, link->ifname))
                return true;

        STRV_FOREACH(n, link->altnames)
                if (hashmap_contains(m->command_line_interfaces_by_name, *n))
                        return true;

        return false;
}

static bool manager_ignore_link(Manager *m, Link *link) {
        assert(m);
        assert(link);

        /* always ignore the loopback interface */
        if (link->flags & IFF_LOOPBACK)
                return true;

        /* if interfaces are given on the command line, ignore all others */
        if (m->command_line_interfaces_by_name &&
            !link_in_command_line_interfaces(link, m))
                return true;

        if (!link->required_for_online)
                return true;

        /* ignore interfaces we explicitly are asked to ignore */
        if (strv_fnmatch(m->ignored_interfaces, link->ifname))
                return true;

        STRV_FOREACH(n, link->altnames)
                if (strv_fnmatch(m->ignored_interfaces, *n))
                        return true;

        return false;
}

static const LinkOperationalStateRange* get_state_range(Manager *m, Link *l, const LinkOperationalStateRange *from_cmdline) {
        assert(m);
        assert(l);

        const LinkOperationalStateRange *range;
        FOREACH_ARGUMENT(range, from_cmdline, &m->required_operstate, &l->required_operstate)
                if (operational_state_range_is_valid(range))
                        return range;

        /* l->requred_operstate should be always valid. */
        assert_not_reached();
}

static int manager_link_is_online(Manager *m, Link *l, const LinkOperationalStateRange *range) {
        AddressFamily required_family;
        bool needs_ipv4;
        bool needs_ipv6;

        assert(m);
        assert(l);
        assert(range);

        /* This returns the following:
         * -EAGAIN       : not processed by udev
         * -EBUSY        : being processed by networkd
         * -EADDRNOTAVAIL: requested conditions (operstate and/or addresses) are not satisfied
         * false         : unmanaged
         * true          : online */

        if (!l->state || streq(l->state, "pending"))
                /* If no state string exists, networkd (and possibly also udevd) has not detected the
                 * interface yet, that mean we cannot determine whether the interface is managed or
                 * not. Hence, return negative value.
                 * If the link is in pending state, then udevd has not processed the link, and networkd
                 * has not tried to find .network file for the link. Hence, return negative value. */
                return log_link_debug_errno(l, SYNTHETIC_ERRNO(EAGAIN),
                                            "link has not yet been processed by udev: setup state is %s.",
                                            strna(l->state));

        if (streq(l->state, "unmanaged")) {
                /* If the link is in unmanaged state, then ignore the interface unless the interface is
                 * specified in '--interface/-i' option. */
                if (!link_in_command_line_interfaces(l, m)) {
                        log_link_debug(l, "link is not managed by networkd.");
                        return false;
                }

        } else if (!streq(l->state, "configured"))
                /* If the link is in non-configured state, return negative value here. */
                return log_link_debug_errno(l, SYNTHETIC_ERRNO(EBUSY),
                                            "link is being processed by networkd: setup state is %s.",
                                            l->state);

        if (!operational_state_is_in_range(l->operational_state, range))
                return log_link_debug_errno(l, SYNTHETIC_ERRNO(EADDRNOTAVAIL),
                                            "Operational state '%s' is not in range ['%s':'%s']",
                                            link_operstate_to_string(l->operational_state),
                                            link_operstate_to_string(range->min), link_operstate_to_string(range->max));

        required_family = m->required_family > 0 ? m->required_family : l->required_family;
        needs_ipv4 = required_family & ADDRESS_FAMILY_IPV4;
        needs_ipv6 = required_family & ADDRESS_FAMILY_IPV6;

        if (range->min < LINK_OPERSTATE_ROUTABLE) {
                if (needs_ipv4 && l->ipv4_address_state < LINK_ADDRESS_STATE_DEGRADED)
                        return log_link_debug_errno(l, SYNTHETIC_ERRNO(EADDRNOTAVAIL),
                                                    "No routable or link-local IPv4 address is configured.");

                if (needs_ipv6 && l->ipv6_address_state < LINK_ADDRESS_STATE_DEGRADED)
                        return log_link_debug_errno(l, SYNTHETIC_ERRNO(EADDRNOTAVAIL),
                                                    "No routable or link-local IPv6 address is configured.");
        } else {
                if (needs_ipv4 && l->ipv4_address_state < LINK_ADDRESS_STATE_ROUTABLE)
                        return log_link_debug_errno(l, SYNTHETIC_ERRNO(EADDRNOTAVAIL),
                                                    "No routable IPv4 address is configured.");

                if (needs_ipv6 && l->ipv6_address_state < LINK_ADDRESS_STATE_ROUTABLE)
                        return log_link_debug_errno(l, SYNTHETIC_ERRNO(EADDRNOTAVAIL),
                                                    "No routable IPv6 address is configured.");
        }

        if (m->requires_dns) {
                if (l->dns_accessible_address_families == ADDRESS_FAMILY_NO)
                        return log_link_debug_errno(l, SYNTHETIC_ERRNO(EADDRNOTAVAIL),
                                                    "No DNS server is accessible.");

                if (needs_ipv4 && !FLAGS_SET(l->dns_accessible_address_families, ADDRESS_FAMILY_IPV4))
                        return log_link_debug_errno(l, SYNTHETIC_ERRNO(EADDRNOTAVAIL),
                                                    "No IPv4 DNS server is accessible.");

                if (needs_ipv6 && !FLAGS_SET(l->dns_accessible_address_families, ADDRESS_FAMILY_IPV6))
                        return log_link_debug_errno(l, SYNTHETIC_ERRNO(EADDRNOTAVAIL),
                                                    "No IPv6 DNS server is accessible.");
        }

        log_link_debug(l, "link is configured by networkd and online.");
        return true;
}

bool manager_configured(Manager *m) {
        Link *l;
        int r;

        if (!hashmap_isempty(m->command_line_interfaces_by_name)) {
                const LinkOperationalStateRange *range;
                const char *ifname;

                /* wait for all the links given on the command line to appear */
                HASHMAP_FOREACH_KEY(range, ifname, m->command_line_interfaces_by_name) {

                        l = hashmap_get(m->links_by_name, ifname);
                        if (!l) {
                                if (range->min == LINK_OPERSTATE_MISSING) {
                                        if (m->any)
                                                return true;
                                } else {
                                        log_debug("still waiting for %s", ifname);
                                        if (!m->any)
                                                return false;
                                }
                                continue;
                        }

                        range = get_state_range(m, l, range);

                        r = manager_link_is_online(m, l, range);
                        if (r <= 0 && !m->any)
                                return false;
                        if (r > 0 && m->any)
                                return true;
                }

                /* With '--any'   : no interface is ready    → return false
                 * Without '--any': all interfaces are ready → return true */
                return !m->any;
        }

        /* wait for all links networkd manages */
        bool has_online = false;
        HASHMAP_FOREACH(l, m->links_by_index) {
                const LinkOperationalStateRange *range;

                if (manager_ignore_link(m, l)) {
                        log_link_debug(l, "link is ignored");
                        continue;
                }

                range = get_state_range(m, l, /* from_cmdline = */ NULL);

                r = manager_link_is_online(m, l, range);
                /* Unlike the above loop, unmanaged interfaces are ignored here. Also, Configured but offline
                 * interfaces are ignored. See issue #29506. */
                if (r < 0 && r != -EADDRNOTAVAIL && !m->any)
                        return false;
                if (r > 0) {
                        if (m->any)
                                return true;
                        has_online = true;
                }
        }

        /* With '--any'   : no interface is ready → return false
         * Without '--any': all interfaces are ready or unmanaged
         *
         * In this stage, drivers for interfaces may not be loaded yet, and there may be only lo.
         * To avoid that wait-online exits earlier than that drivers are loaded, let's request at least one
         * managed online interface exists. See issue #27822. */
        return !m->any && has_online;
}

static int manager_process_link(sd_netlink *rtnl, sd_netlink_message *mm, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        uint16_t type;
        Link *l;
        const char *ifname;
        int ifindex, r;

        assert(rtnl);
        assert(mm);

        r = sd_netlink_message_get_type(mm, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Could not get message type, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_link_get_ifindex(mm, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Could not get ifindex from link, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received link message with invalid ifindex %d, ignoring", ifindex);
                return 0;
        }

        r = sd_netlink_message_read_string(mm, IFLA_IFNAME, &ifname);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Received link message without ifname, ignoring: %m");
                return 0;
        }

        l = hashmap_get(m->links_by_index, INT_TO_PTR(ifindex));

        switch (type) {

        case RTM_NEWLINK:
                if (!l) {
                        log_debug("Found link %s(%i)", ifname, ifindex);

                        r = link_new(m, &l, ifindex, ifname);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to create link object for %s(%i), ignoring: %m", ifname, ifindex);
                                return 0;
                        }
                }

                r = link_update_rtnl(l, mm);
                if (r < 0)
                        log_link_warning_errno(l, r, "Failed to process RTNL link message, ignoring: %m");

                r = link_update_monitor(l);
                if (r < 0)
                        log_link_full_errno(l, IN_SET(r, -ENODATA, -ENOENT) ? LOG_DEBUG : LOG_WARNING, r,
                                            "Failed to update link state, ignoring: %m");

                break;

        case RTM_DELLINK:
                if (l) {
                        log_link_debug(l, "Removing link");
                        link_free(l);
                }

                break;
        }

        return 0;
}

static int on_rtnl_event(sd_netlink *rtnl, sd_netlink_message *mm, void *userdata) {
        Manager *m = userdata;
        int r;

        r = manager_process_link(rtnl, mm, m);
        if (r < 0)
                return r;

        if (manager_configured(m))
                sd_event_exit(m->event, 0);

        return 1;
}

static int manager_rtnl_listen(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        int r;

        assert(m);

        /* First, subscribe to interfaces coming and going */
        r = sd_netlink_open(&m->rtnl);
        if (r < 0)
                return r;

        r = sd_netlink_attach_event(m->rtnl, m->event, 0);
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_NEWLINK, on_rtnl_event, NULL, m, "wait-online-on-NEWLINK");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_DELLINK, on_rtnl_event, NULL, m, "wait-online-on-DELLINK");
        if (r < 0)
                return r;

        /* Then, enumerate all links */
        r = sd_rtnl_message_new_link(m->rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return r;

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(m->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *i = reply; i; i = sd_netlink_message_next(i)) {
                r = manager_process_link(m->rtnl, i, m);
                if (r < 0)
                        return r;
        }

        return r;
}

static int on_network_event(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        Link *l;
        int r;

        sd_network_monitor_flush(m->network_monitor);

        HASHMAP_FOREACH(l, m->links_by_index) {
                r = link_update_monitor(l);
                if (r < 0)
                        log_link_full_errno(l, IN_SET(r, -ENODATA, -ENOENT) ? LOG_DEBUG : LOG_WARNING, r,
                                            "Failed to update link state, ignoring: %m");
        }

        if (manager_configured(m))
                sd_event_exit(m->event, 0);

        return 0;
}

static int manager_network_monitor_listen(Manager *m) {
        int r, fd, events;

        assert(m);

        r = sd_network_monitor_new(&m->network_monitor, NULL);
        if (r < 0)
                return r;

        fd = sd_network_monitor_get_fd(m->network_monitor);
        if (fd < 0)
                return fd;

        events = sd_network_monitor_get_events(m->network_monitor);
        if (events < 0)
                return events;

        r = sd_event_add_io(m->event, &m->network_monitor_event_source,
                            fd, events, &on_network_event, m);
        if (r < 0)
                return r;

        return 0;
}

typedef struct DNSServer {
        union in_addr_union addr;
        int family;
        uint16_t port;
        int ifindex;
        char *server_name;
        bool accessible;
} DNSServer;

static DNSServer *dns_server_free(DNSServer *s) {
        if (!s)
                return NULL;

        free(s->server_name);

        return mfree(s);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(DNSServer*, dns_server_free);

static int dispatch_dns_server(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dns_server_dispatch_table[] = {
                { "address",            SD_JSON_VARIANT_ARRAY,    json_dispatch_in_addr_union, offsetof(DNSServer, addr),        SD_JSON_MANDATORY },
                { "addressFamily",      SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,       offsetof(DNSServer, family),      SD_JSON_MANDATORY },
                { "port",               SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint16,     offsetof(DNSServer, port),        0                 },
                { "interfaceSpecifier", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,       offsetof(DNSServer, ifindex),     0                 },
                { "serverName",         SD_JSON_VARIANT_STRING,   sd_json_dispatch_string,     offsetof(DNSServer, server_name), 0                 },
                { "accessible",         SD_JSON_VARIANT_BOOLEAN,  sd_json_dispatch_stdbool,    offsetof(DNSServer, accessible),  SD_JSON_MANDATORY },
                {},
        };
        DNSServer **ret = ASSERT_PTR(userdata);
        _cleanup_(dns_server_freep) DNSServer *s = NULL;
        int r;

        s = new0(DNSServer, 1);
        if (!s)
                return log_oom();

        r = sd_json_dispatch(variant, dns_server_dispatch_table, flags, s);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(s);

        return 0;
}

static int dispatch_dns_server_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Set **ret = ASSERT_PTR(userdata);
        Set *dns_servers = set_new(NULL);
        sd_json_variant *v = NULL;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                _cleanup_(dns_server_freep) DNSServer *s = NULL;

                s = new0(DNSServer, 1);
                if (!s)
                        return log_oom();

                r = dispatch_dns_server(name, v, flags, &s);
                if (r < 0)
                        return json_log(v, flags, r, "JSON array element is not a valid DNSServer.");

                r = set_put(dns_servers, TAKE_PTR(s));
                if (r < 0)
                        return log_oom();
        }

        set_free_and_replace(*ret, dns_servers);

        return 0;
}

typedef struct DNSConfiguration {
        char *ifname;
        int ifindex;
        DNSServer *current_dns_server;
        Set *dns_servers;
        char **search_domains;
} DNSConfiguration;

static DNSConfiguration *dns_configuration_free(DNSConfiguration *c) {
        if (!c)
                return NULL;

        dns_server_free(c->current_dns_server);
        set_free_with_destructor(c->dns_servers, dns_server_free);
        free(c->ifname);
        strv_free(c->search_domains);

        return mfree(c);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(DNSConfiguration*, dns_configuration_free);

static int dispatch_dns_configuration(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dns_configuration_dispatch_table[] = {
                { "interface",        SD_JSON_VARIANT_STRING,   sd_json_dispatch_string,   offsetof(DNSConfiguration, ifname),             0 },
                { "interfaceIndex",   SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,     offsetof(DNSConfiguration, ifindex),            0 },
                { "currentDNSServer", SD_JSON_VARIANT_OBJECT,   dispatch_dns_server,       offsetof(DNSConfiguration, current_dns_server), 0 },
                { "dnsServers",       SD_JSON_VARIANT_ARRAY,    dispatch_dns_server_array, offsetof(DNSConfiguration, dns_servers),        0 },
                { "searchDomains",    SD_JSON_VARIANT_ARRAY,    sd_json_dispatch_strv,     offsetof(DNSConfiguration, search_domains),     0 },
                {},

        };
        DNSConfiguration **ret = ASSERT_PTR(userdata);
        _cleanup_(dns_configuration_freep) DNSConfiguration *c = NULL;
        int r;

        c = new0(DNSConfiguration, 1);
        if (!c)
                return log_oom();

        r = sd_json_dispatch(variant, dns_configuration_dispatch_table, flags, c);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);

        return 0;
}

static int on_dns_configuration_event(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        Manager *m = ASSERT_PTR(userdata);
        sd_json_variant *configurations = NULL, *v = NULL;
        int r;

        assert(link);

        if (error_id) {
                log_warning("DNS configuration event error, ignoring: %s", error_id);
                return 0;
        }

        configurations = sd_json_variant_by_key(parameters, "configuration");
        if (!configurations || !sd_json_variant_is_array(configurations)) {
                log_warning("DNS configuration JSON data does not have configuration key, ignoring.");
                return 0;
        }

        JSON_VARIANT_ARRAY_FOREACH(v, configurations) {
                _cleanup_(dns_configuration_freep) DNSConfiguration *c = NULL;
                DNSServer *s = NULL;
                AddressFamily families = ADDRESS_FAMILY_NO;

                r = dispatch_dns_configuration(NULL, v, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &c);
                if (r < 0) {
                        log_warning_errno(r, "Failed to get DNS configuration JSON, ignoring: %m");
                        continue;
                }

                SET_FOREACH(s, c->dns_servers) {
                        if (s->accessible)
                                families |= s->family == AF_INET ? ADDRESS_FAMILY_IPV4 :
                                            s->family == AF_INET6 ? ADDRESS_FAMILY_IPV6 : ADDRESS_FAMILY_NO;

                        if (FLAGS_SET(families, ADDRESS_FAMILY_YES))
                                break;
                }

                if (c->ifindex > 0) {
                        Link *l = hashmap_get(m->links_by_index, INT_TO_PTR(c->ifindex));
                        if (l)
                                l->dns_accessible_address_families = families;
                } else
                        /* Global DNS configuration */
                        m->dns_accessible_address_families = families;
        }

        if (manager_configured(m))
                sd_event_exit(m->event, 0);

        return 0;
}

static int manager_dns_configuration_listen(Manager *m) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        assert(m);
        assert(m->event);

        if (!m->requires_dns)
                return 0;

        r = sd_varlink_connect_address(&vl, "/run/systemd/resolve/io.systemd.Resolve.Monitor");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to io.systemd.Resolve.Monitor: %m");

        r = sd_varlink_set_relative_timeout(vl, USEC_INFINITY);
        if (r < 0)
                return log_error_errno(r, "Failed to set varlink timeout: %m");

        r = sd_varlink_attach_event(vl, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        (void) sd_varlink_set_userdata(vl, m);

        r = sd_varlink_bind_reply(vl, on_dns_configuration_event);
        if (r < 0)
                return log_error_errno(r, "Failed to bind varlink reply callback: %m");

        r = sd_varlink_observebo(
                        vl,
                        "io.systemd.Resolve.Monitor.SubscribeDNSConfiguration",
                        SD_JSON_BUILD_PAIR_BOOLEAN("allowInteractiveAuthentication", false));
        if (r < 0)
                return log_error_errno(r, "Failed to issue SubscribeDNSConfiguration: %m");

        m->varlink_client = TAKE_PTR(vl);

        return 0;
}

int manager_new(Manager **ret,
                Hashmap *command_line_interfaces_by_name,
                char **ignored_interfaces,
                LinkOperationalStateRange required_operstate,
                AddressFamily required_family,
                bool any,
                usec_t timeout,
                bool requires_dns) {

        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .command_line_interfaces_by_name = command_line_interfaces_by_name,
                .ignored_interfaces = ignored_interfaces,
                .required_operstate = required_operstate,
                .required_family = required_family,
                .any = any,
                .requires_dns = requires_dns,
                .dns_accessible_address_families = ADDRESS_FAMILY_NO,
        };

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        (void) sd_event_set_signal_exit(m->event, true);

        if (timeout > 0) {
                r = sd_event_add_time_relative(m->event, NULL, CLOCK_BOOTTIME, timeout, 0, NULL, INT_TO_PTR(-ETIMEDOUT));
                if (r < 0 && r != -EOVERFLOW)
                        return r;
        }

        sd_event_set_watchdog(m->event, true);

        r = manager_network_monitor_listen(m);
        if (r < 0)
                return r;

        r = manager_rtnl_listen(m);
        if (r < 0)
                return r;

        r = manager_dns_configuration_listen(m);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);

        return 0;
}

Manager* manager_free(Manager *m) {
        if (!m)
                return NULL;

        hashmap_free_with_destructor(m->links_by_index, link_free);
        hashmap_free(m->links_by_name);

        sd_event_source_unref(m->network_monitor_event_source);
        sd_network_monitor_unref(m->network_monitor);
        sd_event_source_unref(m->rtnl_event_source);
        sd_netlink_unref(m->rtnl);
        sd_event_unref(m->event);
        sd_varlink_unref(m->varlink_client);

        return mfree(m);
}
