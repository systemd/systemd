/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/ether.h>
#include <linux/if.h>
#include <fnmatch.h>

#include "alloc-util.h"
#include "link.h"
#include "manager.h"
#include "netlink-util.h"
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

static int manager_link_is_online(Manager *m, Link *l, LinkOperationalStateRange s) {
        AddressFamily required_family;
        bool needs_ipv4;
        bool needs_ipv6;

        assert(m);
        assert(l);

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

        if (s.min < 0)
                s.min = m->required_operstate.min >= 0 ? m->required_operstate.min
                                                       : l->required_operstate.min;

        if (s.max < 0)
                s.max = m->required_operstate.max >= 0 ? m->required_operstate.max
                                                       : l->required_operstate.max;

        if (l->operational_state < s.min || l->operational_state > s.max)
                return log_link_debug_errno(l, SYNTHETIC_ERRNO(EADDRNOTAVAIL),
                                            "Operational state '%s' is not in range ['%s':'%s']",
                                            link_operstate_to_string(l->operational_state),
                                            link_operstate_to_string(s.min), link_operstate_to_string(s.max));

        required_family = m->required_family > 0 ? m->required_family : l->required_family;
        needs_ipv4 = required_family & ADDRESS_FAMILY_IPV4;
        needs_ipv6 = required_family & ADDRESS_FAMILY_IPV6;

        if (s.min < LINK_OPERSTATE_ROUTABLE) {
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

        log_link_debug(l, "link is configured by networkd and online.");
        return true;
}

bool manager_configured(Manager *m) {
        Link *l;
        int r;

        if (!hashmap_isempty(m->command_line_interfaces_by_name)) {
                LinkOperationalStateRange *range;
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

                        r = manager_link_is_online(m, l, *range);
                        if (r <= 0 && !m->any)
                                return false;
                        if (r > 0 && m->any)
                                return true;
                }

                /* With '--any'   : no interface is ready
                 * Without '--any': all interfaces are ready */
                return !m->any;
        }

        /* wait for all links networkd manages */
        HASHMAP_FOREACH(l, m->links_by_index) {
                if (manager_ignore_link(m, l)) {
                        log_link_debug(l, "link is ignored");
                        continue;
                }

                r = manager_link_is_online(m, l,
                                           (LinkOperationalStateRange) { _LINK_OPERSTATE_INVALID,
                                                                         _LINK_OPERSTATE_INVALID });
                if (r < 0 && !m->any) /* Unlike the above loop, unmanaged interfaces are ignored here. */
                        return false;
                if (r > 0 && m->any)
                        return true;
        }

        /* With '--any'   : no interface is ready
         * Without '--any': all interfaces are ready or unmanaged */
        return !m->any;
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

int manager_new(Manager **ret,
                Hashmap *command_line_interfaces_by_name,
                char **ignored_interfaces,
                LinkOperationalStateRange required_operstate,
                AddressFamily required_family,
                bool any,
                usec_t timeout) {

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
        };

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        (void) sd_event_add_signal(m->event, NULL, SIGTERM, NULL, NULL);
        (void) sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);

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

        return mfree(m);
}
