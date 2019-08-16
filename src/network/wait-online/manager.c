/* SPDX-License-Identifier: LGPL-2.1+ */

#include <netinet/ether.h>
#include <linux/if.h>
#include <fnmatch.h>

#include "alloc-util.h"
#include "link.h"
#include "manager.h"
#include "netlink-util.h"
#include "network-internal.h"
#include "strv.h"
#include "time-util.h"
#include "util.h"

static bool manager_ignore_link(Manager *m, Link *link) {
        assert(m);
        assert(link);

        /* always ignore the loopback interface */
        if (link->flags & IFF_LOOPBACK)
                return true;

        /* if interfaces are given on the command line, ignore all others */
        if (m->interfaces && !hashmap_contains(m->interfaces, link->ifname))
                return true;

        if (!link->required_for_online)
                return true;

        /* ignore interfaces we explicitly are asked to ignore */
        return strv_fnmatch(m->ignore, link->ifname, 0);
}

static int manager_link_is_online(Manager *m, Link *l, LinkOperationalState s) {
        /* This returns the following:
         * -EAGAIN: not processed by udev or networkd
         *       0: operstate is not enough
         *       1: online */

        if (!l->state)
                return log_link_debug_errno(l, SYNTHETIC_ERRNO(EAGAIN),
                                            "link has not yet been processed by udev");

        if (STR_IN_SET(l->state, "configuring", "pending"))
                return log_link_debug_errno(l, SYNTHETIC_ERRNO(EAGAIN),
                                            "link is being processed by networkd");

        if (s < 0)
                s = m->required_operstate >= 0 ? m->required_operstate : l->required_operstate;

        if (l->operational_state < s) {
                log_link_debug(l, "Operational state '%s' is below '%s'",
                               link_operstate_to_string(l->operational_state),
                               link_operstate_to_string(s));
                return 0;
        }

        return 1;
}

bool manager_configured(Manager *m) {
        bool one_ready = false;
        Iterator i;
        const char *ifname;
        void *p;
        Link *l;
        int r;

        if (!hashmap_isempty(m->interfaces)) {
                /* wait for all the links given on the command line to appear */
                HASHMAP_FOREACH_KEY(p, ifname, m->interfaces, i) {
                        LinkOperationalState s = PTR_TO_INT(p);

                        l = hashmap_get(m->links_by_name, ifname);
                        if (!l) {
                                log_debug("still waiting for %s", ifname);
                                if (!m->any)
                                        return false;
                                continue;
                        }

                        if (manager_link_is_online(m, l, s) <= 0) {
                                if (!m->any)
                                        return false;
                                continue;
                        }

                        one_ready = true;
                }

                /* all interfaces given by the command line are online, or
                 * one of the specified interfaces is online. */
                return one_ready;
        }

        /* wait for all links networkd manages to be in admin state 'configured'
         * and at least one link to gain a carrier */
        HASHMAP_FOREACH(l, m->links, i) {
                if (manager_ignore_link(m, l)) {
                        log_link_debug(l, "link is ignored");
                        continue;
                }

                r = manager_link_is_online(m, l, _LINK_OPERSTATE_INVALID);
                if (r < 0 && !m->any)
                        return false;
                if (r > 0)
                        /* we wait for at least one link to be ready,
                         * regardless of who manages it */
                        one_ready = true;
        }

        return one_ready;
}

static int manager_process_link(sd_netlink *rtnl, sd_netlink_message *mm, void *userdata) {
        Manager *m = userdata;
        uint16_t type;
        Link *l;
        const char *ifname;
        int ifindex, r;

        assert(rtnl);
        assert(m);
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

        l = hashmap_get(m->links, INT_TO_PTR(ifindex));

        switch (type) {

        case RTM_NEWLINK:
                if (!l) {
                        log_debug("Found link %i", ifindex);

                        r = link_new(m, &l, ifindex, ifname);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create link object: %m");
                }

                r = link_update_rtnl(l, mm);
                if (r < 0)
                        log_link_warning_errno(l, r, "Failed to process RTNL link message, ignoring: %m");

                r = link_update_monitor(l);
                if (r < 0 && r != -ENODATA)
                        log_link_warning_errno(l, r, "Failed to update link state, ignoring: %m");

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
        sd_netlink_message *i;
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

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(m->rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (i = reply; i; i = sd_netlink_message_next(i)) {
                r = manager_process_link(m->rtnl, i, m);
                if (r < 0)
                        return r;
        }

        return r;
}

static int on_network_event(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        Iterator i;
        Link *l;
        int r;

        assert(m);

        sd_network_monitor_flush(m->network_monitor);

        HASHMAP_FOREACH(l, m->links, i) {
                r = link_update_monitor(l);
                if (r < 0 && r != -ENODATA)
                        log_link_warning_errno(l, r, "Failed to update link state, ignoring: %m");
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

int manager_new(Manager **ret, Hashmap *interfaces, char **ignore,
                LinkOperationalState required_operstate,
                bool any, usec_t timeout) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .interfaces = interfaces,
                .ignore = ignore,
                .required_operstate = required_operstate,
                .any = any,
        };

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        (void) sd_event_add_signal(m->event, NULL, SIGTERM, NULL,  NULL);
        (void) sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);

        if (timeout > 0) {
                usec_t usec;

                usec = now(clock_boottime_or_monotonic()) + timeout;

                r = sd_event_add_time(m->event, NULL, clock_boottime_or_monotonic(), usec, 0, NULL, INT_TO_PTR(-ETIMEDOUT));
                if (r < 0)
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

void manager_free(Manager *m) {
        if (!m)
                return;

        hashmap_free_with_destructor(m->links, link_free);
        hashmap_free(m->links_by_name);

        sd_event_source_unref(m->network_monitor_event_source);
        sd_network_monitor_unref(m->network_monitor);

        sd_event_source_unref(m->rtnl_event_source);
        sd_netlink_unref(m->rtnl);

        sd_event_unref(m->event);
        free(m);

        return;
}
