/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/ether.h>
#include <linux/if.h>
#include <fnmatch.h>

#include "alloc-util.h"
#include "netlink-util.h"
#include "network-internal.h"
#include "networkd-wait-online-link.h"
#include "networkd-wait-online.h"
#include "time-util.h"
#include "util.h"

bool manager_ignore_link(Manager *m, Link *link) {
        char **ignore;

        assert(m);
        assert(link);

        /* always ignore the loopback interface */
        if (link->flags & IFF_LOOPBACK)
                return true;

        /* if interfaces are given on the command line, ignore all others */
        if (m->interfaces && !strv_contains(m->interfaces, link->ifname))
                return true;

        /* ignore interfaces we explicitly are asked to ignore */
        STRV_FOREACH(ignore, m->ignore)
                if (fnmatch(*ignore, link->ifname, 0) == 0)
                        return true;

        return false;
}

bool manager_all_configured(Manager *m) {
        Iterator i;
        Link *l;
        char **ifname;
        bool one_ready = false;

        /* wait for all the links given on the command line to appear */
        STRV_FOREACH(ifname, m->interfaces) {
                l = hashmap_get(m->links_by_name, *ifname);
                if (!l) {
                        log_debug("still waiting for %s", *ifname);
                        return false;
                }
        }

        /* wait for all links networkd manages to be in admin state 'configured'
           and at least one link to gain a carrier */
        HASHMAP_FOREACH(l, m->links, i) {
                if (manager_ignore_link(m, l)) {
                        log_info("ignoring: %s", l->ifname);
                        continue;
                }

                if (!l->state) {
                        log_debug("link %s has not yet been processed by udev",
                                  l->ifname);
                        return false;
                }

                if (STR_IN_SET(l->state, "configuring", "pending")) {
                        log_debug("link %s is being processed by networkd",
                                  l->ifname);
                        return false;
                }

                if (l->operational_state &&
                    STR_IN_SET(l->operational_state, "degraded", "routable"))
                        /* we wait for at least one link to be ready,
                           regardless of who manages it */
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
        if (r < 0)
                goto fail;

        r = sd_rtnl_message_link_get_ifindex(mm, &ifindex);
        if (r < 0)
                goto fail;

        r = sd_netlink_message_read_string(mm, IFLA_IFNAME, &ifname);
        if (r < 0)
                goto fail;

        l = hashmap_get(m->links, INT_TO_PTR(ifindex));

        switch (type) {

        case RTM_NEWLINK:
                if (!l) {
                        log_debug("Found link %i", ifindex);

                        r = link_new(m, &l, ifindex, ifname);
                        if (r < 0)
                                goto fail;

                        r = link_update_monitor(l);
                        if (r < 0)
                                goto fail;
                }

                r = link_update_rtnl(l, mm);
                if (r < 0)
                        goto fail;

                break;

        case RTM_DELLINK:
                if (l) {
                        log_debug("Removing link %i", l->ifindex);
                        link_free(l);
                }

                break;
        }

        return 0;

fail:
        log_warning_errno(r, "Failed to process RTNL link message: %m");
        return 0;
}

static int on_rtnl_event(sd_netlink *rtnl, sd_netlink_message *mm, void *userdata) {
        Manager *m = userdata;
        int r;

        r = manager_process_link(rtnl, mm, m);
        if (r < 0)
                return r;

        if (manager_all_configured(m))
                sd_event_exit(m->event, 0);

        return 1;
}

static int manager_rtnl_listen(Manager *m) {
        _cleanup_netlink_message_unref_ sd_netlink_message *req = NULL, *reply = NULL;
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

        r = sd_netlink_add_match(m->rtnl, RTM_NEWLINK, on_rtnl_event, m);
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, RTM_DELLINK, on_rtnl_event, m);
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
                if (r < 0)
                        log_warning_errno(r, "Failed to update monitor information for %i: %m", l->ifindex);
        }

        if (manager_all_configured(m))
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

int manager_new(Manager **ret, char **interfaces, char **ignore, usec_t timeout) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        m->interfaces = interfaces;
        m->ignore = ignore;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        sd_event_add_signal(m->event, NULL, SIGTERM, NULL,  NULL);
        sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);

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

        *ret = m;
        m = NULL;

        return 0;
}

void manager_free(Manager *m) {
        Link *l;

        if (!m)
                return;

        while ((l = hashmap_first(m->links)))
               link_free(l);
        hashmap_free(m->links);
        hashmap_free(m->links_by_name);

        sd_event_source_unref(m->network_monitor_event_source);
        sd_network_monitor_unref(m->network_monitor);

        sd_event_source_unref(m->rtnl_event_source);
        sd_netlink_unref(m->rtnl);

        sd_event_unref(m->event);
        free(m);

        return;
}
