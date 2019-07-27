/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>

#include "sd-event.h"
#include "sd-netlink.h"

#include "networkd-link-bus.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-speed-meter.h"

static int process_message(Manager *manager, sd_netlink_message *message) {
        uint16_t type;
        int ifindex, r;
        Link *link;

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0)
                return r;

        if (type != RTM_NEWLINK)
                return 0;

        r = sd_rtnl_message_link_get_ifindex(message, &ifindex);
        if (r < 0)
                return r;

        link = hashmap_get(manager->links, INT_TO_PTR(ifindex));
        if (!link)
                return -ENODEV;

        link->stats_old = link->stats_new;

        r = sd_netlink_message_read(message, IFLA_STATS64, sizeof link->stats_new, &link->stats_new);
        if (r < 0)
                return r;

        link->stats_updated = true;

        return 0;
}

static int speed_meter_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        Manager *manager = userdata;
        sd_netlink_message *i;
        usec_t usec_now;
        Iterator j;
        Link *link;
        int r;

        assert(s);
        assert(userdata);

        r = sd_event_now(sd_event_source_get_event(s), CLOCK_MONOTONIC, &usec_now);
        if (r < 0)
                return r;

        r = sd_event_source_set_time(s, usec_now + manager->speed_meter_interval_usec);
        if (r < 0)
                return r;

        manager->speed_meter_usec_old = manager->speed_meter_usec_new;
        manager->speed_meter_usec_new = usec_now;

        HASHMAP_FOREACH(link, manager->links, j)
                link->stats_updated = false;

        r = sd_rtnl_message_new_link(manager->rtnl, &req, RTM_GETLINK, 0);
        if (r < 0) {
                log_warning_errno(r, "Failed to allocate RTM_GETLINK netlink message, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_request_dump(req, true);
        if (r < 0) {
                log_warning_errno(r, "Failed to set dump flag, ignoring: %m");
                return 0;
        }

        r = sd_netlink_call(manager->rtnl, req, 0, &reply);
        if (r < 0) {
                log_warning_errno(r, "Failed to call RTM_GETLINK, ignoring: %m");
                return 0;
        }

        for (i = reply; i; i = sd_netlink_message_next(i))
                (void) process_message(manager, i);

        return 0;
}

int manager_start_speed_meter(Manager *manager) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int r;

        assert(manager);
        assert(manager->event);

        if (!manager->use_speed_meter)
                return 0;

        r = sd_event_add_time(manager->event, &s, CLOCK_MONOTONIC, 0, 0, speed_meter_handler, manager);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(s, SD_EVENT_ON);
        if (r < 0)
                return r;

        manager->speed_meter_event_source = TAKE_PTR(s);
        return 0;
}
