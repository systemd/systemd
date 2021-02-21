/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#include <sys/types.h>

#include "sd-daemon.h"

#include "async.h"
#include "alloc-util.h"
#include "cloud-provider-link.h"
#include "cloud-provider-manager.h"
#include "fd-util.h"
#include "format-util.h"
#include "json.h"
#include "log-link.h"
#include "log.h"
#include "network-cloud-azure.h"
#include "network-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"
#include "virt.h"

static int acquire_azure_cloud_metadata(NetworkCloudProvider **ret) {
        _cleanup_(network_cloud_provider_freep) NetworkCloudProvider *m = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        r = azure_acquire_cloud_metadata_from_imds(&m);
        if (r < 0)
                return r;

        r = json_parse((char *) m->payload, JSON_PARSE_SENSITIVE, &v, NULL, NULL);
        if (r < 0)
                return r;

        r = azure_parse_json_object(m, v);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

static void *manager_send_request(void *arg) {
        Manager *m = (Manager *) arg;
        int r;

        assert(m);

        if (detect_virtualization() == VIRTUALIZATION_MICROSOFT) {
                _cleanup_(network_cloud_provider_freep) NetworkCloudProvider *n = NULL;
                Link *l;

                log_debug("Acquring network information from Azure Instance Metadata Service (IMDS) ...");

                r = acquire_azure_cloud_metadata(&n);
                if (r < 0)
                        log_error_errno(r, "Failed to fetch network information from IMDS: %m");

                m->cloud_manager = TAKE_PTR(n);

                HASHMAP_FOREACH(l, m->links)
                        link_save(l);
        }

        return 0;
}

static int manager_process_link(sd_netlink *rtnl, sd_netlink_message *rep, void *userdata) {
        Manager *m = userdata;
        const char *ifname;
        int ifindex, r;
        uint16_t type;
        Link *l;

        assert(rtnl);
        assert(m);
        assert(rep);

        r = sd_netlink_message_get_type(rep, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Could not get message type, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_link_get_ifindex(rep, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Could not get ifindex from link, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received link message with invalid ifindex %d, ignoring", ifindex);
                return 0;
        }

        r = sd_netlink_message_read_string(rep, IFLA_IFNAME, &ifname);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Received link message without ifname, ignoring: %m");
                return 0;
        }

        l = hashmap_get(m->links, INT_TO_PTR(ifindex));

        switch (type) {

        case RTM_NEWLINK:
                if (!l) {
                        log_debug("Found link ifindex=%i, ifname=%s", ifindex, ifname);

                        r = link_new(m, &l, ifindex, ifname);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create link object: %m");
                }

                r = link_update_rtnl(l, rep);
                if (r < 0)
                        log_link_warning_errno(l, r, "Failed to process RTNL link message, ignoring: %m");

                break;

        case RTM_DELLINK:
                if (l) {
                        log_link_debug(l, "Removing link ifindex=%i", ifindex);
                        link_free(l);
                }

                break;
        }

        return 0;
}

static int on_rtnl_event(sd_netlink *rtnl, sd_netlink_message *rep, void *userdata) {
        Manager *m = userdata;
        int r;

        r = manager_process_link(rtnl, rep, m);
        if (r < 0)
                return r;

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

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_NEWLINK, on_rtnl_event, NULL, m, "cloud-provider-on-NEWLINK");
        if (r < 0)
                return r;

        r = sd_netlink_add_match(m->rtnl, NULL, RTM_DELLINK, on_rtnl_event, NULL, m, "cloud-provider-on-DELLINK");
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

        for (sd_netlink_message *i = reply; i; i = sd_netlink_message_next(i)) {
                r = manager_process_link(m->rtnl, i, m);
                if (r < 0)
                        return r;
        }

        return r;
}

static int manager_begin(Manager *m) {
        assert(m);

        log_debug("Connecting to cloud provider database .");

        sd_notifyf(false, "STATUS=Connecting to cloud provider database.");

        return asynchronous_job(manager_send_request, m);
}

int manager_connect(Manager *m) {
        int r;

        assert(m);

        manager_disconnect(m);

        r = manager_begin(m);
        if (r < 0)
                return r;

        return 1;
}

void manager_disconnect(Manager *m) {
        assert(m);

        m->cloud_manager = network_cloud_provider_free(m->cloud_manager);

        sd_notifyf(false, "STATUS=Idle.");
}

static int manager_network_event_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        bool online;
        int r;

        assert(m);

        sd_network_monitor_flush(m->network_monitor);

        online = network_is_online();
        if (!online) {
                log_info("No network connectivity, watching for changes.");
                manager_disconnect(m);

        } else if (online) {
                log_info("Network configuration changed, trying to establish connection.");

                r = manager_connect(m);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int manager_network_monitor_listen(Manager *m) {
        int r, fd, events;

        assert(m);

        r = sd_network_monitor_new(&m->network_monitor, NULL);
        if (r == -ENOENT) {
                log_info("systemd-networkd does not appear to be running, not listening for systemd-networkd events.");
                return 0;
        }
        if (r < 0)
                return r;

        fd = sd_network_monitor_get_fd(m->network_monitor);
        if (fd < 0)
                return fd;

        events = sd_network_monitor_get_events(m->network_monitor);
        if (events < 0)
                return events;

        r = sd_event_add_io(m->event, &m->network_event_source, fd, events, manager_network_event_handler, m);
        if (r < 0)
                return r;

        return 0;
}

void manager_free(Manager *m) {
        if (!m)
                return;

        sd_event_source_unref(m->network_event_source);
        sd_network_monitor_unref(m->network_monitor);

        network_cloud_provider_free(m->cloud_manager);
        sd_event_unref(m->event);
        free(m);
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        (void) sd_event_add_signal(m->event, NULL, SIGTERM, NULL,  NULL);
        (void) sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);

        (void) sd_event_set_watchdog(m->event, true);

        r = manager_network_monitor_listen(m);
        if (r < 0)
                return r;

        r = manager_rtnl_listen(m);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}
