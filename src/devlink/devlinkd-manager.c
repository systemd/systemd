/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/filter.h>

#include "sd-netlink.h"
#include "sd-bus.h"

#include "signal-util.h"
#include "daemon-util.h"
#include "devlink-util.h"
#include "bus-object.h"
#include "bus-util.h"
#include "string-util.h"
#include "time-util.h"
#include "netlink-util.h"

#include "devlinkd-manager.h"
#include "devlink.h"
#include "devlink-key.h"
#include "devlink-ifname-tracker.h"

/* use 128 MB for receive socket kernel queue. */
#define RCVBUF_SIZE    (128*1024*1024)

static void _manager_genl_process_message(sd_netlink *genl, sd_netlink_message *message,
                                          Manager *m, uint8_t enumerate_cmd_override) {
        const char *family;
        uint8_t cmd;
        int i;
        int r;

        assert(genl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_warning_errno(r, "devlink netlink: Received error message, ignoring: %m");
                return;
        }

        r = sd_genl_message_get_family_name(genl, message, &family);
        if (r < 0) {
                log_debug_errno(r, "devlink netlink: Failed to determine genl family, ignoring: %m");
                return;
        }
        if (!streq(family, DEVLINK_GENL_NAME)) {
                log_debug("devlink netlink: Received message of unexpected genl family '%s', ignoring: %m", family);
                return;
        }

        if (enumerate_cmd_override == DEVLINK_CMD_UNSPEC) {
                r = sd_genl_message_get_command(genl, message, &cmd);
                if (r < 0) {
                        log_debug_errno(r, "devlink netlink: Failed to determine genl message command, ignoring: %m");
                        return;
                }
        } else {
                /* Works around buggy kernel returning wrong reply cmd for some objects. */
                cmd = enumerate_cmd_override;
        }

        log_debug("devlink netlink: Received %s(%u) message.", strna(devlink_cmd_to_string(cmd)), cmd);

        devlink_for_each_kind(i) {
                const DevlinkVTable *vtable = _DEVLINK_VTABLE(i);

                FOREACH_ARRAY(j, vtable->genl_monitor_cmds, vtable->genl_monitor_cmds_count) {
                        if (j->cmd == cmd)
                                devlink_genl_process_message(message, m, i, j);
                }
        }
}

static int manager_genl_process_message(
                sd_netlink *genl,
                sd_netlink_message *message,
                Manager *m) {
        _manager_genl_process_message(genl, message, m, DEVLINK_CMD_UNSPEC);
        return 0;
}

static int manager_genl_enumerate_process_message(
                sd_netlink *genl,
                sd_netlink_message *message,
                Manager *m,
                uint8_t enumerate_cmd_override) {
        log_debug("devlink netlink: Incoming enumeration message");
        _manager_genl_process_message(genl, message, m, enumerate_cmd_override);
        return 0;
}

static int manager_genl_enumerate_one(
                Manager *m,
                uint8_t enumerate_cmd,
                uint8_t enumerate_cmd_override,
                DevlinkKey *key) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *rep = NULL;
        int r;

        assert(m);
        assert(m->genl);

        r = sd_genl_message_new(m->genl, DEVLINK_GENL_NAME, enumerate_cmd, &req);
        if (r < 0)
                return r;

        if (key) {
                r = devlink_key_genl_append(req, key);
                if (r < 0)
                        return r;
        } else {
                r = sd_netlink_message_set_request_dump(req, true);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_call(m->genl, req, 0, &rep);
        if (r < 0)
                return r;

        for (sd_netlink_message *rep_one = rep; rep_one; rep_one = sd_netlink_message_next(rep_one)) {
                r = sd_netlink_message_get_errno(rep_one);
                if (r < 0)
                        return r;
                r = manager_genl_enumerate_process_message(m->genl, rep_one, m, enumerate_cmd_override);
                if (r < 0)
                        return r;
        }

        return r;
}

static int manager_genl_enumerate_kind(
                Manager *m,
                DevlinkKind kind,
                DevlinkKey *key, bool may_fail) {
        const DevlinkVTable *vtable = _DEVLINK_VTABLE(kind);
        int r;

        assert(m);
        assert(m->genl);

        FOREACH_ARRAY(i, vtable->genl_monitor_cmds, vtable->genl_monitor_cmds_count) {
                if (!i->enumerate)
                        continue;
                r = manager_genl_enumerate_one(m, i->cmd, i->cmd_override, key);
                if (r < 0) {
                        if (may_fail) {
                                log_debug_errno(r, "Could not enumerate %s, cmd %u: %m", devlink_kind_to_string(kind), i->cmd);
                        } else {
                                log_error_errno(r, "Could not enumerate %s, cmd %u: %m", devlink_kind_to_string(kind), i->cmd);
                                return r;
                        }
                }
        }
        return 0;
}

void manager_kind_inc(Manager *m, DevlinkKind kind) {
    m->kind_info[kind].count++;
    m->kind_info[kind].dirty = true;
}

void manager_kind_dec(Manager *m, DevlinkKind kind) {
    m->kind_info[kind].count--;
}

static bool manager_kind_test_and_clear(Manager *m, DevlinkKind kind) {
    bool was_dirty = m->kind_info[kind].dirty;

    m->kind_info[kind].dirty = false;
    return was_dirty;
}

static int manager_genl_enumerate_dirty(Manager *m) {
        int r, i;

        devlink_for_each_kind(i) {
                if (!manager_kind_test_and_clear(m, i))
                        continue;
                r = manager_genl_enumerate_kind(m, i, NULL, true);
                if (r)
                        return r;
        }
        return 0;
}

static int manager_genl_enumerate_periodic(Manager *m) {
        int r, i;

        devlink_for_each_kind(i) {
                if (!m->kind_info[i].count ||
                    !_DEVLINK_VTABLE(i)->genl_need_periodic_enumeration)
                        continue;
                r = manager_genl_enumerate_kind(m, i, NULL, true);
                if (r)
                        return r;
        }
        return 0;
}

int manager_enumerate(Manager *m) {
        log_debug("Enumeration started");
        return manager_genl_enumerate_dirty(m);
}

void manager_enumerate_by_key(Manager *m, DevlinkKey *key) {
        (void) manager_genl_enumerate_kind(m, key->kind, key, true);
}

#define MANAGER_PERIODIC_ENUMERATION_INTERVAL (USEC_PER_SEC / 4)

static int manager_periodic_enumeration_event_callback(sd_event_source *source, usec_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(source == m->periodic_enumeration_event_source);

        (void) manager_genl_enumerate_periodic(m);

        r = sd_event_source_set_time_relative(
                        m->periodic_enumeration_event_source,
                        MANAGER_PERIODIC_ENUMERATION_INTERVAL);
        if (r < 0)
                return r;
        return sd_event_source_set_enabled(m->periodic_enumeration_event_source, SD_EVENT_ONESHOT);
}

static void manager_periodic_enumeration_stop(Manager *m) {
        m->periodic_enumeration_event_source = sd_event_source_disable_unref(m->periodic_enumeration_event_source);
}

static int manager_periodic_enumeration_start(Manager *m) {
        int r;

        r = sd_event_add_time_relative(
                        m->event,
                        &m->periodic_enumeration_event_source,
                        CLOCK_MONOTONIC,
                        MANAGER_PERIODIC_ENUMERATION_INTERVAL, 0,
                        manager_periodic_enumeration_event_callback,
                        m);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(m->periodic_enumeration_event_source, "devlink-periodic-enumeration");

        return 0;
}

static int manager_genl_connect(Manager *m) {
        int r;

        assert(m);

        r = sd_genl_socket_open(&m->genl);
        if (r < 0)
                return r;

        r = sd_netlink_increase_rxbuf(m->genl, RCVBUF_SIZE);
        if (r < 0)
                log_warning_errno(r, "Failed to increase receive buffer size for general netlink socket, ignoring: %m");

        r = sd_netlink_attach_event(m->genl, m->event, 0);
        if (r < 0)
                return r;

        r = genl_add_match(m->genl, NULL, DEVLINK_GENL_NAME, DEVLINK_GENL_MCGRP_CONFIG_NAME, 0,
                           &manager_genl_process_message, NULL, m, "devlinkd-genl_process_devlink_config");
        if (r < 0 && r != -EOPNOTSUPP)
                return r;

        return 0;
}

static int manager_setup_rtnl_filter(Manager *m) {
        struct sock_filter filter[] = {
                /* Check the packet length. */
                BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),                                      /* A <- packet length */
                BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, sizeof(struct nlmsghdr), 1, 0),         /* A (packet length) >= sizeof(struct nlmsghdr) ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                               /* reject */
                /* Accept all messages of types RTM_NEWLINK or RTM_DELLINK. */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct nlmsghdr, nlmsg_type)),  /* A <- message type */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, htobe16(RTM_NEWLINK), 2, 0),            /* message type == RTM_NEWLINK ? */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, htobe16(RTM_DELLINK), 1, 0),            /* message type == RTM_DELLINK ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                               /* reject */
                BPF_STMT(BPF_RET + BPF_K, UINT32_MAX),                                      /* accept */
        };

        assert(m);
        assert(m->rtnl);

        return sd_netlink_attach_filter(m->rtnl, ELEMENTSOF(filter), filter);
}

static int manager_rtnl_process_link(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        uint16_t type;
        int ifindex;
        int r;

        assert(rtnl);
        assert(message);
        assert(m);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_warning_errno(r, "rtnl: Could not receive link message, ignoring: %m");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Could not get message type, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_link_get_ifindex(message, &ifindex);
        if (r < 0) {
                log_warning_errno(r, "rtnl: Could not get ifindex from link message, ignoring: %m");
                return 0;
        } else if (ifindex <= 0) {
                log_warning("rtnl: received link message with invalid ifindex %d, ignoring: %m", ifindex);
                return 0;
        }

        switch (type) {
        case RTM_NEWLINK:
                r = devlink_ifname_tracker_ifindex_update(m, ifindex, message);
                if (r < 0)
                        log_warning_errno(r, "rtnl: Could not update ifname tracker, ignoring: %m");
                return 0;
        case RTM_DELLINK:
                devlink_ifname_tracker_ifindex_remove(m, ifindex);
                return 0;
        default:
                log_warning("rtnl: Received unexpected message type %u when processing link, ignoring.", type);
                return 0;
        }
}

int manager_rtnl_query_one(Manager *m, uint32_t ifindex) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *rep = NULL;
        int r;

        r = sd_rtnl_message_new_link(m->rtnl, &req, RTM_GETLINK, ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_call(m->rtnl, req, 0, &rep);
        if (r < 0) {
                if (r == -EINVAL) /* Device not present. */
                        return 0;
                return r;
        }

        (void) manager_rtnl_process_link(m->rtnl, rep, m);

        return 0;
}

static int manager_rtnl_connect(Manager *m) {
        int r;

        assert(m);

        r = sd_netlink_open(&m->rtnl);
        if (r < 0)
                return r;

        r = sd_netlink_increase_rxbuf(m->rtnl, RCVBUF_SIZE);
        if (r < 0)
                log_warning_errno(r, "Failed to increase receive buffer size for RT netlink socket, ignoring: %m");

        r = sd_netlink_attach_event(m->rtnl, m->event, 0);
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_NEWLINK, &manager_rtnl_process_link, NULL, m, "devlinkd-rtnl_process_link");
        if (r < 0)
                return r;

        r = netlink_add_match(m->rtnl, NULL, RTM_DELLINK, &manager_rtnl_process_link, NULL, m, "devlinkd-rtnl_process_link");
        if (r < 0)
                return r;

        return manager_setup_rtnl_filter(m);
}

static int signal_terminate_callback(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        log_debug("Terminate operation initiated.");
        return sd_event_exit(m->event, 0);
}

static int signal_restart_callback(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        log_debug("Restart operation initiated.");
        return sd_event_exit(m->event, 0);
}

static int signal_reload_callback(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        log_debug("Reloading configuration files...");
        (void) notify_reloading();

        manager_periodic_enumeration_stop(m);

        r = devlink_config_reload(m);
        if (r < 0)
                log_warning_errno(r, "Failed to reload configuration files: %m");

        r = manager_enumerate(m);
        if (r < 0)
                return r;

        r = manager_periodic_enumeration_start(m);
        if (r < 0)
                return r;

        log_debug("Reload of configuration files done");
        (void) sd_notify(false, NOTIFY_READY_MESSAGE);

        return 0;
}

static const sd_bus_vtable devlinkd_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_VTABLE_END
};

static const BusObjectImplementation devlinkd_object = {
    "/org/freedesktop/devlink1",
    "org.freedesktop.devlink1.Manager",
    .vtables = BUS_VTABLES(devlinkd_vtable),
};

static int manager_connect_bus(Manager *m) {
        int r;

        assert(m);
        assert(!m->bus);

        r = bus_open_system_watch_bind_with_description(&m->bus, "bus-api-devlink");
        if (r < 0)
                return log_warning_errno(r, "Failed to connect to system bus, continuing without D-Bus: %m");

        r = bus_add_implementation(m->bus, &devlinkd_object, m);
        if (r < 0)
                return log_warning_errno(r, "Failed to add D-Bus implementation: %m");

        r = sd_bus_request_name_async(m->bus, NULL, "org.freedesktop.devlink1", 0, NULL, NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to request D-Bus name: %m");

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0) {
                log_warning_errno(r, "Failed to attach D-Bus to event loop, continuing: %m");
                m->bus = sd_bus_unref(m->bus);
                return r;
        }

        return 0;
}

int manager_setup(Manager *m) {
        int r;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        (void) sd_event_set_watchdog(m->event, true);
        (void) sd_event_add_signal(m->event, NULL, SIGTERM | SD_EVENT_SIGNAL_PROCMASK, signal_terminate_callback, m);
        (void) sd_event_add_signal(m->event, NULL, SIGINT | SD_EVENT_SIGNAL_PROCMASK, signal_terminate_callback, m);
        (void) sd_event_add_signal(m->event, NULL, SIGUSR2 | SD_EVENT_SIGNAL_PROCMASK, signal_restart_callback, m);
        (void) sd_event_add_signal(m->event, NULL, SIGHUP | SD_EVENT_SIGNAL_PROCMASK, signal_reload_callback, m);

        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        r = manager_genl_connect(m);
        if (r < 0)
                return r;

        r = manager_rtnl_connect(m);
        if (r < 0)
                return r;

        return 0;
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        *ret = TAKE_PTR(m);

        return 0;
}

Manager* manager_free(Manager *m) {
        if (!m)
                return NULL;

        manager_periodic_enumeration_stop(m);
        m->bus = sd_bus_unref(m->bus);
        m->event = sd_event_unref(m->event);
        m->genl = sd_netlink_unref(m->genl);
        m->rtnl = sd_netlink_unref(m->rtnl);
        m->devlink_objs = hashmap_free(m->devlink_objs);
        m->reload = hashmap_free(m->reload);
        m->port_cache_by_ifindex = hashmap_free(m->port_cache_by_ifindex);
        m->ifname_tracker_by_ifname = hashmap_free(m->ifname_tracker_by_ifname);
        m->port_cache_by_ifindex = hashmap_free(m->port_cache_by_ifindex);

        return mfree(m);
}

int manager_start(Manager *m) {
        assert(m);

        return manager_periodic_enumeration_start(m);
}

int manager_config_load(Manager *m) {
        return devlink_config_load(m);
}
