/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>

#include "bus-error.h"
#include "bus-locator.h"
#include "fd-util.h"
#include "format-ifname.h"
#include "netlink-util.h"
#include "networkctl.h"
#include "networkctl-misc.h"
#include "networkctl-util.h"
#include "parse-util.h"
#include "polkit-agent.h"
#include "set.h"
#include "strv.h"
#include "varlink-util.h"

static int link_up_down_send_message(sd_netlink *rtnl, char *command, int index) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(rtnl);
        assert(index >= 0);

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_SETLINK, index);
        if (r < 0)
                return rtnl_log_create_error(r);

        if (streq(command, "up"))
                r = sd_rtnl_message_link_set_flags(req, IFF_UP, IFF_UP);
        else
                r = sd_rtnl_message_link_set_flags(req, 0, IFF_UP);
        if (r < 0)
                return log_error_errno(r, "Could not set link flags: %m");

        r = sd_netlink_call(rtnl, req, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}

int link_up_down(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_set_free_ Set *indexes = NULL;
        int index, r;
        void *p;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        indexes = set_new(NULL);
        if (!indexes)
                return log_oom();

        for (int i = 1; i < argc; i++) {
                index = rtnl_resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                r = set_put(indexes, INT_TO_PTR(index));
                if (r < 0)
                        return log_oom();
        }

        SET_FOREACH(p, indexes) {
                index = PTR_TO_INT(p);
                r = link_up_down_send_message(rtnl, argv[0], index);
                if (r < 0)
                        return log_error_errno(r, "Failed to bring %s interface %s: %m",
                                               argv[0], FORMAT_IFNAME_FULL(index, FORMAT_IFNAME_IFINDEX));
        }

        return r;
}

static int link_delete_send_message(sd_netlink *rtnl, int index) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(rtnl);
        assert(index >= 0);

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_DELLINK, index);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_netlink_call(rtnl, req, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}

int link_delete(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_set_free_ Set *indexes = NULL;
        int index, r;
        void *p;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        indexes = set_new(NULL);
        if (!indexes)
                return log_oom();

        for (int i = 1; i < argc; i++) {
                index = rtnl_resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                r = set_put(indexes, INT_TO_PTR(index));
                if (r < 0)
                        return log_oom();
        }

        SET_FOREACH(p, indexes) {
                index = PTR_TO_INT(p);
                r = link_delete_send_message(rtnl, index);
                if (r < 0)
                        return log_error_errno(r, "Failed to delete interface %s: %m",
                                               FORMAT_IFNAME_FULL(index, FORMAT_IFNAME_IFINDEX));
        }

        return r;
}

static int link_renew_one(sd_bus *bus, int index, const char *name) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(index >= 0);
        assert(name);

        r = bus_call_method(bus, bus_network_mgr, "RenewLink", &error, NULL, "i", index);
        if (r < 0)
                return log_error_errno(r, "Failed to renew dynamic configuration of interface %s: %s",
                                       name, bus_error_message(&error, r));

        return 0;
}

int link_renew(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = 0;

        for (int i = 1; i < argc; i++) {
                int index;

                index = rtnl_resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                RET_GATHER(r, link_renew_one(bus, index, argv[i]));
        }

        return r;
}

static int link_force_renew_one(sd_bus *bus, int index, const char *name) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(index >= 0);
        assert(name);

        r = bus_call_method(bus, bus_network_mgr, "ForceRenewLink", &error, NULL, "i", index);
        if (r < 0)
                return log_error_errno(r, "Failed to force renew dynamic configuration of interface %s: %s",
                                       name, bus_error_message(&error, r));

        return 0;
}

int link_force_renew(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int k = 0, r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        for (int i = 1; i < argc; i++) {
                int index = rtnl_resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                r = link_force_renew_one(bus, index, argv[i]);
                if (r < 0 && k >= 0)
                        k = r;
        }

        return k;
}

int verb_reload(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = bus_call_method(bus, bus_network_mgr, "Reload", &error, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to reload network settings: %s", bus_error_message(&error, r));

        return 0;
}

int verb_reconfigure(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_set_free_ Set *indexes = NULL;
        int index, r;
        void *p;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        indexes = set_new(NULL);
        if (!indexes)
                return log_oom();

        for (int i = 1; i < argc; i++) {
                index = rtnl_resolve_interface_or_warn(&rtnl, argv[i]);
                if (index < 0)
                        return index;

                r = set_put(indexes, INT_TO_PTR(index));
                if (r < 0)
                        return log_oom();
        }

        SET_FOREACH(p, indexes) {
                index = PTR_TO_INT(p);
                r = bus_call_method(bus, bus_network_mgr, "ReconfigureLink", &error, NULL, "i", index);
                if (r < 0)
                        return log_error_errno(r, "Failed to reconfigure network interface %s: %s",
                                               FORMAT_IFNAME_FULL(index, FORMAT_IFNAME_IFINDEX),
                                               bus_error_message(&error, r));
        }

        return 0;
}

int verb_persistent_storage(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        bool ready;
        int r;

        r = parse_boolean(argv[1]);
        if (r < 0)
                return log_error_errno(r, "Failed to parse argument: %s", argv[1]);
        ready = r;

        r = varlink_connect_networkd(&vl);
        if (r < 0)
                return r;

        if (ready) {
                _cleanup_close_ int fd = -EBADF;

                fd = open("/var/lib/systemd/network/", O_CLOEXEC | O_DIRECTORY);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open /var/lib/systemd/network/: %m");

                r = sd_varlink_push_fd(vl, fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to push file descriptor of /var/lib/systemd/network/ into varlink: %m");

                TAKE_FD(fd);
        }

        return varlink_callbo_and_log(
                        vl,
                        "io.systemd.Network.SetPersistentStorage",
                        /* reply= */ NULL,
                        SD_JSON_BUILD_PAIR_BOOLEAN("Ready", ready));
}
