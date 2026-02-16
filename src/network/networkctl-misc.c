/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-netlink.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-ifname.h"
#include "log.h"
#include "netlink-util.h"
#include "networkctl.h"
#include "networkctl-misc.h"
#include "networkctl-util.h"
#include "ordered-set.h"
#include "parse-util.h"
#include "polkit-agent.h"
#include "string-util.h"
#include "strv.h"
#include "varlink-util.h"

static int parse_interfaces(sd_netlink **rtnl, char *argv[], OrderedSet **ret) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *our_rtnl = NULL;
        _cleanup_ordered_set_free_ OrderedSet *indexes = NULL;
        int r;

        assert(ret);

        if (!rtnl)
                rtnl = &our_rtnl;

        STRV_FOREACH(s, strv_skip(argv, 1)) {
                int index = rtnl_resolve_interface_or_warn(rtnl, *s);
                if (index < 0)
                        return index;
                assert(index > 0);

                r = ordered_set_ensure_put(&indexes, /* ops= */ NULL, INT_TO_PTR(index));
                if (r < 0)
                        return log_oom();
        }

        *ret = TAKE_PTR(indexes);
        return 0;
}

int link_up_down(int argc, char *argv[], void *userdata) {
        int r, ret = 0;

        bool up = streq_ptr(argv[0], "up");

        _cleanup_ordered_set_free_ OrderedSet *indexes = NULL;
        r = parse_interfaces(/* rtnl= */ NULL, argv, &indexes);
        if (r < 0)
                return r;

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        r = varlink_connect_networkd(&vl);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        void *p;
        ORDERED_SET_FOREACH(p, indexes)
                RET_GATHER(ret, varlink_callbo_and_log(
                                           vl,
                                           up ? "io.systemd.Network.LinkUp" : "io.systemd.Network.LinkDown",
                                           /* reply= */ NULL,
                                           SD_JSON_BUILD_PAIR_INTEGER("InterfaceIndex", PTR_TO_INT(p)),
                                           SD_JSON_BUILD_PAIR_BOOLEAN("allowInteractiveAuthentication", arg_ask_password)));

        return ret;
}

int link_delete(int argc, char *argv[], void *userdata) {
        int r, ret = 0;

        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_ordered_set_free_ OrderedSet *indexes = NULL;
        r = parse_interfaces(&rtnl, argv, &indexes);
        if (r < 0)
                return r;

        void *p;
        ORDERED_SET_FOREACH(p, indexes) {
                _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
                int index = PTR_TO_INT(p);

                r = sd_rtnl_message_new_link(rtnl, &req, RTM_DELLINK, index);
                if (r < 0)
                        return rtnl_log_create_error(r);

                r = sd_netlink_call(rtnl, req, /* timeout= */ 0, /* ret= */ NULL);
                if (r < 0) {
                        RET_GATHER(ret, r);
                        log_error_errno(r, "Failed to delete interface %s: %m",
                                        FORMAT_IFNAME_FULL(index, FORMAT_IFNAME_IFINDEX));
                }
        }

        return ret;
}

int link_bus_simple_method(int argc, char *argv[], void *userdata) {
        int r, ret = 0;

        typedef struct LinkBusAction {
                const char *verb;
                const char *bus_method;
                const char *error_message;
        } LinkBusAction;

        static const LinkBusAction link_bus_action_table[] = {
                { "renew",       "RenewLink",       "Failed to renew dynamic configuration of interface"          },
                { "forcerenew",  "ForceRenewLink",  "Failed to forcibly renew dynamic configuration of interface" },
                { "reconfigure", "ReconfigureLink", "Failed to reconfigure network interface"                     },
        };

        /* Common implementation for 'simple' method calls that just take an ifindex, and nothing else. */

        const LinkBusAction *a = NULL;
        FOREACH_ELEMENT(i, link_bus_action_table)
                if (streq(argv[0], i->verb)) {
                        a = i;
                        break;
                }
        assert(a);

        _cleanup_ordered_set_free_ OrderedSet *indexes = NULL;
        r = parse_interfaces(/* rtnl= */ NULL, argv, &indexes);
        if (r < 0)
                return r;

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        void *p;
        ORDERED_SET_FOREACH(p, indexes) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                int index = PTR_TO_INT(p);

                r = bus_call_method(bus, bus_network_mgr, a->bus_method, &error, /* ret_reply= */ NULL, "i", index);
                if (r < 0) {
                        RET_GATHER(ret, r);
                        log_error_errno(r, "%s %s: %s",
                                        a->error_message,
                                        FORMAT_IFNAME_FULL(index, FORMAT_IFNAME_IFINDEX),
                                        bus_error_message(&error, r));
                }
        }

        return ret;
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
                        return log_error_errno(errno, "Failed to open %s: %m", "/var/lib/systemd/network/");

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
