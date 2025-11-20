/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-netlink.h"
#include "sd-varlink.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "bus-wait-for-jobs.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-ifname.h"
#include "json-util.h"
#include "log.h"
#include "netlink-util.h"
#include "networkctl.h"
#include "networkd-json.h"
#include "normalize.h"
#include "polkit-agent.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "varlink-util.h"

int link_up_down(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        int r, ret = 0;
        bool up = streq(argv[0], "up");

        (void) polkit_agent_open_if_enabled(BUS_TRANSPORT_LOCAL, arg_ask_password);

        r = varlink_connect_networkd(&vl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to systemd-networkd via varlink: %m");

        STRV_FOREACH(s, strv_skip(argv, 1)) {
                r = parse_ifindex(*s);
                if (r >= 0)
                        r = varlink_callbo_and_log(
                                        vl,
                                        "io.systemd.Network.SetLink",
                                        /* reply = */ NULL,
                                        SD_JSON_BUILD_PAIR_INTEGER("InterfaceIndex", r),
                                        SD_JSON_BUILD_PAIR_BOOLEAN("Up", up),
                                        SD_JSON_BUILD_PAIR_BOOLEAN("allowInteractiveAuthentication", arg_ask_password));
                else
                        r = varlink_callbo_and_log(
                                        vl,
                                        "io.systemd.Network.SetLink",
                                        /* reply = */ NULL,
                                        SD_JSON_BUILD_PAIR_STRING("InterfaceName", *s),
                                        SD_JSON_BUILD_PAIR_BOOLEAN("Up", up),
                                        SD_JSON_BUILD_PAIR_BOOLEAN("allowInteractiveAuthentication", arg_ask_password));
                RET_GATHER(ret, r);
        }

        return ret;
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

int link_renameif(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int r, ifindex;

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Exactly 2 arguments are required.");

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        ifindex = rtnl_resolve_interface_or_warn(&rtnl, argv[1]);
        if (ifindex < 0)
                return ifindex;

        r = rtnl_set_link_name(&rtnl, ifindex, argv[2]);
        if (r < 0)
                return log_error_errno(r, "Failed to rename interface %s to %s: %m", argv[1], argv[2]);

        return 0;
}
