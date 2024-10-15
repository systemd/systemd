/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "ansi-color.h"
#include "networkctl.h"
#include "networkctl-util.h"
#include "strv.h"
#include "varlink-util.h"

int varlink_connect_networkd(sd_varlink **ret_varlink) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        sd_json_variant *reply;
        uint64_t id;
        int r;

        r = sd_varlink_connect_address(&vl, "/run/systemd/netif/io.systemd.Network");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to network service /run/systemd/netif/io.systemd.Network: %m");

        (void) sd_varlink_set_description(vl, "varlink-network");

        r = sd_varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to allow passing file descriptor through varlink: %m");

        r = varlink_call_and_log(vl, "io.systemd.Network.GetNamespaceId", /* parameters= */ NULL, &reply);
        if (r < 0)
                return r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "NamespaceId", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint64, 0, SD_JSON_MANDATORY },
                {},
        };

        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &id);
        if (r < 0)
                return r;

        if (id == 0)
                log_debug("systemd-networkd.service not running in a network namespace (?), skipping netns check.");
        else {
                struct stat st;

                if (stat("/proc/self/ns/net", &st) < 0)
                        return log_error_errno(errno, "Failed to determine our own network namespace ID: %m");

                if (id != st.st_ino)
                        return log_error_errno(SYNTHETIC_ERRNO(EREMOTE),
                                               "networkctl must be invoked in same network namespace as systemd-networkd.service.");
        }

        if (ret_varlink)
                *ret_varlink = TAKE_PTR(vl);
        return 0;
}

bool networkd_is_running(void) {
        static int cached = -1;
        int r;

        if (cached < 0) {
                r = access("/run/systemd/netif/state", F_OK);
                if (r < 0) {
                        if (errno != ENOENT)
                                log_debug_errno(errno,
                                                "Failed to determine whether networkd is running, assuming it's not: %m");

                        cached = false;
                } else
                        cached = true;
        }

        return cached;
}

int acquire_bus(sd_bus **ret) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(ret);

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        (void) sd_bus_set_allow_interactive_authorization(bus, arg_ask_password);

        if (networkd_is_running()) {
                r = varlink_connect_networkd(/* ret_varlink = */ NULL);
                if (r < 0)
                        return r;
        } else
                log_warning("systemd-networkd is not running, output might be incomplete.");

        *ret = TAKE_PTR(bus);
        return 0;
}

int link_get_property(
                sd_bus *bus,
                int ifindex,
                sd_bus_error *error,
                sd_bus_message **reply,
                const char *iface,
                const char *propname,
                const char *type) {

        _cleanup_free_ char *path = NULL;
        char ifindex_str[DECIMAL_STR_MAX(int)];
        int r;

        assert(bus);
        assert(ifindex >= 0);
        assert(error);
        assert(reply);
        assert(iface);
        assert(propname);
        assert(type);

        xsprintf(ifindex_str, "%i", ifindex);

        r = sd_bus_path_encode("/org/freedesktop/network1/link", ifindex_str, &path);
        if (r < 0)
                return r;

        return sd_bus_get_property(bus, "org.freedesktop.network1", path, iface, propname, error, reply, type);
}

void operational_state_to_color(const char *name, const char *state, const char **on, const char **off) {
        if (STRPTR_IN_SET(state, "routable", "enslaved") ||
            (streq_ptr(name, "lo") && streq_ptr(state, "carrier"))) {
                if (on)
                        *on = ansi_highlight_green();
                if (off)
                        *off = ansi_normal();
        } else if (streq_ptr(state, "degraded")) {
                if (on)
                        *on = ansi_highlight_yellow();
                if (off)
                        *off = ansi_normal();
        } else {
                if (on)
                        *on = "";
                if (off)
                        *off = "";
        }
}

void setup_state_to_color(const char *state, const char **on, const char **off) {
        if (streq_ptr(state, "configured")) {
                if (on)
                        *on = ansi_highlight_green();
                if (off)
                        *off = ansi_normal();
        } else if (streq_ptr(state, "configuring")) {
                if (on)
                        *on = ansi_highlight_yellow();
                if (off)
                        *off = ansi_normal();
        } else if (STRPTR_IN_SET(state, "failed", "linger")) {
                if (on)
                        *on = ansi_highlight_red();
                if (off)
                        *off = ansi_normal();
        } else {
                if (on)
                        *on = "";
                if (off)
                        *off = "";
        }
}

void online_state_to_color(const char *state, const char **on, const char **off) {
        if (streq_ptr(state, "online")) {
                if (on)
                        *on = ansi_highlight_green();
                if (off)
                        *off = ansi_normal();
        } else if (streq_ptr(state, "partial")) {
                if (on)
                        *on = ansi_highlight_yellow();
                if (off)
                        *off = ansi_normal();
        } else {
                if (on)
                        *on = "";
                if (off)
                        *off = "";
        }
}
