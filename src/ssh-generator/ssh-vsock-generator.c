/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "install.h"
#include "log.h"
#include "main-func.h"
#include "path-lookup.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "ssh-generator-util.h"
#include "strv.h"

static bool arg_auto = true;

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        assert(key);

        if (proc_cmdline_key_streq(key, "systemd.ssh_auto")) {
                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning_errno(r, "Failed to parse systemd.ssh_auto switch \"%s\", ignoring: %m", value);
                else
                        arg_auto = r;
        }

        return 0;
}

static int run(int argc, char **argv) {
        const char *dest = "/run/systemd/generator";
        int r;

        log_setup();

        if (strv_length(argv) > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes no arguments.");

        r = proc_cmdline_parse(parse_proc_cmdline_item, /* userdata= */ NULL, /* flags= */ 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        if (!arg_auto) {
                log_debug("Disabling SSH generator logic, because it has been turned off explicitly.");
                return 0;
        }

        _cleanup_(lookup_paths_done) LookupPaths lp = {};
        r = lookup_paths_init_or_warn(&lp, RUNTIME_SCOPE_SYSTEM, /* flags= */ 0, /* root_dir= */ NULL);
        if (r < 0)
                return r;

        r = unit_file_exists(RUNTIME_SCOPE_SYSTEM, &lp, "sshd-vsock.socket");
        if (r < 0)
                return log_error_errno(r, "Unable to detect if sshd-vsock.socket exists: %m");
        if (r > 0) {
                log_debug("sshd-vsock.socket already exists.");
                return 0;
        }

        _cleanup_free_ char *sshd_binary = NULL, *found_sshd_template_unit = NULL;
        r = find_sshd(&sshd_binary, &found_sshd_template_unit);
        if (r < 0)
                return r;

        _cleanup_free_ char *generated_sshd_template_unit = NULL;
        r = add_vsock_socket(dest, sshd_binary, found_sshd_template_unit, &generated_sshd_template_unit);
        if (r <= 0)
                return r;

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to get D-Bus connection: %m");

        log_debug("Calling org.freedesktop.systemd1.Manager.Reload()...");
        r = bus_service_manager_reload(bus);
        if (r < 0)
                return r;

        log_info("Requesting sshd-vsock.socket/start/replace...");
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        r = bus_call_method(bus, bus_systemd_mgr, "StartUnit", &error, NULL, "ss", "sshd-vsock.socket", "replace");
        if (r < 0)
                return log_error_errno(r, "Failed to (re)start sshd-vsock.socket: %s", bus_error_message(&error, r));

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
