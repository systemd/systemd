/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "coredump-register.h"
#include "errno-util.h"
#include "json-util.h"
#include "log.h"
#include "sysctl-util.h"
#include "varlink-io.systemd.Coredump.Register.h"
#include "varlink-util.h"

static int vl_method_set_core_pattern(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        assert(link);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "pattern", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, SD_JSON_STRICT | SD_JSON_MANDATORY },
                {}
        };

        const char *pattern;
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &pattern);
        if (r != 0)
                return r;

        r = sysctl_write_verify("kernel/core_pattern", pattern);
        if (r == -EINVAL)
                return sd_varlink_error(link, "io.systemd.Coredump.Register.CoredumpPatternNotSupported", NULL);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

int coredump_register(int argc, char *argv[]) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        int r;

        log_setup();

        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_ROOT_ONLY,
                        /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_CoredumpRegister);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.Coredump.Register.SetCorePattern", vl_method_set_core_pattern);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}
