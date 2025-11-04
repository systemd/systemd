/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "coredump-register.h"
#include "errno-util.h"
#include "json-util.h"
#include "log.h"
#include "pidfd-util.h"
#include "string-util.h"
#include "sysctl-util.h"
#include "varlink-io.systemd.Coredump.Register.h"
#include "varlink-util.h"

static int coredump_register_socket(const char *path) {
        int r;

        assert(path);

        /* The request mode coredump socket pattern is supported since kernel v6.17. Old kernels do not
         * refuse the new core patterns (moreover, any strings are accepted), hence we need to check kernel
         * version in some ways other than reading/writing core patterns. Here, we use if
         * ioctl(PIDFD_GET_INFO) supportes necessary flags. */

        /* The following flags are required for supporting kernel coredump socket feature:
         * PIDFD_INFO_COREDUMP        : 1d8db6fd698de1f73b1a7d72aea578fdd18d9a87 (v6.16),
         * PIDFD_INFO_COREDUMP_SIGNAL : 036375522be8425874e9e0f907c7127e315c7a52 (v6.19). */
        r = pidfd_info_mask_is_supported(PIDFD_INFO_COREDUMP | PIDFD_INFO_COREDUMP_SIGNAL);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if PIDFD_INFO_COREDUMP and PIDFD_INFO_COREDUMP_SIGNAL flags are supported by ioctl(PIDFD_GET_INFO): %m");
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "ioctl(PIDFD_GET_INFO) does not support PIDFD_INFO_COREDUMP and/or PIDFD_INFO_COREDUMP_SIGNAL.");

        /* The "@@" prefix means the path is a AF_UNIX socket and it accepts the request mode protocol. The
         * protocol is supported since kernel v6.17. We have already checked if PIDFD_INFO_COREDUMP_SIGNAL
         * flag (since v6.19) is supported in the above. Hence, the prefix should be supported. */
        _cleanup_free_ char *buf = strjoin("@@", path);
        if (!buf)
                return log_oom_debug();

        r = sysctl_write_verify("kernel/core_pattern", buf);
        if (r < 0)
                return log_debug_errno(r, "Failed to update kernel core pattern: %m");

        return 0;
}

static int vl_method_register_socket(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        assert(link);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "path", SD_JSON_VARIANT_STRING, json_dispatch_const_path, 0, SD_JSON_STRICT | SD_JSON_MANDATORY },
                {}
        };

        const char *path;
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &path);
        if (r != 0)
                return r;

        r = coredump_register_socket(path);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r) || r == -EINVAL)
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
                        "io.systemd.Coredump.Register.RegisterSocket", vl_method_register_socket);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}
