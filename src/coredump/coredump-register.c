/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "coredump-register.h"
#include "errno-util.h"
#include "fd-util.h"
#include "json-util.h"
#include "log.h"
#include "pidfd-util.h"
#include "process-util.h"
#include "string-util.h"
#include "sysctl-util.h"
#include "varlink-io.systemd.Coredump.Register.h"
#include "varlink-util.h"

static int set_core_pattern(const char *prefix, const char *val) {
        int r;

        assert(val);

        _cleanup_free_ char *buf = NULL;
        if (prefix) {
                buf = strjoin(prefix, val);
                if (!buf)
                        return -ENOMEM;
                val = buf;
        }

        /* Since be1e0283021ec73c2eb92839db9a471a068709d9 (v6.17), which is backported as
         * 7d7c1fb85cba5627bbe741fb7539c709435e3848 (v6.16.8), the kernel accepts any invalid patterns. The
         * written pattern is checked only on read, spuriously... Let's first save the original value, then
         * try to write the requested patter, and validate by reading the value. If the validation failed,
         * let's revert to the original value. */

        _cleanup_free_ char *original = NULL;
        r = sysctl_read("kernel/core_pattern", &original);
        if (r >= 0 && streq(original, val))
                return 0; /* Already set. */

        r = sysctl_write("kernel/core_pattern", val);
        if (r >= 0) {
                _cleanup_free_ char *current = NULL;
                r = sysctl_read("kernel/core_pattern", &current);
                if (r >= 0 && streq(current, val))
                        return 0; /* Yay! */
        }

        if (original)
                (void) sysctl_write("kernel/core_pattern", original);

        return r; /* Return the first error. */
}

static int coredump_register_socket(const char *path, int request_mode) {
        int r;

        assert(path);

        /* The coredump socket pattern is supported since kernel v6.16. Old kernels do not refuse the new
         * core patterns (moreover, any strings are accepted), hence, we need to check kernel version in some
         * ways other than reading/writing core patterns. The coredump socket feature requires the kernel to
         * to support PIDFD_INFO_COREDUMP flag in ioctl(PIDFD_GET_INFO), which is added by
         * 1d8db6fd698de1f73b1a7d72aea578fdd18d9a87 (v6.16). Let's check if the flag is supported. */

        _cleanup_close_ int pidfd = r = RET_NERRNO(pidfd_open(getpid_cached(), /* flags=*/ 0));
        if (r < 0)
                return log_debug_errno(r, "pidfd_open() failed: %m");

        struct pidfd_info info = {
                .mask = PIDFD_INFO_COREDUMP,
        };

        r = pidfd_get_info(pidfd, &info);
        if (r < 0)
                return log_debug_errno(r, "ioctl(PIDFD_GET_INFO) failed: %m");

        if (!FLAGS_SET(info.mask, PIDFD_INFO_COREDUMP))
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "PIDFD_INFO_COREDUMP flag is not supported.");

        /* If we do not know the kernel support the request mode is supported, let's first try to use core
         * pattern with "@@", which is supported since kernel v6.17. */
        if (request_mode != 0) {
                r = set_core_pattern("@@", path);
                if (r >= 0)
                        return 1;
                if (r != -EINVAL)
                        return r;
        }

        /* Next, let's try to use core pattern with "@", which is supported since kernel v6.16. */
        if (request_mode <= 0) {
                r = set_core_pattern("@", path);
                if (r >= 0)
                        return 0;
        }

        assert(r < 0);
        return r == -EINVAL ? -EOPNOTSUPP : r;
}

static int vl_method_register_socket(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        assert(link);

        struct {
                const char *path;
                int request_mode;
        } param = {
                .request_mode = -1,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "path",        SD_JSON_VARIANT_STRING,        json_dispatch_const_path,  voffsetof(param, path),         SD_JSON_STRICT | SD_JSON_MANDATORY },
                { "requestMode", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_tristate, voffsetof(param, request_mode), 0                                  },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &param);
        if (r != 0)
                return r;

        r = coredump_register_socket(param.path, param.request_mode);
        if (r == -EOPNOTSUPP)
                return sd_varlink_error(link, "io.systemd.Coredump.Register.CoredumpPatternNotSupported", NULL);
        if (r < 0)
                return r;

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("requestMode", r));
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
