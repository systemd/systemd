/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "alloc-util.h"
#include "build.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "log.h"
#include "main-func.h"
#include "sd-varlink.h"

static int metrics_on_query_reply(
        sd_varlink *link,
        sd_json_variant *parameters,
        const char *error,
        sd_varlink_reply_flags_t flags,
        void *userdata) {

        int *ret = ASSERT_PTR(userdata), r;

        assert(link);

        if (error) {
                /* If we can translate this to an errno, let's print that as errno and return it, otherwise, return a generic error code */
                r = sd_varlink_error_to_errno(error, parameters);
                if (r != -EBADR)
                        *ret = log_error_errno(r, "Method call failed: %m");
                else
                        r = *ret = log_error_errno(SYNTHETIC_ERRNO(EBADE), "Method call failed: %s", error);
        } else
                r = 0;

        sd_json_variant_dump(parameters, SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO, stdout, NULL);

        return r;
}

static int metrics_call(const char *path) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        assert(path);

        r = sd_varlink_connect_address(&vl, path);
        if (r < 0)
                return log_debug_errno(r, "Unable to connect to %s: %m", path);

        int ret = 0;
        sd_varlink_set_userdata(vl, &ret);

        r = sd_varlink_bind_reply(vl, metrics_on_query_reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to bind reply callback: %m");

        r = sd_varlink_observe(vl, "io.systemd.Metrics.List", /* parameter */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to invoke varlink method: %m");

        for (;;) {
                r = sd_varlink_is_idle(vl);

                if (r < 0)
                        return log_error_errno(r, "Failed to check if varlink connection is idle: %m");
                if (r > 0) {
                        break;
                }

                r = sd_varlink_process(vl);
                if (r < 0)
                        return log_error_errno(r, "Failed to process varlink connection: %m");
                if (r != 0)
                        continue;

                r = sd_varlink_wait(vl, USEC_INFINITY);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for varlink connection events: %m");
        }

        return ret;
}

static int metrics_start_query(void) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        d = opendir("/run/systemd/metrics/");
        if (!d) {
                if (errno == ENOENT)
                        return -ESRCH;

                return -errno;
        }

        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_free_ char *p = NULL;

                p = path_join("/run/systemd/metrics/", de->d_name);
                if (!p)
                        return -ENOMEM;

                r = metrics_call(p);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Print metrics for all systemd components.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100
        };

        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'               },
                { "version",       no_argument,       NULL, ARG_VERSION       },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hp", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s takes no arguments.",
                                       program_invocation_short_name);

        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        /* This is mostly intended to be used for scripts which want
         * to detect whether we are being run in a virtualized
         * environment or not */

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = metrics_start_query();
        if (r < 0)
                return r;

        return 0;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
