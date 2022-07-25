/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "cgroup-util.h"
#include "devnum-util.h"
#include "main-func.h"
#include "path-util.h"
#include "pretty-print.h"
#include "verbs.h"

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-iocost", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "Set up iocost model and qos solutions for block devices\n"
               "\nCommands:\n"
               "  apply <path or node>       Apply the known solution for the device, if any, otherwise does nothing\n"
               "\nOptions:\n"
               "  -h --help                  Show this help\n"
               "     --version               Show package version\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                {}
        };

        int c;

        assert(argc >= 1);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
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

        return 1;
}

static int apply_solution_for_path(const char *path) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        _cleanup_free_ char *qos = NULL, *model = NULL;
        const char *params;
        dev_t devnum;
        int r;

        r = sd_device_new_from_path(&device, path);
        if (r < 0)
                return log_error_errno(r, "Error looking up device: %m");

        r = sd_device_get_devnum(device, &devnum);
        if (r < 0)
                return log_error_errno(r, "Error getting devnum for device %s: %m", path);

        r = sd_device_get_property_value(device, "IOCOST_TUNE_MODEL", &params);
        if (r < 0) {
                log_info("Parameters for iocost model not available, doing nothing.");
                return 0;
        }
        if (asprintf(&model, DEVNUM_FORMAT_STR " model=linear ctrl=user %s", DEVNUM_FORMAT_VAL(devnum), params) < 0)
                return log_oom();

        r = sd_device_get_property_value(device, "IOCOST_TUNE_QOS", &params);
        if (r < 0) {
                log_info("Parameters for iocost qos not available, doing nothing.");
                return 0;
        }
        if (asprintf(&qos, DEVNUM_FORMAT_STR " enable=1 ctrl=user %s", DEVNUM_FORMAT_VAL(devnum), params) < 0)
                return log_oom();

        log_debug("Applying iocost parameters to %s\n\tio.cost.model: %s\n\tio.cost.qos: %s\n", path, model, qos);

        r = cg_set_attribute("io", NULL, "io.cost.qos", qos);
        if (r < 0)
                return log_error_errno(r, "Failed to set qos: %m");

        r = cg_set_attribute("io", NULL, "io.cost.model", model);
        if (r < 0)
                return log_error_errno(r, "Failed to set model: %m");

        return 0;
}

static int verb_apply(int argc, char *argv[], void *userdata) {
        const char *path = ASSERT_PTR(argv[1]);
        return apply_solution_for_path(path);
}

static int iocost_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "apply", 2, 2, 0, verb_apply },
                {},
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return iocost_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
