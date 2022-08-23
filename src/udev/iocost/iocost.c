/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "cgroup-util.h"
#include "devnum-util.h"
#include "device-util.h"
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
               "  apply <path> [solution]    Apply the known solution for the device, if any, otherwise does nothing\n"
               "  query <path>               Query the known solution for the device\n"
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

static int get_known_solutions(sd_device *device, char ***solutions) {
        const char *value;
        int r;

        r = sd_device_get_property_value(device, "IOCOST_SOLUTIONS", &value);
        if (r < 0) {
                return 1;
        }

        *solutions = strv_split(value, " ");
        if (!*solutions)
                return log_oom();

        return 0;
}

static int query_named_solution(sd_device *device, const char *name, const char **model, const char **qos) {
        _cleanup_free_ char *upper_name = NULL, *qos_key = NULL, *model_key = NULL;
        _cleanup_strv_free_ char **solutions = NULL;
        int r;

        /* If NULL is passed we query the default solution, which is the first one listed
         * in the SOLUTIONS key.
         */
        if (name == NULL) {
                r = get_known_solutions(device, &solutions);

                /* A positive 1 return indicates no solutions exist for the device, which should not
                 * be treated as an error.
                 */
                if (r < 0)
                        return r;
                else if (r == 1)
                        return r;

                name = ASSERT_PTR(solutions[0]);
        }

        upper_name = strdup(name);
        if (!upper_name)
                return log_oom();

        ascii_strupper(upper_name);

        if (asprintf(&qos_key, "IOCOST_QOS_%s", upper_name) < 0)
                return log_oom();

        if (asprintf(&model_key, "IOCOST_MODEL_%s", upper_name) < 0)
                return log_oom();

        r = sd_device_get_property_value(device, model_key, model);
        if (r < 0) {
                log_error("Model key missing from hwdb for iocost solution '%s'.", name);
                return -1;
        }

        r = sd_device_get_property_value(device, qos_key, qos);
        if (r < 0) {
                log_error("QoS key missing from hwdb for iocost solution '%s'.", name);
                return -1;
        }

        return 0;
}

static int apply_solution_for_path(const char *path, const char *name) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        _cleanup_free_ char *model = NULL, *qos = NULL;
        const char *model_params = NULL, *qos_params = NULL;
        dev_t devnum;
        int r;

        r = sd_device_new_from_path(&device, path);
        if (r < 0)
                return log_error_errno(r, "Error looking up device: %m");

        r = query_named_solution(device, name, &model_params, &qos_params);
        if (r < 0)
                return r;
        else if (r == 1) {
                log_info("Parameters for iocost model missing from hwdb, doing nothing.");
                return 0;
        }

        r = sd_device_get_devnum(device, &devnum);
        if (r < 0)
                return log_error_errno(r, "Error getting devnum for device %s: %m", path);

        if (asprintf(&model, DEVNUM_FORMAT_STR " model=linear ctrl=user %s", DEVNUM_FORMAT_VAL(devnum), model_params) < 0)
                return log_oom();

        if (asprintf(&qos, DEVNUM_FORMAT_STR " enable=1 ctrl=user %s", DEVNUM_FORMAT_VAL(devnum), qos_params) < 0)
                return log_oom();

        log_debug("Applying iocost parameters to %s using solution '%s'\n\tio.cost.model: %s\n\tio.cost.qos: %s\n", path, name ? name : "default", model, qos);

        r = cg_set_attribute("io", NULL, "io.cost.qos", qos);
        if (r < 0)
                return log_error_errno(r, "Failed to set qos: %m");

        r = cg_set_attribute("io", NULL, "io.cost.model", model);
        if (r < 0)
                return log_error_errno(r, "Failed to set model: %m");

        return 0;
}

static int query_solutions_for_path(const char *path) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        _cleanup_strv_free_ char **solutions = NULL;
        const char *model_name = NULL;
        int r;

        r = sd_device_new_from_path(&device, path);
        if (r < 0)
                return log_error_errno(r, "Error looking up device: %m");

        if ((sd_device_get_property_value(device, "ID_MODEL_FROM_DATABASE", &model_name) < 0 &&
             sd_device_get_property_value(device, "ID_MODEL", &model_name) < 0)) {
                log_info("Model name for device %s is unknown", path);
                model_name = "Unknown";
        }

        r = get_known_solutions(device, &solutions);
        if (r < 0)
                return r;
        else if (r == 1) {
                printf("No solutions found for device %s, model name %s on hwdb.\n", path, model_name);
                return 0;
        }

        printf("Known solutions for %s model name: %s\n", path, model_name);
        STRV_FOREACH(s, solutions) {
                const char *model = NULL, *qos = NULL;

                r = query_named_solution(device, *s, &model, &qos);
                if (r < 0 || r == 1) {
                        log_error("Could not find solution named '%s'", *s);
                        return -1;
                }

                printf("\n[%s]\nio.cost.model: %s\nio.cost.qos: %s\n", *s, model, qos);
        }

        return 0;
}

static int verb_query(int argc, char *argv[], void *userdata) {
        const char *path = ASSERT_PTR(argv[1]);
        return query_solutions_for_path(path);
}

static int verb_apply(int argc, char *argv[], void *userdata) {
        const char *path = ASSERT_PTR(argv[1]);
        const char *name = argc > 2 ? ASSERT_PTR(argv[2]) : NULL;
        return apply_solution_for_path(path, name);
}

static int iocost_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "query", 2, 2, 0, verb_query },
                { "apply", 2, 3, 0, verb_apply },
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
