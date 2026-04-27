/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "build.h"
#include "cgroup-util.h"
#include "conf-parser.h"
#include "device-util.h"
#include "devnum-util.h"
#include "format-table.h"
#include "help-util.h"
#include "main-func.h"
#include "options.h"
#include "string-util.h"
#include "strv.h"
#include "udev-util.h"
#include "verbs.h"

static char *arg_target_solution = NULL;
STATIC_DESTRUCTOR_REGISTER(arg_target_solution, freep);

static int parse_config(void) {
        static const ConfigTableItem items[] = {
                { "IOCost", "TargetSolution", config_parse_string, 0, &arg_target_solution },
        };
        int r;

        r = config_parse(
                        NULL,
                        "/etc/udev/iocost.conf",
                        NULL,
                        "IOCost\0",
                        config_item_table_lookup,
                        items,
                        CONFIG_PARSE_WARN,
                        NULL,
                        NULL);
        if (r < 0)
                return r;

        if (!arg_target_solution) {
                arg_target_solution = strdup("naive");
                if (!arg_target_solution)
                        return log_oom();
        }

        log_debug("Target solution: %s", arg_target_solution);
        return 0;
}

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL, *verbs = NULL;
        int r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, options, verbs);

        help_cmdline("[OPTIONS...] COMMAND");
        help_abstract("Set up iocost model and qos solutions for block devices.");

        help_section("Commands:");
        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        help_section("Options:");
        return table_print_or_warn(options);
}

VERB_COMMON_HELP_HIDDEN(help);

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser state = { argc, argv };
        const char *arg;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();
                }

        *remaining_args = option_parser_get_args(&state);
        return 1;
}

static int get_known_solutions(sd_device *device, int log_level, char ***ret_solutions, const char **ret_selected) {
        _cleanup_free_ char **s = NULL;
        const char *value, *found;
        int r;

        assert(ret_solutions);
        assert(ret_selected);

        r = sd_device_get_property_value(device, "IOCOST_SOLUTIONS", &value);
        if (r == -ENOENT)
                return log_device_full_errno(device, log_level, r, "No iocost solution found for device.");
        if (r < 0)
                return log_device_error_errno(device, r, "Failed to query solutions from device: %m");

        s = strv_split(value, WHITESPACE);
        if (!s)
                return log_oom();
        if (strv_isempty(s))
                return log_device_error_errno(device, SYNTHETIC_ERRNO(EINVAL),
                                              "IOCOST_SOLUTIONS exists in hwdb but is empty.");

        found = strv_find(s, arg_target_solution);
        if (found) {
                *ret_selected = found;
                log_device_debug(device, "Selected solution based on target solution: %s", *ret_selected);
        } else {
                *ret_selected = s[0];
                log_device_debug(device, "Selected first available solution: %s", *ret_selected);
        }

        *ret_solutions = TAKE_PTR(s);
        return 0;
}

static int query_named_solution(
                sd_device *device,
                const char *name,
                const char **ret_model,
                const char **ret_qos) {

        _cleanup_free_ char *upper_name = NULL, *qos_key = NULL, *model_key = NULL;
        const char *qos, *model;
        int r;

        assert(name);
        assert(ret_qos);
        assert(ret_model);

        upper_name = strdup(name);
        if (!upper_name)
                return log_oom();

        ascii_strupper(upper_name);
        string_replace_char(upper_name, '-', '_');

        qos_key = strjoin("IOCOST_QOS_", upper_name);
        if (!qos_key)
                return log_oom();

        model_key = strjoin("IOCOST_MODEL_", upper_name);
        if (!model_key)
                return log_oom();

        r = sd_device_get_property_value(device, qos_key, &qos);
        if (r == -ENOENT)
                return log_device_debug_errno(device, r, "No value found for key %s, skipping iocost logic.", qos_key);
        if (r < 0)
                return log_device_error_errno(device, r, "Failed to obtain QoS for iocost solution from device: %m");

        r = sd_device_get_property_value(device, model_key, &model);
        if (r == -ENOENT)
                return log_device_debug_errno(device, r, "No value found for key %s, skipping iocost logic.", model_key);
        if (r < 0)
                return log_device_error_errno(device, r, "Failed to obtain model for iocost solution from device: %m");

        *ret_qos = qos;
        *ret_model = model;

        return 0;
}

static int apply_solution_for_path(const char *path, const char *name) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        _cleanup_strv_free_ char **solutions = NULL;
        _cleanup_free_ char *qos = NULL, *model = NULL;
        const char *qos_params, *model_params;
        dev_t devnum;
        int r;

        r = sd_device_new_from_path(&device, path);
        if (r < 0)
                return log_error_errno(r, "Error looking up device: %m");

        r = sd_device_get_devnum(device, &devnum);
        if (r < 0)
                return log_device_error_errno(device, r, "Error getting devnum: %m");

        if (!name) {
                r = get_known_solutions(device, LOG_DEBUG, &solutions, &name);
                if (r == -ENOENT)
                        return 0;
                if (r < 0)
                        return r;
        }

        r = query_named_solution(device, name, &model_params, &qos_params);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        if (asprintf(&qos, DEVNUM_FORMAT_STR " enable=1 ctrl=user %s", DEVNUM_FORMAT_VAL(devnum), qos_params) < 0)
                return log_oom();

        if (asprintf(&model, DEVNUM_FORMAT_STR " model=linear ctrl=user %s", DEVNUM_FORMAT_VAL(devnum), model_params) < 0)
                return log_oom();

        log_debug("Applying iocost parameters to %s using solution '%s'\n"
                  "\tio.cost.qos: %s\n"
                  "\tio.cost.model: %s\n",
                  path, name, qos, model);

        r = cg_set_attribute(/* path= */ NULL, "io.cost.qos", qos);
        if (r < 0) {
                log_device_full_errno(device, r == -ENOENT ? LOG_DEBUG : LOG_ERR, r, "Failed to set io.cost.qos: %m");
                return r == -ENOENT ? 0 : r;
        }

        r = cg_set_attribute(/* path= */ NULL, "io.cost.model", model);
        if (r < 0) {
                log_device_full_errno(device, r == -ENOENT ? LOG_DEBUG : LOG_ERR, r, "Failed to set io.cost.model: %m");
                return r == -ENOENT ? 0 : r;
        }

        return 0;
}

static int query_solutions_for_path(const char *path) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        _cleanup_strv_free_ char **solutions = NULL;
        const char *selected_solution, *model_name;
        int r;

        r = sd_device_new_from_path(&device, path);
        if (r < 0)
                return log_error_errno(r, "Error looking up device: %m");

        r = device_get_model_string(device, &model_name);
        if (r == -ENOENT) {
                log_device_info(device, "Device model not found");
                return 0;
        }
        if (r < 0)
                return log_device_error_errno(device, r, "Model name for device %s is unknown", path);

        r = get_known_solutions(device, LOG_INFO, &solutions, &selected_solution);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        log_info("Known solutions for %s model name: \"%s\"\n"
                 "Preferred solution: %s\n"
                 "Solution that would be applied: %s",
                 path, model_name,
                 arg_target_solution, selected_solution);

        STRV_FOREACH(s, solutions) {
                const char *model, *qos;

                if (query_named_solution(device, *s, &model, &qos) < 0)
                        continue;

                log_info("%s: io.cost.qos: %s\n"
                         "%s: io.cost.model: %s", *s, qos, *s, model);
        }

        return 0;
}

VERB(verb_query, "query", "PATH", 2, 2, 0,
     "Query the known solution for the device");
static int verb_query(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return query_solutions_for_path(ASSERT_PTR(argv[1]));
}

VERB(verb_apply, "apply", "PATH [SOLUTION]", 2, 3, 0,
     "Apply solution for the device if found, do nothing otherwise");
static int verb_apply(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return apply_solution_for_path(
                        ASSERT_PTR(argv[1]),
                        argc > 2 ? ASSERT_PTR(argv[2]) : NULL);
}

static int run(int argc, char *argv[]) {
        char **args = NULL;
        int r;

        log_setup();

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        r = parse_config();
        if (r < 0)
                return r;

        return dispatch_verb_with_args(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
