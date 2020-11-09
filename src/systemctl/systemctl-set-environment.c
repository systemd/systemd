/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "env-util.h"
#include "escape.h"
#include "systemctl-set-environment.h"
#include "systemctl-util.h"
#include "systemctl.h"

static int print_variable(const char *s) {
        const char *sep;
        _cleanup_free_ char *esc = NULL;

        sep = strchr(s, '=');
        if (!sep)
                return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                       "Invalid environment block");

        esc = shell_maybe_quote(sep + 1, ESCAPE_POSIX);
        if (!esc)
                return log_oom();

        printf("%.*s=%s\n", (int)(sep-s), s, esc);
        return 0;
}

int show_environment(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *text;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        (void) pager_open(arg_pager_flags);

        r = bus_get_property(bus, bus_systemd_mgr, "Environment", &error, &reply, "as");
        if (r < 0)
                return log_error_errno(r, "Failed to get environment: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "s");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read_basic(reply, SD_BUS_TYPE_STRING, &text)) > 0) {
                r = print_variable(text);
                if (r < 0)
                        return r;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        return 0;
}

static void invalid_callback(const char *p, void *userdata) {
        _cleanup_free_ char *t = cescape(p);

        log_debug("Ignoring invalid environment assignment \"%s\".", strnull(t));
}

int set_environment(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        const char *method;
        sd_bus *bus;
        int r;

        assert(argc > 1);
        assert(argv);

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();

        method = streq(argv[0], "set-environment")
                ? "SetEnvironment"
                : "UnsetEnvironment";

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, method);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, strv_skip(argv, 1));
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to set environment: %s", bus_error_message(&error, r));

        return 0;
}

int import_environment(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "SetEnvironment");
        if (r < 0)
                return bus_log_create_error(r);

        if (argc < 2) {
                _cleanup_strv_free_ char **copy = NULL;

                copy = strv_copy(environ);
                if (!copy)
                        return log_oom();

                strv_env_clean_with_callback(copy, invalid_callback, NULL);

                r = sd_bus_message_append_strv(m, copy);

        } else {
                char **a, **b;

                r = sd_bus_message_open_container(m, 'a', "s");
                if (r < 0)
                        return bus_log_create_error(r);

                STRV_FOREACH(a, strv_skip(argv, 1)) {

                        if (!env_name_is_valid(*a))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not a valid environment variable name: %s", *a);

                        STRV_FOREACH(b, environ) {
                                const char *eq;

                                eq = startswith(*b, *a);
                                if (eq && *eq == '=') {

                                        r = sd_bus_message_append(m, "s", *b);
                                        if (r < 0)
                                                return bus_log_create_error(r);

                                        break;
                                }
                        }
                }

                r = sd_bus_message_close_container(m);
        }
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to import environment: %s", bus_error_message(&error, r));

        return 0;
}
