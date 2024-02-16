/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-log-control-api.h"
#include "bus-message.h"
#include "bus-polkit.h"
#include "bus-unit-util.h"
#include "constants.h"
#include "daemon-util.h"
#include "kbd-util.h"
#include "localed-util.h"
#include "macro.h"
#include "main-func.h"
#include "missing_capability.h"
#include "path-util.h"
#include "selinux-util.h"
#include "service-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

static int vconsole_reload(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);

        r = bus_call_method(bus, bus_systemd_mgr, "RestartUnit", &error, NULL, "ss", "systemd-vconsole-setup.service", "replace");
        if (r < 0)
                return log_error_errno(r, "Failed to issue method call: %s", bus_error_message(&error, r));
        return 0;
}

static int property_get_locale(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Context *c = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **l = NULL;
        int r;

        r = locale_read_data(c, reply);
        if (r < 0)
                return r;

        r = locale_context_build_env(&c->locale_context, &l, NULL);
        if (r < 0)
                return r;

        return sd_bus_message_append_strv(reply, l);
}

static int property_get_vconsole(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(property);

        r = vconsole_read_data(c, reply);
        if (r < 0)
                return r;

        if (streq(property, "VConsoleKeymap"))
                return sd_bus_message_append_basic(reply, 's', c->vc.keymap);
        if (streq(property, "VConsoleKeymapToggle"))
                return sd_bus_message_append_basic(reply, 's', c->vc.toggle);

        return -EINVAL;
}

static int property_get_xkb(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Context *c = ASSERT_PTR(userdata);
        const X11Context *xc;
        int r;

        assert(property);

        r = vconsole_read_data(c, reply);
        if (r < 0)
                return r;

        r = x11_read_data(c, reply);
        if (r < 0)
                return r;

        xc = context_get_x11_context(c);

        if (streq(property, "X11Layout"))
                return sd_bus_message_append_basic(reply, 's', xc->layout);
        if (streq(property, "X11Model"))
                return sd_bus_message_append_basic(reply, 's', xc->model);
        if (streq(property, "X11Variant"))
                return sd_bus_message_append_basic(reply, 's', xc->variant);
        if (streq(property, "X11Options"))
                return sd_bus_message_append_basic(reply, 's', xc->options);

        return -EINVAL;
}

static int process_locale_list_item(
                const char *assignment,
                char *new_locale[static _VARIABLE_LC_MAX],
                bool use_localegen,
                sd_bus_error *error) {

        assert(assignment);
        assert(new_locale);

        for (LocaleVariable p = 0; p < _VARIABLE_LC_MAX; p++) {
                const char *name, *e;

                assert_se(name = locale_variable_to_string(p));

                e = startswith(assignment, name);
                if (!e)
                        continue;

                if (*e != '=')
                        continue;

                e++;

                if (!locale_is_valid(e))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Locale %s is not valid, refusing.", e);
                if (!use_localegen && locale_is_installed(e) <= 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Locale %s not installed, refusing.", e);
                if (new_locale[p])
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Locale variable %s set twice, refusing.", name);

                new_locale[p] = strdup(e);
                if (!new_locale[p])
                        return -ENOMEM;

                return 0;
        }

        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Locale assignment %s not valid, refusing.", assignment);
}

static int locale_gen_process_locale(char *new_locale[static _VARIABLE_LC_MAX], sd_bus_error *error) {
        int r;

        assert(new_locale);

        for (LocaleVariable p = 0; p < _VARIABLE_LC_MAX; p++) {
                if (p == VARIABLE_LANGUAGE)
                        continue;
                if (isempty(new_locale[p]))
                        continue;
                if (locale_is_installed(new_locale[p]))
                        continue;

                r = locale_gen_enable_locale(new_locale[p]);
                if (r == -ENOEXEC) {
                        log_error_errno(r, "Refused to enable locale for generation: %m");
                        return sd_bus_error_setf(error,
                                                 SD_BUS_ERROR_INVALID_ARGS,
                                                 "Specified locale is not installed and non-UTF-8 locale will not be auto-generated: %s",
                                                 new_locale[p]);
                }
                if (r == -EINVAL) {
                        log_error_errno(r, "Failed to enable invalid locale %s for generation.", new_locale[p]);
                        return sd_bus_error_setf(error,
                                                 SD_BUS_ERROR_INVALID_ARGS,
                                                 "Cannot enable locale generation for invalid locale: %s",
                                                 new_locale[p]);
                }
                if (r < 0) {
                        log_error_errno(r, "Failed to enable locale for generation: %m");
                        return sd_bus_error_set_errnof(error, r, "Failed to enable locale generation: %m");
                }

                r = locale_gen_run();
                if (r < 0) {
                        log_error_errno(r, "Failed to generate locale: %m");
                        return sd_bus_error_set_errnof(error, r, "Failed to generate locale: %m");
                }
        }

        return 0;
}

static int method_set_locale(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_(locale_variables_freep) char *new_locale[_VARIABLE_LC_MAX] = {};
        _cleanup_strv_free_ char **l = NULL, **l_set = NULL, **l_unset = NULL;
        Context *c = ASSERT_PTR(userdata);
        int interactive, r;
        bool use_localegen;

        assert(m);

        r = sd_bus_message_read_strv(m, &l);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_read_basic(m, 'b', &interactive);
        if (r < 0)
                return bus_log_parse_error(r);

        use_localegen = locale_gen_check_available();

        /* If single locale without variable name is provided, then we assume it is LANG=. */
        if (strv_length(l) == 1 && !strchr(l[0], '=')) {
                if (!locale_is_valid(l[0]))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid locale specification: %s", l[0]);
                if (!use_localegen && locale_is_installed(l[0]) <= 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Specified locale is not installed: %s", l[0]);

                new_locale[VARIABLE_LANG] = strdup(l[0]);
                if (!new_locale[VARIABLE_LANG])
                        return log_oom();

                l = strv_free(l);
        }

        /* Check whether a variable is valid */
        STRV_FOREACH(i, l) {
                r = process_locale_list_item(*i, new_locale, use_localegen, error);
                if (r < 0)
                        return r;
        }

        /* If LANG was specified, but not LANGUAGE, check if we should
         * set it based on the language fallback table. */
        if (!isempty(new_locale[VARIABLE_LANG]) &&
            isempty(new_locale[VARIABLE_LANGUAGE])) {
                _cleanup_free_ char *language = NULL;

                (void) find_language_fallback(new_locale[VARIABLE_LANG], &language);
                if (language) {
                        log_debug("Converted LANG=%s to LANGUAGE=%s", new_locale[VARIABLE_LANG], language);
                        free_and_replace(new_locale[VARIABLE_LANGUAGE], language);
                }
        }

        r = locale_read_data(c, m);
        if (r < 0) {
                log_error_errno(r, "Failed to read locale data: %m");
                return sd_bus_error_set(error, SD_BUS_ERROR_FAILED, "Failed to read locale data");
        }

        /* Merge with the current settings */
        r = locale_context_merge(&c->locale_context, new_locale);
        if (r < 0)
                return log_oom();

        locale_variables_simplify(new_locale);

        if (locale_context_equal(&c->locale_context, new_locale)) {
                log_debug("Locale settings were not modified.");
                return sd_bus_reply_method_return(m, NULL);
        }

        r = bus_verify_polkit_async_full(
                        m,
                        "org.freedesktop.locale1.set-locale",
                        /* details= */ NULL,
                        interactive,
                        /* good_user= */ UID_INVALID,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        /* Generate locale in case it is missing and the system is using locale-gen */
        if (use_localegen) {
                r = locale_gen_process_locale(new_locale, error);
                if (r < 0)
                        return r;
        }

        locale_context_take(&c->locale_context, new_locale);

        /* Write locale configuration */
        r = locale_context_save(&c->locale_context, &l_set, &l_unset);
        if (r < 0) {
                log_error_errno(r, "Failed to set locale: %m");
                return sd_bus_error_set_errnof(error, r, "Failed to set locale: %m");
        }

        /* Since we just updated the locale configuration file, ask the system manager to read it again to
         * update its default locale settings. It's important to not use UnsetAndSetEnvironment or a similar
         * method because in this case unsetting variables means restoring them to PID1 default values, which
         * may be outdated, since locale.conf has just changed and PID1 hasn't read it */
        (void) bus_service_manager_reload(sd_bus_message_get_bus(m));

        if (!strv_isempty(l_set)) {
                _cleanup_free_ char *line = NULL;

                line = strv_join(l_set, ", ");
                log_info("Changed locale to %s.", strnull(line));
        } else
                log_info("Changed locale to unset.");

        (void) sd_bus_emit_properties_changed(
                        sd_bus_message_get_bus(m),
                        "/org/freedesktop/locale1",
                        "org.freedesktop.locale1",
                        "Locale", NULL);

        return sd_bus_reply_method_return(m, NULL);
}

static int method_set_vc_keyboard(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_(x11_context_clear) X11Context converted = {};
        Context *c = ASSERT_PTR(userdata);
        int convert, interactive, r;
        bool x_needs_update;
        VCContext in;

        assert(m);

        r = sd_bus_message_read(m, "ssbb", &in.keymap, &in.toggle, &convert, &interactive);
        if (r < 0)
                return bus_log_parse_error(r);

        vc_context_empty_to_null(&in);

        r = vc_context_verify_and_warn(&in, LOG_ERR, error);
        if (r < 0)
                return r;

        r = vconsole_read_data(c, m);
        if (r < 0) {
                log_error_errno(r, "Failed to read virtual console keymap data: %m");
                return sd_bus_error_set_errnof(error, r, "Failed to read virtual console keymap data: %m");
        }

        r = x11_read_data(c, m);
        if (r < 0) {
                log_error_errno(r, "Failed to read X11 keyboard layout data: %m");
                return sd_bus_error_set_errnof(error, r, "Failed to read X11 keyboard layout data: %m");
        }

        if (convert) {
                r = vconsole_convert_to_x11(&in, &converted);
                if (r < 0) {
                        log_error_errno(r, "Failed to convert keymap data: %m");
                        return sd_bus_error_set_errnof(error, r, "Failed to convert keymap data: %m");
                }

                if (x11_context_isempty(&converted))
                        log_notice("No conversion found for virtual console keymap \"%s\".", strempty(in.keymap));
                else
                        log_info("The virtual console keymap '%s' is converted to X11 keyboard layout '%s' model '%s' variant '%s' options '%s'",
                                 in.keymap, strempty(converted.layout), strempty(converted.model), strempty(converted.variant), strempty(converted.options));

                /* save the result of conversion to emit changed properties later. */
                x_needs_update = !x11_context_equal(&c->x11_from_vc, &converted) || !x11_context_equal(&c->x11_from_xorg, &converted);
        } else
                x_needs_update = !x11_context_equal(&c->x11_from_vc, &c->x11_from_xorg);

        if (vc_context_equal(&c->vc, &in) && !x_needs_update)
                return sd_bus_reply_method_return(m, NULL);

        r = bus_verify_polkit_async_full(
                        m,
                        "org.freedesktop.locale1.set-keyboard",
                        /* details= */ NULL,
                        interactive,
                        /* good_user= */ UID_INVALID,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = vc_context_copy(&c->vc, &in);
        if (r < 0)
                return log_oom();

        if (x_needs_update) {
                if (convert) {
                        r = x11_context_copy(&c->x11_from_vc, &converted);
                        if (r < 0)
                                return log_oom();
                        x11_context_replace(&c->x11_from_xorg, &converted);
                } else {
                        const X11Context *xc = context_get_x11_context(c);

                        /* Even if the conversion is not requested, sync the two X11 contexts. */
                        r = x11_context_copy(&c->x11_from_vc, xc);
                        if (r < 0)
                                return log_oom();

                        r = x11_context_copy(&c->x11_from_xorg, xc);
                        if (r < 0)
                                return log_oom();
                }
        }

        r = vconsole_write_data(c);
        if (r < 0)
                log_warning_errno(r, "Failed to write virtual console keymap, ignoring: %m");

        if (x_needs_update) {
                r = x11_write_data(c);
                if (r < 0)
                        log_warning_errno(r, "Failed to write X11 keyboard layout, ignoring: %m");
        }

        log_info("Changed virtual console keymap to '%s' toggle '%s'",
                 strempty(c->vc.keymap), strempty(c->vc.toggle));

        (void) vconsole_reload(sd_bus_message_get_bus(m));

        (void) sd_bus_emit_properties_changed(
                        sd_bus_message_get_bus(m),
                        "/org/freedesktop/locale1",
                        "org.freedesktop.locale1",
                        "VConsoleKeymap", "VConsoleKeymapToggle",
                        x_needs_update ? "X11Layout"  : NULL,
                        x_needs_update ? "X11Model"   : NULL,
                        x_needs_update ? "X11Variant" : NULL,
                        x_needs_update ? "X11Options" : NULL,
                        NULL);

        return sd_bus_reply_method_return(m, NULL);
}

static int method_set_x11_keyboard(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_(vc_context_clear) VCContext converted = {};
        Context *c = ASSERT_PTR(userdata);
        int convert, interactive, r;
        X11Context in;

        assert(m);

        r = sd_bus_message_read(m, "ssssbb", &in.layout, &in.model, &in.variant, &in.options, &convert, &interactive);
        if (r < 0)
                return bus_log_parse_error(r);

        x11_context_empty_to_null(&in);

        r = x11_context_verify_and_warn(&in, LOG_ERR, error);
        if (r < 0)
                return r;

        r = vconsole_read_data(c, m);
        if (r < 0) {
                log_error_errno(r, "Failed to read virtual console keymap data: %m");
                return sd_bus_error_set_errnof(error, r, "Failed to read virtual console keymap data: %m");
        }

        r = x11_read_data(c, m);
        if (r < 0) {
                log_error_errno(r, "Failed to read x11 keyboard layout data: %m");
                return sd_bus_error_set(error, SD_BUS_ERROR_FAILED, "Failed to read x11 keyboard layout data");
        }

        if (convert) {
                r = x11_convert_to_vconsole(&in, &converted);
                if (r < 0) {
                        log_error_errno(r, "Failed to convert keymap data: %m");
                        return sd_bus_error_set_errnof(error, r, "Failed to convert keymap data: %m");
                }

                if (vc_context_isempty(&converted))
                        /* We search for layout-variant match first, but then we also look
                         * for anything which matches just the layout. So it's accurate to say
                         * that we couldn't find anything which matches the layout. */
                        log_notice("No conversion to virtual console map found for \"%s\".", strempty(in.layout));
                else
                        log_info("The X11 keyboard layout '%s' is converted to virtual console keymap '%s'",
                                 in.layout, converted.keymap);

                /* save the result of conversion to emit changed properties later. */
                convert = !vc_context_equal(&c->vc, &converted);
        }

        if (x11_context_equal(&c->x11_from_vc, &in) && x11_context_equal(&c->x11_from_xorg, &in) && !convert)
                return sd_bus_reply_method_return(m, NULL);

        r = bus_verify_polkit_async_full(
                        m,
                        "org.freedesktop.locale1.set-keyboard",
                        /* details= */ NULL,
                        interactive,
                        /* good_user= */ UID_INVALID,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = x11_context_copy(&c->x11_from_vc, &in);
        if (r < 0)
                return log_oom();

        r = x11_context_copy(&c->x11_from_xorg, &in);
        if (r < 0)
                return log_oom();

        if (convert)
                vc_context_replace(&c->vc, &converted);

        r = vconsole_write_data(c);
        if (r < 0)
                log_warning_errno(r, "Failed to update vconsole.conf, ignoring: %m");

        r = x11_write_data(c);
        if (r < 0)
                log_warning_errno(r, "Failed to write X11 keyboard layout, ignoring: %m");

        log_info("Changed X11 keyboard layout to '%s' model '%s' variant '%s' options '%s'",
                 strempty(in.layout),
                 strempty(in.model),
                 strempty(in.variant),
                 strempty(in.options));

        (void) sd_bus_emit_properties_changed(
                        sd_bus_message_get_bus(m),
                        "/org/freedesktop/locale1",
                        "org.freedesktop.locale1",
                        "X11Layout", "X11Model", "X11Variant", "X11Options",
                        convert ? "VConsoleKeymap" : NULL,
                        convert ? "VConsoleKeymapToggle" : NULL,
                        NULL);

        if (convert)
                (void) vconsole_reload(sd_bus_message_get_bus(m));

        return sd_bus_reply_method_return(m, NULL);
}

static const sd_bus_vtable locale_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Locale", "as", property_get_locale, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("X11Layout", "s", property_get_xkb, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("X11Model", "s", property_get_xkb, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("X11Variant", "s", property_get_xkb, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("X11Options", "s", property_get_xkb, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("VConsoleKeymap", "s", property_get_vconsole, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("VConsoleKeymapToggle", "s", property_get_vconsole, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),

        SD_BUS_METHOD_WITH_ARGS("SetLocale",
                                SD_BUS_ARGS("as", locale, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_locale,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetVConsoleKeyboard",
                                SD_BUS_ARGS("s", keymap, "s", keymap_toggle, "b", convert, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_vc_keyboard,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetX11Keyboard",
                                SD_BUS_ARGS("s", layout, "s", model, "s", variant, "s", options, "b", convert, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_x11_keyboard,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END
};

static const BusObjectImplementation manager_object = {
        "/org/freedesktop/locale1",
        "org.freedesktop.locale1",
        .vtables = BUS_VTABLES(locale_vtable),
};

static int connect_bus(Context *c, sd_event *event, sd_bus **_bus) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(c);
        assert(event);
        assert(_bus);

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to get system bus connection: %m");

        r = bus_add_implementation(bus, &manager_object, c);
        if (r < 0)
                return r;

        r = bus_log_control_api_register(bus);
        if (r < 0)
                return r;

        r = sd_bus_request_name_async(bus, NULL, "org.freedesktop.locale1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        *_bus = TAKE_PTR(bus);

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(context_clear) Context context = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        log_setup();

        r = service_parse_argv("systemd-localed.service",
                               "Manage system locale settings and key mappings.",
                               BUS_IMPLEMENTATIONS(&manager_object,
                                                   &log_control_object),
                               argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        r = mac_init();
        if (r < 0)
                return r;

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        (void) sd_event_set_watchdog(event, true);

        r = sd_event_set_signal_exit(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT/SIGTERM handlers: %m");

        r = connect_bus(&context, event, &bus);
        if (r < 0)
                return r;

        r = sd_notify(false, NOTIFY_READY);
        if (r < 0)
                log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");

        r = bus_event_loop_with_idle(event, bus, "org.freedesktop.locale1", DEFAULT_EXIT_USEC, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
