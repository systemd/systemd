/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if HAVE_XKBCOMMON
#include <xkbcommon/xkbcommon.h>
#include <dlfcn.h>
#endif

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-log-control-api.h"
#include "bus-message.h"
#include "bus-polkit.h"
#include "def.h"
#include "dlfcn-util.h"
#include "kbd-util.h"
#include "keymap-util.h"
#include "locale-util.h"
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

static int locale_update_system_manager(Context *c, sd_bus *bus) {
        _cleanup_free_ char **l_unset = NULL;
        _cleanup_strv_free_ char **l_set = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        size_t c_set = 0, c_unset = 0;
        int r;

        assert(bus);

        l_unset = new0(char*, _VARIABLE_LC_MAX);
        if (!l_unset)
                return log_oom();

        l_set = new0(char*, _VARIABLE_LC_MAX);
        if (!l_set)
                return log_oom();

        for (LocaleVariable p = 0; p < _VARIABLE_LC_MAX; p++) {
                const char *name;

                name = locale_variable_to_string(p);
                assert(name);

                if (isempty(c->locale[p]))
                        l_unset[c_set++] = (char*) name;
                else {
                        char *s;

                        s = strjoin(name, "=", c->locale[p]);
                        if (!s)
                                return log_oom();

                        l_set[c_unset++] = s;
                }
        }

        assert(c_set + c_unset == _VARIABLE_LC_MAX);
        r = sd_bus_message_new_method_call(bus, &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "UnsetAndSetEnvironment");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, l_unset);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, l_set);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to update the manager environment: %s", bus_error_message(&error, r));

        return 0;
}

static int vconsole_reload(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);

        r = sd_bus_call_method(bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "RestartUnit",
                        &error,
                        NULL,
                        "ss", "systemd-vconsole-setup.service", "replace");

        if (r < 0)
                return log_error_errno(r, "Failed to issue method call: %s", bus_error_message(&error, r));

        return 0;
}

static int vconsole_convert_to_x11_and_emit(Context *c, sd_bus_message *m) {
        int r;

        assert(m);

        r = x11_read_data(c, m);
        if (r < 0)
                return r;

        r = vconsole_convert_to_x11(c);
        if (r <= 0)
                return r;

        /* modified */
        r = x11_write_data(c);
        if (r < 0)
                return log_error_errno(r, "Failed to write X11 keyboard layout: %m");

        sd_bus_emit_properties_changed(sd_bus_message_get_bus(m),
                                       "/org/freedesktop/locale1",
                                       "org.freedesktop.locale1",
                                       "X11Layout", "X11Model", "X11Variant", "X11Options", NULL);

        return 1;
}

static int x11_convert_to_vconsole_and_emit(Context *c, sd_bus_message *m) {
        int r;

        assert(m);

        r = vconsole_read_data(c, m);
        if (r < 0)
                return r;

        r = x11_convert_to_vconsole(c);
        if (r <= 0)
                return r;

        /* modified */
        r = vconsole_write_data(c);
        if (r < 0)
                log_error_errno(r, "Failed to save virtual console keymap: %m");

        sd_bus_emit_properties_changed(sd_bus_message_get_bus(m),
                                       "/org/freedesktop/locale1",
                                       "org.freedesktop.locale1",
                                       "VConsoleKeymap", "VConsoleKeymapToggle", NULL);

        return vconsole_reload(sd_bus_message_get_bus(m));
}

static int property_get_locale(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Context *c = userdata;
        _cleanup_strv_free_ char **l = NULL;
        int r;

        r = locale_read_data(c, reply);
        if (r < 0)
                return r;

        l = new0(char*, _VARIABLE_LC_MAX+1);
        if (!l)
                return -ENOMEM;

        for (LocaleVariable p = 0, q = 0; p < _VARIABLE_LC_MAX; p++) {
                char *t;
                const char *name;

                name = locale_variable_to_string(p);
                assert(name);

                if (isempty(c->locale[p]))
                        continue;

                if (asprintf(&t, "%s=%s", name, c->locale[p]) < 0)
                        return -ENOMEM;

                l[q++] = t;
        }

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

        Context *c = userdata;
        int r;

        r = vconsole_read_data(c, reply);
        if (r < 0)
                return r;

        if (streq(property, "VConsoleKeymap"))
                return sd_bus_message_append_basic(reply, 's', c->vc_keymap);
        else if (streq(property, "VConsoleKeymapToggle"))
                return sd_bus_message_append_basic(reply, 's', c->vc_keymap_toggle);

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

        Context *c = userdata;
        int r;

        r = x11_read_data(c, reply);
        if (r < 0)
                return r;

        if (streq(property, "X11Layout"))
                return sd_bus_message_append_basic(reply, 's', c->x11_layout);
        else if (streq(property, "X11Model"))
                return sd_bus_message_append_basic(reply, 's', c->x11_model);
        else if (streq(property, "X11Variant"))
                return sd_bus_message_append_basic(reply, 's', c->x11_variant);
        else if (streq(property, "X11Options"))
                return sd_bus_message_append_basic(reply, 's', c->x11_options);

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

static int locale_gen_process_locale(char *new_locale[static _VARIABLE_LC_MAX],
                                     sd_bus_error *error) {
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
                } else if (r == -EINVAL) {
                        log_error_errno(r, "Failed to enable invalid locale %s for generation.", new_locale[p]);
                        return sd_bus_error_setf(error,
                                                 SD_BUS_ERROR_INVALID_ARGS,
                                                 "Can not enable locale generation for invalid locale: %s",
                                                 new_locale[p]);
                } else if (r < 0) {
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
        _cleanup_strv_free_ char **settings = NULL, **l = NULL;
        Context *c = userdata;
        bool modified = false;
        int interactive, r;
        char **i;
        bool use_localegen;

        assert(m);
        assert(c);

        r = sd_bus_message_read_strv(m, &l);
        if (r < 0)
                return r;

        r = sd_bus_message_read_basic(m, 'b', &interactive);
        if (r < 0)
                return r;

        use_localegen = locale_gen_check_available();

        /* If single locale without variable name is provided, then we assume it is LANG=. */
        if (strv_length(l) == 1 && !strchr(l[0], '=')) {
                if (!locale_is_valid(l[0]))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid locale specification: %s", l[0]);
                if (!use_localegen && locale_is_installed(l[0]) <= 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Specified locale is not installed: %s", l[0]);

                new_locale[VARIABLE_LANG] = strdup(l[0]);
                if (!new_locale[VARIABLE_LANG])
                        return -ENOMEM;

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
        for (LocaleVariable p = 0; p < _VARIABLE_LC_MAX; p++)
                if (!isempty(c->locale[p]) && isempty(new_locale[p])) {
                        new_locale[p] = strdup(c->locale[p]);
                        if (!new_locale[p])
                                return -ENOMEM;
                }

        locale_simplify(new_locale);

        for (LocaleVariable p = 0; p < _VARIABLE_LC_MAX; p++)
                if (!streq_ptr(c->locale[p], new_locale[p])) {
                        modified = true;
                        break;
                }

        if (!modified) {
                log_debug("Locale settings were not modified.");
                return sd_bus_reply_method_return(m, NULL);
        }

        r = bus_verify_polkit_async(
                        m,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.locale1.set-locale",
                        NULL,
                        interactive,
                        UID_INVALID,
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

        for (LocaleVariable p = 0; p < _VARIABLE_LC_MAX; p++)
                free_and_replace(c->locale[p], new_locale[p]);

        /* Write locale configuration */
        r = locale_write_data(c, &settings);
        if (r < 0) {
                log_error_errno(r, "Failed to set locale: %m");
                return sd_bus_error_set_errnof(error, r, "Failed to set locale: %m");
        }

        (void) locale_update_system_manager(c, sd_bus_message_get_bus(m));

        if (settings) {
                _cleanup_free_ char *line = NULL;

                line = strv_join(settings, ", ");
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
        Context *c = userdata;
        const char *name, *keymap, *keymap_toggle;
        int convert, interactive, r;

        assert(m);
        assert(c);

        r = sd_bus_message_read(m, "ssbb", &keymap, &keymap_toggle, &convert, &interactive);
        if (r < 0)
                return r;

        keymap = empty_to_null(keymap);
        keymap_toggle = empty_to_null(keymap_toggle);

        r = vconsole_read_data(c, m);
        if (r < 0) {
                log_error_errno(r, "Failed to read virtual console keymap data: %m");
                return sd_bus_error_set_errnof(error, r, "Failed to read virtual console keymap data: %m");
        }

        FOREACH_STRING(name, keymap ?: keymap_toggle, keymap ? keymap_toggle : NULL) {
                r = keymap_exists(name); /* This also verifies that the keymap name is kosher. */
                if (r < 0) {
                        log_error_errno(r, "Failed to check keymap %s: %m", name);
                        return sd_bus_error_set_errnof(error, r, "Failed to check keymap %s: %m", name);
                }
                if (r == 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_FAILED, "Keymap %s is not installed.", name);
        }

        if (streq_ptr(keymap, c->vc_keymap) &&
            streq_ptr(keymap_toggle, c->vc_keymap_toggle))
                return sd_bus_reply_method_return(m, NULL);

        r = bus_verify_polkit_async(
                        m,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.locale1.set-keyboard",
                        NULL,
                        interactive,
                        UID_INVALID,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        if (free_and_strdup(&c->vc_keymap, keymap) < 0 ||
            free_and_strdup(&c->vc_keymap_toggle, keymap_toggle) < 0)
                return -ENOMEM;

        r = vconsole_write_data(c);
        if (r < 0) {
                log_error_errno(r, "Failed to set virtual console keymap: %m");
                return sd_bus_error_set_errnof(error, r, "Failed to set virtual console keymap: %m");
        }

        log_info("Changed virtual console keymap to '%s' toggle '%s'",
                 strempty(c->vc_keymap), strempty(c->vc_keymap_toggle));

        (void) vconsole_reload(sd_bus_message_get_bus(m));

        (void) sd_bus_emit_properties_changed(
                        sd_bus_message_get_bus(m),
                        "/org/freedesktop/locale1",
                        "org.freedesktop.locale1",
                        "VConsoleKeymap", "VConsoleKeymapToggle", NULL);

        if (convert) {
                r = vconsole_convert_to_x11_and_emit(c, m);
                if (r < 0)
                        log_error_errno(r, "Failed to convert keymap data: %m");
        }

        return sd_bus_reply_method_return(m, NULL);
}

#if HAVE_XKBCOMMON

_printf_(3, 0)
static void log_xkb(struct xkb_context *ctx, enum xkb_log_level lvl, const char *format, va_list args) {
        const char *fmt;

        fmt = strjoina("libxkbcommon: ", format);
        DISABLE_WARNING_FORMAT_NONLITERAL;
        log_internalv(LOG_DEBUG, 0, PROJECT_FILE, __LINE__, __func__, fmt, args);
        REENABLE_WARNING;
}

#define LOAD_SYMBOL(symbol, dl, name)                                   \
        ({                                                              \
                (symbol) = (typeof(symbol)) dlvsym((dl), (name), "V_0.5.0"); \
                (symbol) ? 0 : -EOPNOTSUPP;                             \
        })

static int verify_xkb_rmlvo(const char *model, const char *layout, const char *variant, const char *options) {

        /* We dlopen() the library in order to make the dependency soft. The library (and what it pulls in) is huge
         * after all, hence let's support XKB maps when the library is around, and refuse otherwise. The function
         * pointers to the shared library are below: */

        struct xkb_context* (*symbol_xkb_context_new)(enum xkb_context_flags flags) = NULL;
        void (*symbol_xkb_context_unref)(struct xkb_context *context) = NULL;
        void (*symbol_xkb_context_set_log_fn)(struct xkb_context *context, void (*log_fn)(struct xkb_context *context, enum xkb_log_level level, const char *format, va_list args)) = NULL;
        struct xkb_keymap* (*symbol_xkb_keymap_new_from_names)(struct xkb_context *context, const struct xkb_rule_names *names, enum xkb_keymap_compile_flags flags) = NULL;
        void (*symbol_xkb_keymap_unref)(struct xkb_keymap *keymap) = NULL;

        const struct xkb_rule_names rmlvo = {
                .model          = model,
                .layout         = layout,
                .variant        = variant,
                .options        = options,
        };
        struct xkb_context *ctx = NULL;
        struct xkb_keymap *km = NULL;
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        /* Compile keymap from RMLVO information to check out its validity */

        dl = dlopen("libxkbcommon.so.0", RTLD_LAZY);
        if (!dl)
                return -EOPNOTSUPP;

        r = LOAD_SYMBOL(symbol_xkb_context_new, dl, "xkb_context_new");
        if (r < 0)
                goto finish;

        r = LOAD_SYMBOL(symbol_xkb_context_unref, dl, "xkb_context_unref");
        if (r < 0)
                goto finish;

        r = LOAD_SYMBOL(symbol_xkb_context_set_log_fn, dl, "xkb_context_set_log_fn");
        if (r < 0)
                goto finish;

        r = LOAD_SYMBOL(symbol_xkb_keymap_new_from_names, dl, "xkb_keymap_new_from_names");
        if (r < 0)
                goto finish;

        r = LOAD_SYMBOL(symbol_xkb_keymap_unref, dl, "xkb_keymap_unref");
        if (r < 0)
                goto finish;

        ctx = symbol_xkb_context_new(XKB_CONTEXT_NO_ENVIRONMENT_NAMES);
        if (!ctx) {
                r = -ENOMEM;
                goto finish;
        }

        symbol_xkb_context_set_log_fn(ctx, log_xkb);

        km = symbol_xkb_keymap_new_from_names(ctx, &rmlvo, XKB_KEYMAP_COMPILE_NO_FLAGS);
        if (!km) {
                r = -EINVAL;
                goto finish;
        }

        r = 0;

finish:
        if (symbol_xkb_keymap_unref && km)
                symbol_xkb_keymap_unref(km);

        if (symbol_xkb_context_unref && ctx)
                symbol_xkb_context_unref(ctx);

        return r;
}

#else

static int verify_xkb_rmlvo(const char *model, const char *layout, const char *variant, const char *options) {
        return 0;
}

#endif

static int method_set_x11_keyboard(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = userdata;
        const char *layout, *model, *variant, *options;
        int convert, interactive, r;

        assert(m);
        assert(c);

        r = sd_bus_message_read(m, "ssssbb", &layout, &model, &variant, &options, &convert, &interactive);
        if (r < 0)
                return r;

        layout = empty_to_null(layout);
        model = empty_to_null(model);
        variant = empty_to_null(variant);
        options = empty_to_null(options);

        r = x11_read_data(c, m);
        if (r < 0) {
                log_error_errno(r, "Failed to read x11 keyboard layout data: %m");
                return sd_bus_error_set(error, SD_BUS_ERROR_FAILED, "Failed to read x11 keyboard layout data");
        }

        if (streq_ptr(layout, c->x11_layout) &&
            streq_ptr(model, c->x11_model) &&
            streq_ptr(variant, c->x11_variant) &&
            streq_ptr(options, c->x11_options))
                return sd_bus_reply_method_return(m, NULL);

        if ((layout && !string_is_safe(layout)) ||
            (model && !string_is_safe(model)) ||
            (variant && !string_is_safe(variant)) ||
            (options && !string_is_safe(options)))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Received invalid keyboard data");

        r = verify_xkb_rmlvo(model, layout, variant, options);
        if (r < 0) {
                log_error_errno(r, "Cannot compile XKB keymap for new x11 keyboard layout ('%s' / '%s' / '%s' / '%s'): %m",
                                strempty(model), strempty(layout), strempty(variant), strempty(options));

                if (r == -EOPNOTSUPP)
                        return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Local keyboard configuration not supported on this system.");

                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Specified keymap cannot be compiled, refusing as invalid.");
        }

        r = bus_verify_polkit_async(
                        m,
                        CAP_SYS_ADMIN,
                        "org.freedesktop.locale1.set-keyboard",
                        NULL,
                        interactive,
                        UID_INVALID,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        if (free_and_strdup(&c->x11_layout, layout) < 0 ||
            free_and_strdup(&c->x11_model, model) < 0 ||
            free_and_strdup(&c->x11_variant, variant) < 0 ||
            free_and_strdup(&c->x11_options, options) < 0)
                return -ENOMEM;

        r = x11_write_data(c);
        if (r < 0) {
                log_error_errno(r, "Failed to set X11 keyboard layout: %m");
                return sd_bus_error_set_errnof(error, r, "Failed to set X11 keyboard layout: %m");
        }

        log_info("Changed X11 keyboard layout to '%s' model '%s' variant '%s' options '%s'",
                 strempty(c->x11_layout),
                 strempty(c->x11_model),
                 strempty(c->x11_variant),
                 strempty(c->x11_options));

        (void) sd_bus_emit_properties_changed(
                        sd_bus_message_get_bus(m),
                        "/org/freedesktop/locale1",
                        "org.freedesktop.locale1",
                        "X11Layout", "X11Model", "X11Variant", "X11Options", NULL);

        if (convert) {
                r = x11_convert_to_vconsole_and_emit(c, m);
                if (r < 0)
                        log_error_errno(r, "Failed to convert keymap data: %m");
        }

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

        SD_BUS_METHOD_WITH_NAMES("SetLocale",
                                 "asb",
                                 SD_BUS_PARAM(locale)
                                 SD_BUS_PARAM(interactive),
                                 NULL,,
                                 method_set_locale,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("SetVConsoleKeyboard",
                                 "ssbb",
                                 SD_BUS_PARAM(keymap)
                                 SD_BUS_PARAM(keymap_toggle)
                                 SD_BUS_PARAM(convert)
                                 SD_BUS_PARAM(interactive),
                                 NULL,,
                                 method_set_vc_keyboard,
                                 SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_NAMES("SetX11Keyboard",
                                 "ssssbb",
                                 SD_BUS_PARAM(layout)
                                 SD_BUS_PARAM(model)
                                 SD_BUS_PARAM(variant)
                                 SD_BUS_PARAM(options)
                                 SD_BUS_PARAM(convert)
                                 SD_BUS_PARAM(interactive),
                                 NULL,,
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
        _cleanup_(context_clear) Context context = {
                .locale_mtime = USEC_INFINITY,
                .vc_mtime = USEC_INFINITY,
                .x11_mtime = USEC_INFINITY,
        };
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

        r = mac_selinux_init();
        if (r < 0)
                return r;

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        (void) sd_event_set_watchdog(event, true);

        r = sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT handler: %m");

        r = sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGTERM handler: %m");

        r = connect_bus(&context, event, &bus);
        if (r < 0)
                return r;

        r = bus_event_loop_with_idle(event, bus, "org.freedesktop.locale1", DEFAULT_EXIT_USEC, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
