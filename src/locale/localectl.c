/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "kbd-util.h"
#include "locale-setup.h"
#include "main-func.h"
#include "memory-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "path-util.h"
#include "polkit-agent.h"
#include "pretty-print.h"
#include "runtime-scope.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "verbs.h"

/* Enough time for locale-gen to finish server-side (in case it is in use) */
#define LOCALE_SLOW_BUS_CALL_TIMEOUT_USEC (2*USEC_PER_MINUTE)

static PagerFlags arg_pager_flags = 0;
static bool arg_ask_password = true;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static const char *arg_host = NULL;
static bool arg_convert = true;
static bool arg_full = false;

typedef struct StatusInfo {
        char **locale;
        const char *vconsole_keymap;
        const char *vconsole_keymap_toggle;
        const char *x11_layout;
        const char *x11_model;
        const char *x11_variant;
        const char *x11_options;
} StatusInfo;

static void status_info_clear(StatusInfo *info) {
        if (info) {
                strv_free(info->locale);
                zero(*info);
        }
}

static int print_status_info(StatusInfo *i) {
        _cleanup_strv_free_ char **kernel_locale = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        TableCell *cell;
        int r;

        assert(i);

        if (arg_transport == BUS_TRANSPORT_LOCAL) {
                _cleanup_(locale_context_clear) LocaleContext c = {};

                r = locale_context_load(&c, LOCALE_LOAD_PROC_CMDLINE);
                if (r < 0)
                        return log_error_errno(r, "Failed to read /proc/cmdline: %m");

                r = locale_context_build_env(&c, &kernel_locale, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to build locale settings from kernel command line: %m");
        }

        table = table_new_vertical();
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        assert_se(cell = table_get_cell(table, 0, 0));
        (void) table_set_ellipsize_percent(table, cell, 100);

        table_set_ersatz_string(table, TABLE_ERSATZ_UNSET);

        if (!strv_isempty(kernel_locale)) {
                log_warning("Warning: Settings on kernel command line override system locale settings in /etc/locale.conf.");
                r = table_add_many(table,
                                   TABLE_FIELD, "Command Line",
                                   TABLE_SET_COLOR, ansi_highlight_yellow(),
                                   TABLE_STRV, kernel_locale,
                                   TABLE_SET_COLOR, ansi_highlight_yellow());
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_add_many(table,
                           TABLE_FIELD, "System Locale",
                           TABLE_STRV, i->locale,
                           TABLE_FIELD, "VC Keymap",
                           TABLE_STRING, i->vconsole_keymap);
        if (r < 0)
                return table_log_add_error(r);

        if (!isempty(i->vconsole_keymap_toggle)) {
                r = table_add_many(table,
                                   TABLE_FIELD, "VC Toggle Keymap",
                                   TABLE_STRING, i->vconsole_keymap_toggle);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_add_many(table,
                           TABLE_FIELD, "X11 Layout",
                           TABLE_STRING, i->x11_layout);
        if (r < 0)
                return table_log_add_error(r);

        if (!isempty(i->x11_model)) {
                r = table_add_many(table,
                                   TABLE_FIELD, "X11 Model",
                                   TABLE_STRING, i->x11_model);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(i->x11_variant)) {
                r = table_add_many(table,
                                   TABLE_FIELD, "X11 Variant",
                                   TABLE_STRING, i->x11_variant);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (!isempty(i->x11_options)) {
                r = table_add_many(table,
                                   TABLE_FIELD, "X11 Options",
                                   TABLE_STRING, i->x11_options);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}

static int show_status(int argc, char **argv, void *userdata) {
        _cleanup_(status_info_clear) StatusInfo info = {};
        static const struct bus_properties_map map[]  = {
                { "VConsoleKeymap",       "s",  NULL, offsetof(StatusInfo, vconsole_keymap) },
                { "VConsoleKeymapToggle", "s",  NULL, offsetof(StatusInfo, vconsole_keymap_toggle) },
                { "X11Layout",            "s",  NULL, offsetof(StatusInfo, x11_layout) },
                { "X11Model",             "s",  NULL, offsetof(StatusInfo, x11_model) },
                { "X11Variant",           "s",  NULL, offsetof(StatusInfo, x11_variant) },
                { "X11Options",           "s",  NULL, offsetof(StatusInfo, x11_options) },
                { "Locale",               "as", NULL, offsetof(StatusInfo, locale) },
                {}
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.locale1",
                                   "/org/freedesktop/locale1",
                                   map,
                                   0,
                                   &error,
                                   &m,
                                   &info);
        if (r < 0)
                return log_error_errno(r, "Could not get properties: %s", bus_error_message(&error, r));

        return print_status_info(&info);
}

static int set_locale(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = bus_message_new_method_call(bus, &m, bus_locale, "SetLocale");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, argv + 1);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "b", arg_ask_password);
        if (r < 0)
                return bus_log_create_error(r);

        /* We use a longer timeout for the method call in case localed is running locale-gen */
        r = sd_bus_call(bus, m, LOCALE_SLOW_BUS_CALL_TIMEOUT_USEC, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to issue method call: %s", bus_error_message(&error, r));

        return 0;
}

static int list_locales(int argc, char **argv, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        r = get_locales(&l);
        if (r < 0)
                return log_error_errno(r, "Failed to read list of locales: %m");

        pager_open(arg_pager_flags);
        strv_print(l);

        return 0;
}

static int set_vconsole_keymap(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *map, *toggle_map;
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        map = argv[1];
        toggle_map = argc > 2 ? argv[2] : "";

        r = bus_call_method(
                        bus,
                        bus_locale,
                        "SetVConsoleKeyboard",
                        &error,
                        NULL,
                        "ssbb", map, toggle_map, arg_convert, arg_ask_password);
        if (r < 0)
                return log_error_errno(r, "Failed to set keymap: %s", bus_error_message(&error, r));

        return 0;
}

static int list_vconsole_keymaps(int argc, char **argv, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        r = get_keymaps(&l);
        if (r < 0)
                return log_error_errno(r, "Failed to read list of keymaps: %m");

        pager_open(arg_pager_flags);

        strv_print(l);

        return 0;
}

static int set_x11_keymap(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *layout, *model, *variant, *options;
        sd_bus *bus = userdata;
        int r;

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        layout = argv[1];
        model = argc > 2 ? argv[2] : "";
        variant = argc > 3 ? argv[3] : "";
        options = argc > 4 ? argv[4] : "";

        r = bus_call_method(
                        bus,
                        bus_locale,
                        "SetX11Keyboard",
                        &error,
                        NULL,
                        "ssssbb", layout, model, variant, options,
                                  arg_convert, arg_ask_password);
        if (r < 0)
                return log_error_errno(r, "Failed to set keymap: %s", bus_error_message(&error, r));

        return 0;
}

static const char* xkb_directory(void) {
        static const char *cached = NULL;

        if (!cached)
                cached = secure_getenv("SYSTEMD_XKB_DIRECTORY") ?: "/usr/share/X11/xkb";
        return cached;
}

static int list_x11_keymaps(int argc, char **argv, void *userdata) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **list = NULL;
        enum {
                NONE,
                MODELS,
                LAYOUTS,
                VARIANTS,
                OPTIONS
        } state = NONE, look_for;
        int r;

        _cleanup_free_ char *xkb_base = path_join(xkb_directory(), "rules/base.lst");
        if (!xkb_base)
                return log_oom();

        f = fopen(xkb_base, "re");
        if (!f)
                return log_error_errno(errno,
                                       "Failed to open keyboard mapping list %s: %m",
                                       xkb_base);

        if (streq(argv[0], "list-x11-keymap-models"))
                look_for = MODELS;
        else if (streq(argv[0], "list-x11-keymap-layouts"))
                look_for = LAYOUTS;
        else if (streq(argv[0], "list-x11-keymap-variants"))
                look_for = VARIANTS;
        else if (streq(argv[0], "list-x11-keymap-options"))
                look_for = OPTIONS;
        else
                assert_not_reached();

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *w;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r,
                                               "Failed to read keyboard mapping list %s: %m",
                                               xkb_base);
                if (r == 0)
                        break;

                if (isempty(line))
                        continue;

                if (line[0] == '!') {
                        if (startswith(line, "! model"))
                                state = MODELS;
                        else if (startswith(line, "! layout"))
                                state = LAYOUTS;
                        else if (startswith(line, "! variant"))
                                state = VARIANTS;
                        else if (startswith(line, "! option"))
                                state = OPTIONS;
                        else
                                state = NONE;

                        continue;
                }

                if (state != look_for)
                        continue;

                w = line + strcspn(line, WHITESPACE);

                if (argc > 1) {
                        char *e;

                        if (*w == 0)
                                continue;

                        *w = 0;
                        w++;
                        w += strspn(w, WHITESPACE);

                        e = strchr(w, ':');
                        if (!e)
                                continue;

                        *e = 0;

                        if (!streq(w, argv[1]))
                                continue;
                } else
                        *w = 0;

                if (strv_consume(&list, TAKE_PTR(line)) < 0)
                        return log_oom();
        }

        if (strv_isempty(list))
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Couldn't find any entries in keyboard mapping list %s.",
                                       xkb_base);

        strv_sort_uniq(list);

        pager_open(arg_pager_flags);

        strv_print(list);
        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("localectl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "%sQuery or change system locale and keyboard settings.%s\n"
               "\nCommands:\n"
               "  status                   Show current locale settings\n"
               "  set-locale LOCALE...     Set system locale\n"
               "  list-locales             Show known locales\n"
               "  set-keymap MAP [MAP]     Set console and X11 keyboard mappings\n"
               "  list-keymaps             Show known virtual console keyboard mappings\n"
               "  set-x11-keymap LAYOUT [MODEL [VARIANT [OPTIONS]]]\n"
               "                           Set X11 and console keyboard mappings\n"
               "  list-x11-keymap-models   Show known X11 keyboard mapping models\n"
               "  list-x11-keymap-layouts  Show known X11 keyboard mapping layouts\n"
               "  list-x11-keymap-variants [LAYOUT]\n"
               "                           Show known X11 keyboard mapping variants\n"
               "  list-x11-keymap-options  Show known X11 keyboard mapping options\n"
               "\nOptions:\n"
               "  -h --help                Show this help\n"
               "     --version             Show package version\n"
               "  -l --full                Do not ellipsize output\n"
               "     --no-pager            Do not pipe output into a pager\n"
               "     --no-ask-password     Do not prompt for password\n"
               "  -H --host=[USER@]HOST    Operate on remote host\n"
               "  -M --machine=CONTAINER   Operate on local container\n"
               "     --no-convert          Don't convert keyboard mappings\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int verb_help(int argc, char **argv, void *userdata) {
        return help();
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_CONVERT,
                ARG_NO_ASK_PASSWORD
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "full",            no_argument,       NULL, 'l'                 },
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                { "host",            required_argument, NULL, 'H'                 },
                { "machine",         required_argument, NULL, 'M'                 },
                { "no-ask-password", no_argument,       NULL, ARG_NO_ASK_PASSWORD },
                { "no-convert",      no_argument,       NULL, ARG_NO_CONVERT      },
                {}
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hlH:M:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'l':
                        arg_full = true;
                        break;

                case ARG_NO_CONVERT:
                        arg_convert = false;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        r = parse_machine_argument(optarg, &arg_host, &arg_transport);
                        if (r < 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int localectl_main(sd_bus *bus, int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "status",                   VERB_ANY, 1,        VERB_DEFAULT, show_status           },
                { "set-locale",               2,        VERB_ANY, 0,            set_locale            },
                { "list-locales",             VERB_ANY, 1,        0,            list_locales          },
                { "set-keymap",               2,        3,        0,            set_vconsole_keymap   },
                { "list-keymaps",             VERB_ANY, 1,        0,            list_vconsole_keymaps },
                { "set-x11-keymap",           2,        5,        0,            set_x11_keymap        },
                { "list-x11-keymap-models",   VERB_ANY, 1,        0,            list_x11_keymaps      },
                { "list-x11-keymap-layouts",  VERB_ANY, 1,        0,            list_x11_keymaps      },
                { "list-x11-keymap-variants", VERB_ANY, 2,        0,            list_x11_keymaps      },
                { "list-x11-keymap-options",  VERB_ANY, 1,        0,            list_x11_keymaps      },
                { "help",                     VERB_ANY, VERB_ANY, 0,            verb_help             }, /* Not documented, but supported since it is created. */
                {}
        };

        return dispatch_verb(argc, argv, verbs, bus);
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = bus_connect_transport(arg_transport, arg_host, RUNTIME_SCOPE_SYSTEM, &bus);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, RUNTIME_SCOPE_SYSTEM);

        return localectl_main(bus, argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
