/* SPDX-License-Identifier: LGPL-2.1+ */

#include <ftw.h>
#include <getopt.h>
#include <locale.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sd-bus.h"

#include "bus-error.h"
#include "bus-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "kbd-util.h"
#include "locale-util.h"
#include "main-func.h"
#include "memory-util.h"
#include "pager.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "set.h"
#include "spawn-polkit-agent.h"
#include "strv.h"
#include "verbs.h"
#include "virt.h"

static PagerFlags arg_pager_flags = 0;
static bool arg_ask_password = true;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static const char *arg_host = NULL;
static bool arg_convert = true;

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

static void print_overridden_variables(void) {
        _cleanup_(locale_variables_freep) char *variables[_VARIABLE_LC_MAX] = {};
        bool print_warning = true;
        LocaleVariable j;
        int r;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return;

        r = proc_cmdline_get_key_many(
                        PROC_CMDLINE_STRIP_RD_PREFIX,
                        "locale.LANG",              &variables[VARIABLE_LANG],
                        "locale.LANGUAGE",          &variables[VARIABLE_LANGUAGE],
                        "locale.LC_CTYPE",          &variables[VARIABLE_LC_CTYPE],
                        "locale.LC_NUMERIC",        &variables[VARIABLE_LC_NUMERIC],
                        "locale.LC_TIME",           &variables[VARIABLE_LC_TIME],
                        "locale.LC_COLLATE",        &variables[VARIABLE_LC_COLLATE],
                        "locale.LC_MONETARY",       &variables[VARIABLE_LC_MONETARY],
                        "locale.LC_MESSAGES",       &variables[VARIABLE_LC_MESSAGES],
                        "locale.LC_PAPER",          &variables[VARIABLE_LC_PAPER],
                        "locale.LC_NAME",           &variables[VARIABLE_LC_NAME],
                        "locale.LC_ADDRESS",        &variables[VARIABLE_LC_ADDRESS],
                        "locale.LC_TELEPHONE",      &variables[VARIABLE_LC_TELEPHONE],
                        "locale.LC_MEASUREMENT",    &variables[VARIABLE_LC_MEASUREMENT],
                        "locale.LC_IDENTIFICATION", &variables[VARIABLE_LC_IDENTIFICATION]);
        if (r < 0 && r != -ENOENT) {
                log_warning_errno(r, "Failed to read /proc/cmdline: %m");
                return;
        }

        for (j = 0; j < _VARIABLE_LC_MAX; j++)
                if (variables[j]) {
                        if (print_warning) {
                                log_warning("Warning: Settings on kernel command line override system locale settings in /etc/locale.conf.\n"
                                            "    Command Line: %s=%s", locale_variable_to_string(j), variables[j]);

                                print_warning = false;
                        } else
                                log_warning("                  %s=%s", locale_variable_to_string(j), variables[j]);
                }
}

static void print_status_info(StatusInfo *i) {
        assert(i);

        if (strv_isempty(i->locale))
                puts("   System Locale: n/a");
        else {
                char **j;

                printf("   System Locale: %s\n", i->locale[0]);
                STRV_FOREACH(j, i->locale + 1)
                        printf("                  %s\n", *j);
        }

        printf("       VC Keymap: %s\n", strna(i->vconsole_keymap));
        if (!isempty(i->vconsole_keymap_toggle))
                printf("VC Toggle Keymap: %s\n", i->vconsole_keymap_toggle);

        printf("      X11 Layout: %s\n", strna(i->x11_layout));
        if (!isempty(i->x11_model))
                printf("       X11 Model: %s\n", i->x11_model);
        if (!isempty(i->x11_variant))
                printf("     X11 Variant: %s\n", i->x11_variant);
        if (!isempty(i->x11_options))
                printf("     X11 Options: %s\n", i->x11_options);
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
        sd_bus *bus = userdata;
        int r;

        assert(bus);

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

        print_overridden_variables();
        print_status_info(&info);

        return r;
}

static int set_locale(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.locale1",
                        "/org/freedesktop/locale1",
                        "org.freedesktop.locale1",
                        "SetLocale");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, argv + 1);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "b", arg_ask_password);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to issue method call: %s", bus_error_message(&error, -r));

        return 0;
}

static int list_locales(int argc, char **argv, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        r = get_locales(&l);
        if (r < 0)
                return log_error_errno(r, "Failed to read list of locales: %m");

        (void) pager_open(arg_pager_flags);
        strv_print(l);

        return 0;
}

static int set_vconsole_keymap(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *map, *toggle_map;
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        map = argv[1];
        toggle_map = argc > 2 ? argv[2] : "";

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.locale1",
                        "/org/freedesktop/locale1",
                        "org.freedesktop.locale1",
                        "SetVConsoleKeyboard",
                        &error,
                        NULL,
                        "ssbb", map, toggle_map, arg_convert, arg_ask_password);
        if (r < 0)
                return log_error_errno(r, "Failed to set keymap: %s", bus_error_message(&error, -r));

        return 0;
}

static int list_vconsole_keymaps(int argc, char **argv, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        r = get_keymaps(&l);
        if (r < 0)
                return log_error_errno(r, "Failed to read list of keymaps: %m");

        (void) pager_open(arg_pager_flags);

        strv_print(l);

        return 0;
}

static int set_x11_keymap(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *layout, *model, *variant, *options;
        sd_bus *bus = userdata;
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        layout = argv[1];
        model = argc > 2 ? argv[2] : "";
        variant = argc > 3 ? argv[3] : "";
        options = argc > 4 ? argv[4] : "";

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.locale1",
                        "/org/freedesktop/locale1",
                        "org.freedesktop.locale1",
                        "SetX11Keyboard",
                        &error,
                        NULL,
                        "ssssbb", layout, model, variant, options,
                                  arg_convert, arg_ask_password);
        if (r < 0)
                return log_error_errno(r, "Failed to set keymap: %s", bus_error_message(&error, -r));

        return 0;
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

        f = fopen("/usr/share/X11/xkb/rules/base.lst", "re");
        if (!f)
                return log_error_errno(errno, "Failed to open keyboard mapping list. %m");

        if (streq(argv[0], "list-x11-keymap-models"))
                look_for = MODELS;
        else if (streq(argv[0], "list-x11-keymap-layouts"))
                look_for = LAYOUTS;
        else if (streq(argv[0], "list-x11-keymap-variants"))
                look_for = VARIANTS;
        else if (streq(argv[0], "list-x11-keymap-options"))
                look_for = OPTIONS;
        else
                assert_not_reached("Wrong parameter");

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *l, *w;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read keyboard mapping list: %m");
                if (r == 0)
                        break;

                l = strstrip(line);

                if (isempty(l))
                        continue;

                if (l[0] == '!') {
                        if (startswith(l, "! model"))
                                state = MODELS;
                        else if (startswith(l, "! layout"))
                                state = LAYOUTS;
                        else if (startswith(l, "! variant"))
                                state = VARIANTS;
                        else if (startswith(l, "! option"))
                                state = OPTIONS;
                        else
                                state = NONE;

                        continue;
                }

                if (state != look_for)
                        continue;

                w = l + strcspn(l, WHITESPACE);

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

                r = strv_extend(&list, l);
                if (r < 0)
                        return log_oom();
        }

        if (strv_isempty(list))
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Couldn't find any entries.");

        strv_sort(list);
        strv_uniq(list);

        (void) pager_open(arg_pager_flags);

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
               "Query or change system locale and keyboard settings.\n\n"
               "  -h --help                Show this help\n"
               "     --version             Show package version\n"
               "     --no-pager            Do not pipe output into a pager\n"
               "     --no-ask-password     Do not prompt for password\n"
               "  -H --host=[USER@]HOST    Operate on remote host\n"
               "  -M --machine=CONTAINER   Operate on local container\n"
               "     --no-convert          Don't convert keyboard mappings\n\n"
               "Commands:\n"
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
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

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
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                { "host",            required_argument, NULL, 'H'                 },
                { "machine",         required_argument, NULL, 'M'                 },
                { "no-ask-password", no_argument,       NULL, ARG_NO_ASK_PASSWORD },
                { "no-convert",      no_argument,       NULL, ARG_NO_CONVERT      },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hH:M:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

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
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
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
        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = bus_connect_transport(arg_transport, arg_host, false, &bus);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        return localectl_main(bus, argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
