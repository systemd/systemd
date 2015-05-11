/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
  Copyright 2013 Kay Sievers

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <locale.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <ftw.h>

#include "sd-bus.h"
#include "bus-util.h"
#include "bus-error.h"
#include "util.h"
#include "spawn-polkit-agent.h"
#include "build.h"
#include "strv.h"
#include "pager.h"
#include "set.h"
#include "def.h"
#include "virt.h"
#include "fileio.h"
#include "locale-util.h"

static bool arg_no_pager = false;
static bool arg_ask_password = true;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static char *arg_host = NULL;
static bool arg_convert = true;

static void pager_open_if_enabled(void) {

        if (arg_no_pager)
                return;

        pager_open(false);
}

static void polkit_agent_open_if_enabled(void) {

        /* Open the polkit agent as a child process if necessary */
        if (!arg_ask_password)
                return;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return;

        polkit_agent_open();
}

typedef struct StatusInfo {
        char **locale;
        const char *vconsole_keymap;
        const char *vconsole_keymap_toggle;
        const char *x11_layout;
        const char *x11_model;
        const char *x11_variant;
        const char *x11_options;
} StatusInfo;

static void print_overridden_variables(void) {
        int r;
        char *variables[_VARIABLE_LC_MAX] = {};
        LocaleVariable j;
        bool print_warning = true;

        if (detect_container(NULL) > 0 || arg_host)
                return;

        r = parse_env_file("/proc/cmdline", WHITESPACE,
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
                           "locale.LC_IDENTIFICATION", &variables[VARIABLE_LC_IDENTIFICATION],
                           NULL);

        if (r < 0 && r != -ENOENT) {
                log_warning_errno(r, "Failed to read /proc/cmdline: %m");
                goto finish;
        }

        for (j = 0; j < _VARIABLE_LC_MAX; j++)
                if (variables[j]) {
                        if (print_warning) {
                                log_warning("Warning: Settings on kernel command line override system locale settings in /etc/locale.conf.\n"
                                            "  Command Line: %s=%s", locale_variable_to_string(j), variables[j]);

                                print_warning = false;
                        } else
                                log_warning("                %s=%s", locale_variable_to_string(j), variables[j]);
                }
 finish:
        for (j = 0; j < _VARIABLE_LC_MAX; j++)
                free(variables[j]);
}

static void print_status_info(StatusInfo *i) {
        assert(i);

        if (strv_isempty(i->locale))
                puts("   System Locale: n/a\n");
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

static int show_status(sd_bus *bus, char **args, unsigned n) {
        StatusInfo info = {};
        static const struct bus_properties_map map[]  = {
                { "VConsoleKeymap",       "s",  NULL, offsetof(StatusInfo, vconsole_keymap) },
                { "VConsoleKeymap",       "s",  NULL, offsetof(StatusInfo, vconsole_keymap) },
                { "VConsoleKeymapToggle", "s",  NULL, offsetof(StatusInfo, vconsole_keymap_toggle) },
                { "X11Layout",            "s",  NULL, offsetof(StatusInfo, x11_layout) },
                { "X11Model",             "s",  NULL, offsetof(StatusInfo, x11_model) },
                { "X11Variant",           "s",  NULL, offsetof(StatusInfo, x11_variant) },
                { "X11Options",           "s",  NULL, offsetof(StatusInfo, x11_options) },
                { "Locale",               "as", NULL, offsetof(StatusInfo, locale) },
                {}
        };
        int r;

        assert(bus);

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.locale1",
                                   "/org/freedesktop/locale1",
                                   map,
                                   &info);
        if (r < 0) {
                log_error_errno(r, "Could not get properties: %m");
                goto fail;
        }

        print_overridden_variables();
        print_status_info(&info);

fail:
        strv_free(info.locale);
        return r;
}

static int set_locale(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(args);

        polkit_agent_open_if_enabled();

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.locale1",
                        "/org/freedesktop/locale1",
                        "org.freedesktop.locale1",
                        "SetLocale");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, args + 1);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "b", arg_ask_password);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, NULL);
        if (r < 0) {
                log_error("Failed to issue method call: %s", bus_error_message(&error, -r));
                return r;
        }

        return 0;
}

static int list_locales(sd_bus *bus, char **args, unsigned n) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(args);

        r = get_locales(&l);
        if (r < 0)
                return log_error_errno(r, "Failed to read list of locales: %m");

        pager_open_if_enabled();
        strv_print(l);

        return 0;
}

static int set_vconsole_keymap(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *map, *toggle_map;
        int r;

        assert(bus);
        assert(args);

        if (n > 3) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        polkit_agent_open_if_enabled();

        map = args[1];
        toggle_map = n > 2 ? args[2] : "";

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
                log_error("Failed to set keymap: %s", bus_error_message(&error, -r));

        return r;
}

static Set *keymaps = NULL;

static int nftw_cb(
                const char *fpath,
                const struct stat *sb,
                int tflag,
                struct FTW *ftwbuf) {

        char *p, *e;
        int r;

        if (tflag != FTW_F)
                return 0;

        if (!endswith(fpath, ".map") &&
            !endswith(fpath, ".map.gz"))
                return 0;

        p = strdup(basename(fpath));
        if (!p)
                return log_oom();

        e = endswith(p, ".map");
        if (e)
                *e = 0;

        e = endswith(p, ".map.gz");
        if (e)
                *e = 0;

        r = set_consume(keymaps, p);
        if (r < 0 && r != -EEXIST)
                return log_error_errno(r, "Can't add keymap: %m");

        return 0;
}

static int list_vconsole_keymaps(sd_bus *bus, char **args, unsigned n) {
        _cleanup_strv_free_ char **l = NULL;
        const char *dir;

        keymaps = set_new(&string_hash_ops);
        if (!keymaps)
                return log_oom();

        NULSTR_FOREACH(dir, KBD_KEYMAP_DIRS)
                nftw(dir, nftw_cb, 20, FTW_MOUNT|FTW_PHYS);

        l = set_get_strv(keymaps);
        if (!l) {
                set_free_free(keymaps);
                return log_oom();
        }

        set_free(keymaps);

        if (strv_isempty(l)) {
                log_error("Couldn't find any console keymaps.");
                return -ENOENT;
        }

        strv_sort(l);

        pager_open_if_enabled();

        strv_print(l);

        return 0;
}

static int set_x11_keymap(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *layout, *model, *variant, *options;
        int r;

        assert(bus);
        assert(args);

        if (n > 5) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        polkit_agent_open_if_enabled();

        layout = args[1];
        model = n > 2 ? args[2] : "";
        variant = n > 3 ? args[3] : "";
        options = n > 4 ? args[4] : "";

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
                log_error("Failed to set keymap: %s", bus_error_message(&error, -r));

        return r;
}

static int list_x11_keymaps(sd_bus *bus, char **args, unsigned n) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **list = NULL;
        char line[LINE_MAX];
        enum {
                NONE,
                MODELS,
                LAYOUTS,
                VARIANTS,
                OPTIONS
        } state = NONE, look_for;
        int r;

        if (n > 2) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        f = fopen("/usr/share/X11/xkb/rules/base.lst", "re");
        if (!f)
                return log_error_errno(errno, "Failed to open keyboard mapping list. %m");

        if (streq(args[0], "list-x11-keymap-models"))
                look_for = MODELS;
        else if (streq(args[0], "list-x11-keymap-layouts"))
                look_for = LAYOUTS;
        else if (streq(args[0], "list-x11-keymap-variants"))
                look_for = VARIANTS;
        else if (streq(args[0], "list-x11-keymap-options"))
                look_for = OPTIONS;
        else
                assert_not_reached("Wrong parameter");

        FOREACH_LINE(line, f, break) {
                char *l, *w;

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

                if (n > 1) {
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

                        if (!streq(w, args[1]))
                                continue;
                } else
                        *w = 0;

                 r = strv_extend(&list, l);
                 if (r < 0)
                         return log_oom();
        }

        if (strv_isempty(list)) {
                log_error("Couldn't find any entries.");
                return -ENOENT;
        }

        strv_sort(list);
        strv_uniq(list);

        pager_open_if_enabled();

        strv_print(list);
        return 0;
}

static void help(void) {
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
               , program_invocation_short_name);
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
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_NO_CONVERT:
                        arg_convert = false;
                        break;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
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

        static const struct {
                const char* verb;
                const enum {
                        MORE,
                        LESS,
                        EQUAL
                } argc_cmp;
                const int argc;
                int (* const dispatch)(sd_bus *bus, char **args, unsigned n);
        } verbs[] = {
                { "status",                   LESS,   1, show_status           },
                { "set-locale",               MORE,   2, set_locale            },
                { "list-locales",             EQUAL,  1, list_locales          },
                { "set-keymap",               MORE,   2, set_vconsole_keymap   },
                { "list-keymaps",             EQUAL,  1, list_vconsole_keymaps },
                { "set-x11-keymap",           MORE,   2, set_x11_keymap        },
                { "list-x11-keymap-models",   EQUAL,  1, list_x11_keymaps      },
                { "list-x11-keymap-layouts",  EQUAL,  1, list_x11_keymaps      },
                { "list-x11-keymap-variants", LESS,   2, list_x11_keymaps      },
                { "list-x11-keymap-options",  EQUAL,  1, list_x11_keymaps      },
        };

        int left;
        unsigned i;

        assert(argc >= 0);
        assert(argv);

        left = argc - optind;

        if (left <= 0)
                /* Special rule: no arguments means "status" */
                i = 0;
        else {
                if (streq(argv[optind], "help")) {
                        help();
                        return 0;
                }

                for (i = 0; i < ELEMENTSOF(verbs); i++)
                        if (streq(argv[optind], verbs[i].verb))
                                break;

                if (i >= ELEMENTSOF(verbs)) {
                        log_error("Unknown operation %s", argv[optind]);
                        return -EINVAL;
                }
        }

        switch (verbs[i].argc_cmp) {

        case EQUAL:
                if (left != verbs[i].argc) {
                        log_error("Invalid number of arguments.");
                        return -EINVAL;
                }

                break;

        case MORE:
                if (left < verbs[i].argc) {
                        log_error("Too few arguments.");
                        return -EINVAL;
                }

                break;

        case LESS:
                if (left > verbs[i].argc) {
                        log_error("Too many arguments.");
                        return -EINVAL;
                }

                break;

        default:
                assert_not_reached("Unknown comparison operator.");
        }

        return verbs[i].dispatch(bus, argv + optind, left);
}

int main(int argc, char*argv[]) {
        _cleanup_bus_close_unref_ sd_bus *bus = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = bus_open_transport(arg_transport, arg_host, false, &bus);
        if (r < 0) {
                log_error_errno(r, "Failed to create bus connection: %m");
                goto finish;
        }

        r = localectl_main(bus, argc, argv);

finish:
        pager_close();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
