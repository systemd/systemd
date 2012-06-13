/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <sys/reboot.h>
#include <stdio.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <dbus/dbus.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-shutdown.h>

#include "log.h"
#include "util.h"
#include "macro.h"
#include "set.h"
#include "utmp-wtmp.h"
#include "special.h"
#include "initreq.h"
#include "path-util.h"
#include "strv.h"
#include "dbus-common.h"
#include "cgroup-show.h"
#include "cgroup-util.h"
#include "list.h"
#include "path-lookup.h"
#include "conf-parser.h"
#include "exit-status.h"
#include "bus-errors.h"
#include "build.h"
#include "unit-name.h"
#include "pager.h"
#include "spawn-ask-password-agent.h"
#include "spawn-polkit-agent.h"
#include "install.h"
#include "logs-show.h"
#include "path-util.h"

static const char *arg_type = NULL;
static char **arg_property = NULL;
static bool arg_all = false;
static const char *arg_job_mode = "replace";
static UnitFileScope arg_scope = UNIT_FILE_SYSTEM;
static bool arg_no_block = false;
static bool arg_no_legend = false;
static bool arg_no_pager = false;
static bool arg_no_wtmp = false;
static bool arg_no_sync = false;
static bool arg_no_wall = false;
static bool arg_no_reload = false;
static bool arg_dry = false;
static bool arg_quiet = false;
static bool arg_full = false;
static int arg_force = 0;
static bool arg_ask_password = true;
static bool arg_failed = false;
static bool arg_runtime = false;
static char **arg_wall = NULL;
static const char *arg_kill_who = NULL;
static const char *arg_kill_mode = NULL;
static int arg_signal = SIGTERM;
static const char *arg_root = NULL;
static usec_t arg_when = 0;
static enum action {
        ACTION_INVALID,
        ACTION_SYSTEMCTL,
        ACTION_HALT,
        ACTION_POWEROFF,
        ACTION_REBOOT,
        ACTION_KEXEC,
        ACTION_EXIT,
        ACTION_SUSPEND,
        ACTION_HIBERNATE,
        ACTION_RUNLEVEL2,
        ACTION_RUNLEVEL3,
        ACTION_RUNLEVEL4,
        ACTION_RUNLEVEL5,
        ACTION_RESCUE,
        ACTION_EMERGENCY,
        ACTION_DEFAULT,
        ACTION_RELOAD,
        ACTION_REEXEC,
        ACTION_RUNLEVEL,
        ACTION_CANCEL_SHUTDOWN,
        _ACTION_MAX
} arg_action = ACTION_SYSTEMCTL;
static enum dot {
        DOT_ALL,
        DOT_ORDER,
        DOT_REQUIRE
} arg_dot = DOT_ALL;
static enum transport {
        TRANSPORT_NORMAL,
        TRANSPORT_SSH,
        TRANSPORT_POLKIT
} arg_transport = TRANSPORT_NORMAL;
static const char *arg_host = NULL;
static bool arg_follow = false;
static unsigned arg_lines = 10;
static OutputMode arg_output = OUTPUT_SHORT;

static bool private_bus = false;

static int daemon_reload(DBusConnection *bus, char **args);
static void halt_now(enum action a);

static bool on_tty(void) {
        static int t = -1;

        /* Note that this is invoked relatively early, before we start
         * the pager. That means the value we return reflects whether
         * we originally were started on a tty, not if we currently
         * are. But this is intended, since we want colour and so on
         * when run in our own pager. */

        if (_unlikely_(t < 0))
                t = isatty(STDOUT_FILENO) > 0;

        return t;
}

static void pager_open_if_enabled(void) {

        /* Cache result before we open the pager */
        on_tty();

        if (arg_no_pager)
                return;

        pager_open();
}

static void ask_password_agent_open_if_enabled(void) {

        /* Open the password agent as a child process if necessary */

        if (!arg_ask_password)
                return;

        if (arg_scope != UNIT_FILE_SYSTEM)
                return;

        ask_password_agent_open();
}

#ifdef HAVE_LOGIND
static void polkit_agent_open_if_enabled(void) {

        /* Open the polkit agent as a child process if necessary */

        if (!arg_ask_password)
                return;

        if (arg_scope != UNIT_FILE_SYSTEM)
                return;

        polkit_agent_open();
}
#endif

static const char *ansi_highlight_red(bool b) {

        if (!on_tty())
                return "";

        return b ? ANSI_HIGHLIGHT_RED_ON : ANSI_HIGHLIGHT_OFF;
}

static const char *ansi_highlight_green(bool b) {

        if (!on_tty())
                return "";

        return b ? ANSI_HIGHLIGHT_GREEN_ON : ANSI_HIGHLIGHT_OFF;
}

static bool error_is_no_service(const DBusError *error) {
        assert(error);

        if (!dbus_error_is_set(error))
                return false;

        if (dbus_error_has_name(error, DBUS_ERROR_NAME_HAS_NO_OWNER))
                return true;

        if (dbus_error_has_name(error, DBUS_ERROR_SERVICE_UNKNOWN))
                return true;

        return startswith(error->name, "org.freedesktop.DBus.Error.Spawn.");
}

static int translate_bus_error_to_exit_status(int r, const DBusError *error) {
        assert(error);

        if (!dbus_error_is_set(error))
                return r;

        if (dbus_error_has_name(error, DBUS_ERROR_ACCESS_DENIED) ||
            dbus_error_has_name(error, BUS_ERROR_ONLY_BY_DEPENDENCY) ||
            dbus_error_has_name(error, BUS_ERROR_NO_ISOLATION) ||
            dbus_error_has_name(error, BUS_ERROR_TRANSACTION_IS_DESTRUCTIVE))
                return EXIT_NOPERMISSION;

        if (dbus_error_has_name(error, BUS_ERROR_NO_SUCH_UNIT))
                return EXIT_NOTINSTALLED;

        if (dbus_error_has_name(error, BUS_ERROR_JOB_TYPE_NOT_APPLICABLE) ||
            dbus_error_has_name(error, BUS_ERROR_NOT_SUPPORTED))
                return EXIT_NOTIMPLEMENTED;

        if (dbus_error_has_name(error, BUS_ERROR_LOAD_FAILED))
                return EXIT_NOTCONFIGURED;

        if (r != 0)
                return r;

        return EXIT_FAILURE;
}

static void warn_wall(enum action a) {
        static const char *table[_ACTION_MAX] = {
                [ACTION_HALT]      = "The system is going down for system halt NOW!",
                [ACTION_REBOOT]    = "The system is going down for reboot NOW!",
                [ACTION_POWEROFF]  = "The system is going down for power-off NOW!",
                [ACTION_KEXEC]     = "The system is going down for kexec reboot NOW!",
                [ACTION_RESCUE]    = "The system is going down to rescue mode NOW!",
                [ACTION_EMERGENCY] = "The system is going down to emergency mode NOW!"
        };

        if (arg_no_wall)
                return;

        if (arg_wall) {
                char *p;

                p = strv_join(arg_wall, " ");
                if (!p) {
                        log_error("Failed to join strings.");
                        return;
                }

                if (*p) {
                        utmp_wall(p, NULL);
                        free(p);
                        return;
                }

                free(p);
        }

        if (!table[a])
                return;

        utmp_wall(table[a], NULL);
}

static bool avoid_bus(void) {

        if (running_in_chroot() > 0)
                return true;

        if (sd_booted() <= 0)
                return true;

        if (!isempty(arg_root))
                return true;

        if (arg_scope == UNIT_FILE_GLOBAL)
                return true;

        return false;
}

struct unit_info {
        const char *id;
        const char *description;
        const char *load_state;
        const char *active_state;
        const char *sub_state;
        const char *following;
        const char *unit_path;
        uint32_t job_id;
        const char *job_type;
        const char *job_path;
};

static int compare_unit_info(const void *a, const void *b) {
        const char *d1, *d2;
        const struct unit_info *u = a, *v = b;

        d1 = strrchr(u->id, '.');
        d2 = strrchr(v->id, '.');

        if (d1 && d2) {
                int r;

                if ((r = strcasecmp(d1, d2)) != 0)
                        return r;
        }

        return strcasecmp(u->id, v->id);
}

static bool output_show_unit(const struct unit_info *u) {
        const char *dot;

        if (arg_failed)
                return streq(u->active_state, "failed");

        return (!arg_type || ((dot = strrchr(u->id, '.')) &&
                              streq(dot+1, arg_type))) &&
                (arg_all || !(streq(u->active_state, "inactive") || u->following[0]) || u->job_id > 0);
}

static void output_units_list(const struct unit_info *unit_infos, unsigned c) {
        unsigned id_len, max_id_len, active_len, sub_len, job_len, desc_len, n_shown = 0;
        const struct unit_info *u;

        max_id_len = sizeof("UNIT")-1;
        active_len = sizeof("ACTIVE")-1;
        sub_len = sizeof("SUB")-1;
        job_len = sizeof("JOB")-1;
        desc_len = 0;

        for (u = unit_infos; u < unit_infos + c; u++) {
                if (!output_show_unit(u))
                        continue;

                max_id_len = MAX(max_id_len, strlen(u->id));
                active_len = MAX(active_len, strlen(u->active_state));
                sub_len = MAX(sub_len, strlen(u->sub_state));
                if (u->job_id != 0)
                        job_len = MAX(job_len, strlen(u->job_type));
        }

        if (!arg_full) {
                unsigned basic_len;
                id_len = MIN(max_id_len, 25);
                basic_len = 5 + id_len + 6 + active_len + sub_len + job_len;
                if (basic_len < (unsigned) columns()) {
                        unsigned extra_len, incr;
                        extra_len = columns() - basic_len;
                        /* Either UNIT already got 25, or is fully satisfied.
                         * Grant up to 25 to DESC now. */
                        incr = MIN(extra_len, 25);
                        desc_len += incr;
                        extra_len -= incr;
                        /* split the remaining space between UNIT and DESC,
                         * but do not give UNIT more than it needs. */
                        if (extra_len > 0) {
                                incr = MIN(extra_len / 2, max_id_len - id_len);
                                id_len += incr;
                                desc_len += extra_len - incr;
                        }
                }
        } else
                id_len = max_id_len;

        if (!arg_no_legend) {
                printf("%-*s %-6s %-*s %-*s %-*s ", id_len, "UNIT", "LOAD",
                       active_len, "ACTIVE", sub_len, "SUB", job_len, "JOB");
                if (!arg_full && arg_no_pager)
                        printf("%.*s\n", desc_len, "DESCRIPTION");
                else
                        printf("%s\n", "DESCRIPTION");
        }

        for (u = unit_infos; u < unit_infos + c; u++) {
                char *e;
                const char *on_loaded, *off_loaded;
                const char *on_active, *off_active;

                if (!output_show_unit(u))
                        continue;

                n_shown++;

                if (streq(u->load_state, "error")) {
                        on_loaded = ansi_highlight_red(true);
                        off_loaded = ansi_highlight_red(false);
                } else
                        on_loaded = off_loaded = "";

                if (streq(u->active_state, "failed")) {
                        on_active = ansi_highlight_red(true);
                        off_active = ansi_highlight_red(false);
                } else
                        on_active = off_active = "";

                e = arg_full ? NULL : ellipsize(u->id, id_len, 33);

                printf("%-*s %s%-6s%s %s%-*s %-*s%s %-*s ",
                       id_len, e ? e : u->id,
                       on_loaded, u->load_state, off_loaded,
                       on_active, active_len, u->active_state,
                       sub_len, u->sub_state, off_active,
                       job_len, u->job_id ? u->job_type : "");
                if (!arg_full && arg_no_pager)
                        printf("%.*s\n", desc_len, u->description);
                else
                        printf("%s\n", u->description);

                free(e);
        }

        if (!arg_no_legend) {
                printf("\nLOAD   = Reflects whether the unit definition was properly loaded.\n"
                       "ACTIVE = The high-level unit activation state, i.e. generalization of SUB.\n"
                       "SUB    = The low-level unit activation state, values depend on unit type.\n"
                       "JOB    = Pending job for the unit.\n");

                if (arg_all)
                        printf("\n%u units listed.\n", n_shown);
                else
                        printf("\n%u units listed. Pass --all to see inactive units, too.\n", n_shown);
        }
}

static int list_units(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        DBusMessageIter iter, sub, sub2;
        unsigned c = 0, n_units = 0;
        struct unit_info *unit_infos = NULL;

        dbus_error_init(&error);

        assert(bus);

        pager_open_if_enabled();

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "ListUnits"))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                struct unit_info *u;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                if (c >= n_units) {
                        struct unit_info *w;

                        n_units = MAX(2*c, 16);
                        w = realloc(unit_infos, sizeof(struct unit_info) * n_units);

                        if (!w) {
                                log_error("Failed to allocate unit array.");
                                r = -ENOMEM;
                                goto finish;
                        }

                        unit_infos = w;
                }

                u = unit_infos+c;

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &u->id, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &u->description, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &u->load_state, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &u->active_state, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &u->sub_state, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &u->following, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &u->unit_path, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &u->job_id, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &u->job_type, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &u->job_path, false) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_next(&sub);
                c++;
        }

        if (c > 0) {
                qsort(unit_infos, c, sizeof(struct unit_info), compare_unit_info);
                output_units_list(unit_infos, c);
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        free(unit_infos);

        dbus_error_free(&error);

        return r;
}

static int compare_unit_file_list(const void *a, const void *b) {
        const char *d1, *d2;
        const UnitFileList *u = a, *v = b;

        d1 = strrchr(u->path, '.');
        d2 = strrchr(v->path, '.');

        if (d1 && d2) {
                int r;

                r = strcasecmp(d1, d2);
                if (r != 0)
                        return r;
        }

        return strcasecmp(path_get_file_name(u->path), path_get_file_name(v->path));
}

static bool output_show_unit_file(const UnitFileList *u) {
        const char *dot;

        return !arg_type || ((dot = strrchr(u->path, '.')) && streq(dot+1, arg_type));
}

static void output_unit_file_list(const UnitFileList *units, unsigned c) {
        unsigned max_id_len, id_cols, state_cols, n_shown = 0;
        const UnitFileList *u;

        max_id_len = sizeof("UNIT FILE")-1;
        state_cols = sizeof("STATE")-1;
        for (u = units; u < units + c; u++) {
                if (!output_show_unit_file(u))
                        continue;

                max_id_len = MAX(max_id_len, strlen(path_get_file_name(u->path)));
                state_cols = MAX(state_cols, strlen(unit_file_state_to_string(u->state)));
        }

        if (!arg_full) {
                unsigned basic_cols;
                id_cols = MIN(max_id_len, 25);
                basic_cols = 1 + id_cols + state_cols;
                if (basic_cols < (unsigned) columns())
                        id_cols += MIN(columns() - basic_cols, max_id_len - id_cols);
        } else
                id_cols = max_id_len;

        if (!arg_no_legend)
                printf("%-*s %-*s\n", id_cols, "UNIT FILE", state_cols, "STATE");

        for (u = units; u < units + c; u++) {
                char *e;
                const char *on, *off;
                const char *id;

                if (!output_show_unit_file(u))
                        continue;

                n_shown++;

                if (u->state == UNIT_FILE_MASKED ||
                    u->state == UNIT_FILE_MASKED_RUNTIME ||
                    u->state == UNIT_FILE_DISABLED) {
                        on  = ansi_highlight_red(true);
                        off = ansi_highlight_red(false);
                } else if (u->state == UNIT_FILE_ENABLED) {
                        on  = ansi_highlight_green(true);
                        off = ansi_highlight_green(false);
                } else
                        on = off = "";

                id = path_get_file_name(u->path);

                e = arg_full ? NULL : ellipsize(id, id_cols, 33);

                printf("%-*s %s%-*s%s\n",
                       id_cols, e ? e : id,
                       on, state_cols, unit_file_state_to_string(u->state), off);

                free(e);
        }

        if (!arg_no_legend)
                printf("\n%u unit files listed.\n", n_shown);
}

static int list_unit_files(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        DBusMessageIter iter, sub, sub2;
        unsigned c = 0, n_units = 0;
        UnitFileList *units = NULL;

        dbus_error_init(&error);

        pager_open_if_enabled();

        if (avoid_bus()) {
                Hashmap *h;
                UnitFileList *u;
                Iterator i;

                h = hashmap_new(string_hash_func, string_compare_func);
                if (!h) {
                        log_error("Out of memory");
                        return -ENOMEM;
                }

                r = unit_file_get_list(arg_scope, arg_root, h);
                if (r < 0) {
                        unit_file_list_free(h);
                        log_error("Failed to get unit file list: %s", strerror(-r));
                        return r;
                }

                n_units = hashmap_size(h);
                units = new(UnitFileList, n_units);
                if (!units) {
                        unit_file_list_free(h);
                        log_error("Out of memory");
                        return -ENOMEM;
                }

                HASHMAP_FOREACH(u, h, i) {
                        memcpy(units + c++, u, sizeof(UnitFileList));
                        free(u);
                }

                hashmap_free(h);
        } else {
                assert(bus);

                m = dbus_message_new_method_call(
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "ListUnitFiles");
                if (!m) {
                        log_error("Could not allocate message.");
                        return -ENOMEM;
                }

                reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
                if (!reply) {
                        log_error("Failed to issue method call: %s", bus_error_message(&error));
                        r = -EIO;
                        goto finish;
                }

                if (!dbus_message_iter_init(reply, &iter) ||
                    dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
                    dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&iter, &sub);

                while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                        UnitFileList *u;
                        const char *state;

                        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                                log_error("Failed to parse reply.");
                                r = -EIO;
                                goto finish;
                        }

                        if (c >= n_units) {
                                UnitFileList *w;

                                n_units = MAX(2*c, 16);
                                w = realloc(units, sizeof(struct UnitFileList) * n_units);

                                if (!w) {
                                        log_error("Failed to allocate unit array.");
                                        r = -ENOMEM;
                                        goto finish;
                                }

                                units = w;
                        }

                        u = units+c;

                        dbus_message_iter_recurse(&sub, &sub2);

                        if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &u->path, true) < 0 ||
                            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &state, false) < 0) {
                                log_error("Failed to parse reply.");
                                r = -EIO;
                                goto finish;
                        }

                        u->state = unit_file_state_from_string(state);

                        dbus_message_iter_next(&sub);
                        c++;
                }
        }

        if (c > 0) {
                qsort(units, c, sizeof(UnitFileList), compare_unit_file_list);
                output_unit_file_list(units, c);
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        free(units);

        dbus_error_free(&error);

        return r;
}

static int dot_one_property(const char *name, const char *prop, DBusMessageIter *iter) {
        static const char * const colors[] = {
                "Requires",              "[color=\"black\"]",
                "RequiresOverridable",   "[color=\"black\"]",
                "Requisite",             "[color=\"darkblue\"]",
                "RequisiteOverridable",  "[color=\"darkblue\"]",
                "Wants",                 "[color=\"darkgrey\"]",
                "Conflicts",             "[color=\"red\"]",
                "ConflictedBy",          "[color=\"red\"]",
                "After",                 "[color=\"green\"]"
        };

        const char *c = NULL;
        unsigned i;

        assert(name);
        assert(prop);
        assert(iter);

        for (i = 0; i < ELEMENTSOF(colors); i += 2)
                if (streq(colors[i], prop)) {
                        c = colors[i+1];
                        break;
                }

        if (!c)
                return 0;

        if (arg_dot != DOT_ALL)
                if ((arg_dot == DOT_ORDER) != streq(prop, "After"))
                        return 0;

        switch (dbus_message_iter_get_arg_type(iter)) {

        case DBUS_TYPE_ARRAY:

                if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRING) {
                        DBusMessageIter sub;

                        dbus_message_iter_recurse(iter, &sub);

                        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                                const char *s;

                                assert(dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING);
                                dbus_message_iter_get_basic(&sub, &s);
                                printf("\t\"%s\"->\"%s\" %s;\n", name, s, c);

                                dbus_message_iter_next(&sub);
                        }

                        return 0;
                }
        }

        return 0;
}

static int dot_one(DBusConnection *bus, const char *name, const char *path) {
        DBusMessage *m = NULL, *reply = NULL;
        const char *interface = "org.freedesktop.systemd1.Unit";
        int r;
        DBusError error;
        DBusMessageIter iter, sub, sub2, sub3;

        assert(bus);
        assert(path);

        dbus_error_init(&error);

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              path,
                              "org.freedesktop.DBus.Properties",
                              "GetAll"))) {
                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &interface,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_DICT_ENTRY)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *prop;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_DICT_ENTRY) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &prop, true) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                if (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_VARIANT)  {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub2, &sub3);

                if (dot_one_property(name, prop, &sub3)) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_next(&sub);
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int dot(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        DBusMessageIter iter, sub, sub2;

        dbus_error_init(&error);

        assert(bus);

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "ListUnits"))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        printf("digraph systemd {\n");

        dbus_message_iter_recurse(&iter, &sub);
        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *id, *description, *load_state, *active_state, *sub_state, *following, *unit_path;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &id, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &description, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &load_state, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &active_state, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &sub_state, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &following, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &unit_path, true) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                if ((r = dot_one(bus, id, unit_path)) < 0)
                        goto finish;

                /* printf("\t\"%s\";\n", id); */
                dbus_message_iter_next(&sub);
        }

        printf("}\n");

        log_info("   Color legend: black     = Requires\n"
                 "                 dark blue = Requisite\n"
                 "                 dark grey = Wants\n"
                 "                 red       = Conflicts\n"
                 "                 green     = After\n");

        if (on_tty())
                log_notice("-- You probably want to process this output with graphviz' dot tool.\n"
                           "-- Try a shell pipeline like 'systemctl dot | dot -Tsvg > systemd.svg'!\n");

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int list_jobs(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        DBusMessageIter iter, sub, sub2;
        unsigned k = 0;

        dbus_error_init(&error);

        assert(bus);

        pager_open_if_enabled();

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "ListJobs"))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (on_tty())
                printf("%4s %-25s %-15s %-7s\n", "JOB", "UNIT", "TYPE", "STATE");

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *name, *type, *state, *job_path, *unit_path;
                uint32_t id;
                char *e;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &id, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &name, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &type, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &state, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &job_path, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_OBJECT_PATH, &unit_path, false) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                e = arg_full ? NULL : ellipsize(name, 25, 33);
                printf("%4u %-25s %-15s %-7s\n", id, e ? e : name, type, state);
                free(e);

                k++;

                dbus_message_iter_next(&sub);
        }

        if (on_tty())
                printf("\n%u jobs listed.\n", k);

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int load_unit(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL;
        DBusError error;
        int r;
        char **name;

        dbus_error_init(&error);

        assert(bus);
        assert(args);

        STRV_FOREACH(name, args+1) {
                DBusMessage *reply;

                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager",
                                      "LoadUnit"))) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, name,
                                              DBUS_TYPE_INVALID)) {
                        log_error("Could not append arguments to message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                        log_error("Failed to issue method call: %s", bus_error_message(&error));
                        r = -EIO;
                        goto finish;
                }

                dbus_message_unref(m);
                dbus_message_unref(reply);

                m = reply = NULL;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        dbus_error_free(&error);

        return r;
}

static int cancel_job(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        char **name;

        dbus_error_init(&error);

        assert(bus);
        assert(args);

        if (strv_length(args) <= 1)
                return daemon_reload(bus, args);

        STRV_FOREACH(name, args+1) {
                unsigned id;
                const char *path;

                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager",
                                      "GetJob"))) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if ((r = safe_atou(*name, &id)) < 0) {
                        log_error("Failed to parse job id: %s", strerror(-r));
                        goto finish;
                }

                assert_cc(sizeof(uint32_t) == sizeof(id));
                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_UINT32, &id,
                                              DBUS_TYPE_INVALID)) {
                        log_error("Could not append arguments to message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                        log_error("Failed to issue method call: %s", bus_error_message(&error));
                        r = -EIO;
                        goto finish;
                }

                if (!dbus_message_get_args(reply, &error,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse reply: %s", bus_error_message(&error));
                        r = -EIO;
                        goto finish;
                }

                dbus_message_unref(m);
                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      path,
                                      "org.freedesktop.systemd1.Job",
                                      "Cancel"))) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                dbus_message_unref(reply);
                if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                        log_error("Failed to issue method call: %s", bus_error_message(&error));
                        r = -EIO;
                        goto finish;
                }

                dbus_message_unref(m);
                dbus_message_unref(reply);
                m = reply = NULL;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static bool need_daemon_reload(DBusConnection *bus, const char *unit) {
        DBusMessage *m = NULL, *reply = NULL;
        dbus_bool_t b = FALSE;
        DBusMessageIter iter, sub;
        const char
                *interface = "org.freedesktop.systemd1.Unit",
                *property = "NeedDaemonReload",
                *path;

        /* We ignore all errors here, since this is used to show a warning only */

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "GetUnit")))
                goto finish;

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &unit,
                                      DBUS_TYPE_INVALID))
                goto finish;

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, NULL)))
                goto finish;

        if (!dbus_message_get_args(reply, NULL,
                                   DBUS_TYPE_OBJECT_PATH, &path,
                                   DBUS_TYPE_INVALID))
                goto finish;

        dbus_message_unref(m);
        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              path,
                              "org.freedesktop.DBus.Properties",
                              "Get")))
                goto finish;

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &interface,
                                      DBUS_TYPE_STRING, &property,
                                      DBUS_TYPE_INVALID)) {
                goto finish;
        }

        dbus_message_unref(reply);
        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, NULL)))
                goto finish;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
                goto finish;

        dbus_message_iter_recurse(&iter, &sub);

        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_BOOLEAN)
                goto finish;

        dbus_message_iter_get_basic(&sub, &b);

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        return b;
}

typedef struct WaitData {
        Set *set;
        char *result;
} WaitData;

static DBusHandlerResult wait_filter(DBusConnection *connection, DBusMessage *message, void *data) {
        DBusError error;
        WaitData *d = data;

        assert(connection);
        assert(message);
        assert(d);

        dbus_error_init(&error);

        log_debug("Got D-Bus request: %s.%s() on %s",
                  dbus_message_get_interface(message),
                  dbus_message_get_member(message),
                  dbus_message_get_path(message));

        if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
                log_error("Warning! D-Bus connection terminated.");
                dbus_connection_close(connection);

        } else if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Manager", "JobRemoved")) {
                uint32_t id;
                const char *path, *result, *unit;
                dbus_bool_t success = true;

                if (dbus_message_get_args(message, &error,
                                          DBUS_TYPE_UINT32, &id,
                                          DBUS_TYPE_OBJECT_PATH, &path,
                                          DBUS_TYPE_STRING, &unit,
                                          DBUS_TYPE_STRING, &result,
                                          DBUS_TYPE_INVALID)) {
                        char *p;

                        p = set_remove(d->set, (char*) path);
                        free(p);

                        if (*result)
                                d->result = strdup(result);

                        goto finish;
                }
#ifndef LEGACY
                dbus_error_free(&error);
                if (dbus_message_get_args(message, &error,
                                          DBUS_TYPE_UINT32, &id,
                                          DBUS_TYPE_OBJECT_PATH, &path,
                                          DBUS_TYPE_STRING, &result,
                                          DBUS_TYPE_INVALID)) {
                        char *p;

                        /* Compatibility with older systemd versions <
                         * 183 during upgrades. This should be dropped
                         * one day. */
                        p = set_remove(d->set, (char*) path);
                        free(p);

                        if (*result)
                                d->result = strdup(result);

                        goto finish;
                }

                dbus_error_free(&error);
                if (dbus_message_get_args(message, &error,
                                          DBUS_TYPE_UINT32, &id,
                                          DBUS_TYPE_OBJECT_PATH, &path,
                                          DBUS_TYPE_BOOLEAN, &success,
                                          DBUS_TYPE_INVALID)) {
                        char *p;

                        /* Compatibility with older systemd versions <
                         * 19 during upgrades. This should be dropped
                         * one day */

                        p = set_remove(d->set, (char*) path);
                        free(p);

                        if (!success)
                                d->result = strdup("failed");

                        goto finish;
                }
#endif

                log_error("Failed to parse message: %s", bus_error_message(&error));
        }

finish:
        dbus_error_free(&error);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int enable_wait_for_jobs(DBusConnection *bus) {
        DBusError error;

        assert(bus);

        if (private_bus)
                return 0;

        dbus_error_init(&error);
        dbus_bus_add_match(bus,
                           "type='signal',"
                           "sender='org.freedesktop.systemd1',"
                           "interface='org.freedesktop.systemd1.Manager',"
                           "member='JobRemoved',"
                           "path='/org/freedesktop/systemd1'",
                           &error);

        if (dbus_error_is_set(&error)) {
                log_error("Failed to add match: %s", bus_error_message(&error));
                dbus_error_free(&error);
                return -EIO;
        }

        /* This is slightly dirty, since we don't undo the match registrations. */
        return 0;
}

static int wait_for_jobs(DBusConnection *bus, Set *s) {
        int r;
        WaitData d;

        assert(bus);
        assert(s);

        zero(d);
        d.set = s;

        if (!dbus_connection_add_filter(bus, wait_filter, &d, NULL)) {
                log_error("Failed to add filter.");
                r = -ENOMEM;
                goto finish;
        }

        while (!set_isempty(s) &&
               dbus_connection_read_write_dispatch(bus, -1))
                ;

        if (!arg_quiet && d.result) {
                if (streq(d.result, "timeout"))
                        log_error("Job timed out.");
                else if (streq(d.result, "canceled"))
                        log_error("Job canceled.");
                else if (streq(d.result, "dependency"))
                        log_error("A dependency job failed. See system journal for details.");
                else if (!streq(d.result, "done") && !streq(d.result, "skipped"))
                        log_error("Job failed. See system journal and 'systemctl status' for details.");
        }

        if (streq_ptr(d.result, "timeout"))
                r = -ETIME;
        else if (streq_ptr(d.result, "canceled"))
                r = -ECANCELED;
        else if (!streq_ptr(d.result, "done") && !streq_ptr(d.result, "skipped"))
                r = -EIO;
        else
                r = 0;

        free(d.result);

finish:
        /* This is slightly dirty, since we don't undo the filter registration. */

        return r;
}

static int get_unit_path(
                DBusConnection *bus,
                const char *name,
                char **unit_path) {

        DBusError error;
        DBusMessage *m = NULL, *reply = NULL;
        char *path;
        int r = 0;

        assert(bus);
        assert(name);
        assert(unit_path);

        dbus_error_init(&error);

        m = dbus_message_new_method_call("org.freedesktop.systemd1",
                                         "/org/freedesktop/systemd1",
                                         "org.freedesktop.systemd1.Manager",
                                         "GetUnit");
        if (!m) {
                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &name,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                if (streq(error.name, BUS_ERROR_NO_SUCH_UNIT))
                        r = -EINVAL;
                else {
                        log_error("Failed to issue method call: %s", bus_error_message(&error));
                        r = -EIO;
                }
                goto finish;
        }

        if (!dbus_message_get_args(reply, &error,
                                   DBUS_TYPE_OBJECT_PATH, &path,
                                   DBUS_TYPE_INVALID)) {
                log_error("Failed to parse reply: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        *unit_path = strdup(path);
        if (!(*unit_path)) {
               log_error("Failed to duplicate unit path");
               r = -ENOMEM;
        }
finish:
        if (m)
                dbus_message_unref(m);
        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int check_one_unit(DBusConnection *bus, char *name, bool quiet) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        DBusMessageIter iter, sub;
        const char
                *interface = "org.freedesktop.systemd1.Unit",
                *property = "ActiveState";
        const char *path = NULL;
        const char *state;
        int r = 3; /* According to LSB: "program is not running" */

        assert(bus);
        assert(name);

        dbus_error_init(&error);

        m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "GetUnit");
        if (!m) {
                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &name,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                /* Hmm, cannot figure out anything about this unit... */
                if (!quiet)
                        puts("unknown");

                goto finish;
        }

        if (!dbus_message_get_args(reply, &error,
                                   DBUS_TYPE_OBJECT_PATH, &path,
                                   DBUS_TYPE_INVALID)) {
                log_error("Failed to parse reply: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        dbus_message_unref(m);
        m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              path,
                              "org.freedesktop.DBus.Properties",
                              "Get");
        if (!m) {
                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &interface,
                                      DBUS_TYPE_STRING, &property,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        dbus_message_unref(reply);
        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_get_basic(&sub, &state);

        if (!quiet)
                puts(state);

        if (streq(state, "active") || streq(state, "reloading"))
                r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static void check_listening_sockets(
                DBusConnection *bus,
                const char *unit_name) {

        DBusError error;
        DBusMessage *m = NULL, *reply = NULL;
        DBusMessageIter iter, sub;
        char *service_trigger = NULL;
        const char *interface = "org.freedesktop.systemd1.Unit",
                   *triggered_by_property = "TriggeredBy";

        char *unit_path = NULL;
        bool print_warning_label = true;

        dbus_error_init(&error);

        if (get_unit_path(bus, unit_name, &unit_path) < 0)
                goto finish;

        m = dbus_message_new_method_call("org.freedesktop.systemd1",
                                         unit_path,
                                         "org.freedesktop.DBus.Properties",
                                         "Get");
        if (!m) {
                log_error("Could not allocate message.");
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &interface,
                                      DBUS_TYPE_STRING, &triggered_by_property,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                goto finish;
        }

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
                log_error("Failed to parse reply: %s", bus_error_message(&error));
                goto finish;

        }

        dbus_message_iter_recurse(&iter, &sub);
        dbus_message_iter_recurse(&sub, &iter);
        sub = iter;

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                int r;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING) {
                        log_error("Failed to parse reply: %s", bus_error_message(&error));
                        goto finish;
                }

                dbus_message_iter_get_basic(&sub, &service_trigger);

                if (!endswith(service_trigger, ".socket"))
                        goto next;

                r = check_one_unit(bus, service_trigger, true);
                if (r < 0)
                        goto finish;
                if (r == 0) {
                        if (print_warning_label) {
                                log_warning("There are listening sockets associated with %s :", unit_name);
                                print_warning_label = false;
                        }
                        log_warning("%s", service_trigger);
                }
next:
                dbus_message_iter_recurse(&iter, &sub);
                iter = sub;
        }
finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        free(unit_path);
}

static int start_unit_one(
                DBusConnection *bus,
                const char *method,
                const char *name,
                const char *mode,
                DBusError *error,
                Set *s) {

        DBusMessage *m = NULL, *reply = NULL;
        const char *path;
        int r;

        assert(bus);
        assert(method);
        assert(name);
        assert(mode);
        assert(error);
        assert(arg_no_block || s);

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              method))) {
                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &name,
                                      DBUS_TYPE_STRING, &mode,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, error))) {

                if (arg_action != ACTION_SYSTEMCTL && error_is_no_service(error)) {
                        /* There's always a fallback possible for
                         * legacy actions. */
                        r = -EADDRNOTAVAIL;
                        goto finish;
                }

                log_error("Failed to issue method call: %s", bus_error_message(error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_get_args(reply, error,
                                   DBUS_TYPE_OBJECT_PATH, &path,
                                   DBUS_TYPE_INVALID)) {
                log_error("Failed to parse reply: %s", bus_error_message(error));
                r = -EIO;
                goto finish;
        }

        if (need_daemon_reload(bus, name))
                log_warning("Warning: Unit file of created job changed on disk, 'systemctl %s daemon-reload' recommended.",
                            arg_scope == UNIT_FILE_SYSTEM ? "--system" : "--user");

        if (!arg_no_block) {
                char *p;

                if (!(p = strdup(path))) {
                        log_error("Failed to duplicate path.");
                        r = -ENOMEM;
                        goto finish;
                }

                if ((r = set_put(s, p)) < 0) {
                        free(p);
                        log_error("Failed to add path to set.");
                        goto finish;
                }
        }

        /* When stopping unit check if we have some listening sockets active */
        if (streq(method, "StopUnit") && !arg_quiet)
                check_listening_sockets(bus, name);

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        return r;
}

static enum action verb_to_action(const char *verb) {
        if (streq(verb, "halt"))
                return ACTION_HALT;
        else if (streq(verb, "poweroff"))
                return ACTION_POWEROFF;
        else if (streq(verb, "reboot"))
                return ACTION_REBOOT;
        else if (streq(verb, "kexec"))
                return ACTION_KEXEC;
        else if (streq(verb, "rescue"))
                return ACTION_RESCUE;
        else if (streq(verb, "emergency"))
                return ACTION_EMERGENCY;
        else if (streq(verb, "default"))
                return ACTION_DEFAULT;
        else if (streq(verb, "exit"))
                return ACTION_EXIT;
        else if (streq(verb, "suspend"))
                return ACTION_SUSPEND;
        else if (streq(verb, "hibernate"))
                return ACTION_HIBERNATE;
        else
                return ACTION_INVALID;
}

static int start_unit(DBusConnection *bus, char **args) {

        static const char * const table[_ACTION_MAX] = {
                [ACTION_HALT] = SPECIAL_HALT_TARGET,
                [ACTION_POWEROFF] = SPECIAL_POWEROFF_TARGET,
                [ACTION_REBOOT] = SPECIAL_REBOOT_TARGET,
                [ACTION_KEXEC] = SPECIAL_KEXEC_TARGET,
                [ACTION_RUNLEVEL2] = SPECIAL_RUNLEVEL2_TARGET,
                [ACTION_RUNLEVEL3] = SPECIAL_RUNLEVEL3_TARGET,
                [ACTION_RUNLEVEL4] = SPECIAL_RUNLEVEL4_TARGET,
                [ACTION_RUNLEVEL5] = SPECIAL_RUNLEVEL5_TARGET,
                [ACTION_RESCUE] = SPECIAL_RESCUE_TARGET,
                [ACTION_EMERGENCY] = SPECIAL_EMERGENCY_TARGET,
                [ACTION_DEFAULT] = SPECIAL_DEFAULT_TARGET,
                [ACTION_EXIT] = SPECIAL_EXIT_TARGET,
                [ACTION_SUSPEND] = SPECIAL_SUSPEND_TARGET,
                [ACTION_HIBERNATE] = SPECIAL_HIBERNATE_TARGET
        };

        int r, ret = 0;
        const char *method, *mode, *one_name;
        Set *s = NULL;
        DBusError error;
        char **name;

        dbus_error_init(&error);

        assert(bus);

        ask_password_agent_open_if_enabled();

        if (arg_action == ACTION_SYSTEMCTL) {
                method =
                        streq(args[0], "stop") ||
                        streq(args[0], "condstop")              ? "StopUnit" :
                        streq(args[0], "reload")                ? "ReloadUnit" :
                        streq(args[0], "restart")               ? "RestartUnit" :

                        streq(args[0], "try-restart")           ||
                        streq(args[0], "condrestart")           ? "TryRestartUnit" :

                        streq(args[0], "reload-or-restart")     ? "ReloadOrRestartUnit" :

                        streq(args[0], "reload-or-try-restart") ||
                        streq(args[0], "condreload") ||

                        streq(args[0], "force-reload")          ? "ReloadOrTryRestartUnit" :
                                                                  "StartUnit";

                mode =
                        (streq(args[0], "isolate") ||
                         streq(args[0], "rescue")  ||
                         streq(args[0], "emergency")) ? "isolate" : arg_job_mode;

                one_name = table[verb_to_action(args[0])];

        } else {
                assert(arg_action < ELEMENTSOF(table));
                assert(table[arg_action]);

                method = "StartUnit";

                mode = (arg_action == ACTION_EMERGENCY ||
                        arg_action == ACTION_RESCUE ||
                        arg_action == ACTION_RUNLEVEL2 ||
                        arg_action == ACTION_RUNLEVEL3 ||
                        arg_action == ACTION_RUNLEVEL4 ||
                        arg_action == ACTION_RUNLEVEL5) ? "isolate" : "replace";

                one_name = table[arg_action];
        }

        if (!arg_no_block) {
                if ((ret = enable_wait_for_jobs(bus)) < 0) {
                        log_error("Could not watch jobs: %s", strerror(-ret));
                        goto finish;
                }

                if (!(s = set_new(string_hash_func, string_compare_func))) {
                        log_error("Failed to allocate set.");
                        ret = -ENOMEM;
                        goto finish;
                }
        }

        if (one_name) {
                if ((ret = start_unit_one(bus, method, one_name, mode, &error, s)) <= 0)
                        goto finish;
        } else {
                STRV_FOREACH(name, args+1)
                        if ((r = start_unit_one(bus, method, *name, mode, &error, s)) != 0) {
                                ret = translate_bus_error_to_exit_status(r, &error);
                                dbus_error_free(&error);
                        }
        }

        if (!arg_no_block)
                if ((r = wait_for_jobs(bus, s)) < 0) {
                        ret = r;
                        goto finish;
                }

finish:
        if (s)
                set_free_free(s);

        dbus_error_free(&error);

        return ret;
}

/* Ask systemd-logind, which might grant access to unprivileged users
 * through PolicyKit */
static int reboot_with_logind(DBusConnection *bus, enum action a) {
#ifdef HAVE_LOGIND
        const char *method;
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        dbus_bool_t interactive = true;
        int r;

        dbus_error_init(&error);

        polkit_agent_open_if_enabled();

        switch (a) {

        case ACTION_REBOOT:
                method = "Reboot";
                break;

        case ACTION_POWEROFF:
                method = "PowerOff";
                break;

        case ACTION_SUSPEND:
                method = "Suspend";
                break;

        case ACTION_HIBERNATE:
                method = "Hibernate";
                break;

        default:
                return -EINVAL;
        }

        m = dbus_message_new_method_call(
                                "org.freedesktop.login1",
                                "/org/freedesktop/login1",
                                "org.freedesktop.login1.Manager",
                                method);
        if (!m) {
                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_BOOLEAN, &interactive,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                if (error_is_no_service(&error)) {
                        log_debug("Failed to issue method call: %s", bus_error_message(&error));
                        r = -ENOENT;
                        goto finish;
                }

                if (dbus_error_has_name(&error, DBUS_ERROR_ACCESS_DENIED)) {
                        log_debug("Failed to issue method call: %s", bus_error_message(&error));
                        r = -EACCES;
                        goto finish;
                }

                log_info("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
#else
        return -ENOSYS;
#endif
}

static int start_special(DBusConnection *bus, char **args) {
        enum action a;
        int r;

        assert(args);

        a = verb_to_action(args[0]);

        if (arg_force >= 2 && geteuid() != 0) {
                log_error("Must be root.");
                return -EPERM;
        }

        if (arg_force >= 2 &&
            (a == ACTION_HALT ||
             a == ACTION_POWEROFF ||
             a == ACTION_REBOOT))
                halt_now(a);

        if (arg_force >= 1 &&
            (a == ACTION_HALT ||
             a == ACTION_POWEROFF ||
             a == ACTION_REBOOT ||
             a == ACTION_KEXEC ||
             a == ACTION_EXIT))
                return daemon_reload(bus, args);

        /* first try logind, to allow authentication with polkit */
        if (geteuid() != 0 &&
            (a == ACTION_POWEROFF ||
             a == ACTION_REBOOT ||
             a == ACTION_SUSPEND ||
             a == ACTION_HIBERNATE)) {
                r = reboot_with_logind(bus, a);
                if (r >= 0)
                        return r;
        }

        r = start_unit(bus, args);
        if (r >= 0)
                warn_wall(a);

        return r;
}

static int check_unit(DBusConnection *bus, char **args) {
        char **name;
        int r = 3; /* According to LSB: "program is not running" */

        assert(bus);
        assert(args);

        STRV_FOREACH(name, args+1) {
                int state = check_one_unit(bus, *name, arg_quiet);
                if (state < 0)
                        return state;
                if (state == 0)
                        r = 0;
        }

        return r;
}

static int kill_unit(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL;
        int r = 0;
        DBusError error;
        char **name;

        assert(bus);
        assert(args);

        dbus_error_init(&error);

        if (!arg_kill_who)
                arg_kill_who = "all";

        if (!arg_kill_mode)
                arg_kill_mode = streq(arg_kill_who, "all") ? "control-group" : "process";

        STRV_FOREACH(name, args+1) {
                DBusMessage *reply;

                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager",
                                      "KillUnit"))) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, name,
                                              DBUS_TYPE_STRING, &arg_kill_who,
                                              DBUS_TYPE_STRING, &arg_kill_mode,
                                              DBUS_TYPE_INT32, &arg_signal,
                                              DBUS_TYPE_INVALID)) {
                        log_error("Could not append arguments to message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                        log_error("Failed to issue method call: %s", bus_error_message(&error));
                        dbus_error_free(&error);
                        r = -EIO;
                }

                dbus_message_unref(m);

                if (reply)
                        dbus_message_unref(reply);
                m = reply = NULL;
        }

finish:
        if (m)
                dbus_message_unref(m);

        dbus_error_free(&error);

        return r;
}

typedef struct ExecStatusInfo {
        char *name;

        char *path;
        char **argv;

        bool ignore;

        usec_t start_timestamp;
        usec_t exit_timestamp;
        pid_t pid;
        int code;
        int status;

        LIST_FIELDS(struct ExecStatusInfo, exec);
} ExecStatusInfo;

static void exec_status_info_free(ExecStatusInfo *i) {
        assert(i);

        free(i->name);
        free(i->path);
        strv_free(i->argv);
        free(i);
}

static int exec_status_info_deserialize(DBusMessageIter *sub, ExecStatusInfo *i) {
        uint64_t start_timestamp, exit_timestamp, start_timestamp_monotonic, exit_timestamp_monotonic;
        DBusMessageIter sub2, sub3;
        const char*path;
        unsigned n;
        uint32_t pid;
        int32_t code, status;
        dbus_bool_t ignore;

        assert(i);
        assert(i);

        if (dbus_message_iter_get_arg_type(sub) != DBUS_TYPE_STRUCT)
                return -EIO;

        dbus_message_iter_recurse(sub, &sub2);

        if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, true) < 0)
                return -EIO;

        if (!(i->path = strdup(path)))
                return -ENOMEM;

        if (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&sub2) != DBUS_TYPE_STRING)
                return -EIO;

        n = 0;
        dbus_message_iter_recurse(&sub2, &sub3);
        while (dbus_message_iter_get_arg_type(&sub3) != DBUS_TYPE_INVALID) {
                assert(dbus_message_iter_get_arg_type(&sub3) == DBUS_TYPE_STRING);
                dbus_message_iter_next(&sub3);
                n++;
        }


        if (!(i->argv = new0(char*, n+1)))
                return -ENOMEM;

        n = 0;
        dbus_message_iter_recurse(&sub2, &sub3);
        while (dbus_message_iter_get_arg_type(&sub3) != DBUS_TYPE_INVALID) {
                const char *s;

                assert(dbus_message_iter_get_arg_type(&sub3) == DBUS_TYPE_STRING);
                dbus_message_iter_get_basic(&sub3, &s);
                dbus_message_iter_next(&sub3);

                if (!(i->argv[n++] = strdup(s)))
                        return -ENOMEM;
        }

        if (!dbus_message_iter_next(&sub2) ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_BOOLEAN, &ignore, true) < 0 ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &start_timestamp, true) < 0 ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &start_timestamp_monotonic, true) < 0 ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &exit_timestamp, true) < 0 ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &exit_timestamp_monotonic, true) < 0 ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT32, &pid, true) < 0 ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_INT32, &code, true) < 0 ||
            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_INT32, &status, false) < 0)
                return -EIO;

        i->ignore = ignore;
        i->start_timestamp = (usec_t) start_timestamp;
        i->exit_timestamp = (usec_t) exit_timestamp;
        i->pid = (pid_t) pid;
        i->code = code;
        i->status = status;

        return 0;
}

typedef struct UnitStatusInfo {
        const char *id;
        const char *load_state;
        const char *active_state;
        const char *sub_state;
        const char *unit_file_state;

        const char *description;
        const char *following;

        char **documentation;

        const char *fragment_path;
        const char *source_path;
        const char *default_control_group;

        const char *load_error;
        const char *result;

        usec_t inactive_exit_timestamp;
        usec_t inactive_exit_timestamp_monotonic;
        usec_t active_enter_timestamp;
        usec_t active_exit_timestamp;
        usec_t inactive_enter_timestamp;

        bool need_daemon_reload;

        /* Service */
        pid_t main_pid;
        pid_t control_pid;
        const char *status_text;
        bool running:1;

        usec_t start_timestamp;
        usec_t exit_timestamp;

        int exit_code, exit_status;

        usec_t condition_timestamp;
        bool condition_result;

        /* Socket */
        unsigned n_accepted;
        unsigned n_connections;
        bool accept;

        /* Device */
        const char *sysfs_path;

        /* Mount, Automount */
        const char *where;

        /* Swap */
        const char *what;

        LIST_HEAD(ExecStatusInfo, exec);
} UnitStatusInfo;

static void print_status_info(UnitStatusInfo *i) {
        ExecStatusInfo *p;
        const char *on, *off, *ss;
        usec_t timestamp;
        char since1[FORMAT_TIMESTAMP_PRETTY_MAX], *s1;
        char since2[FORMAT_TIMESTAMP_MAX], *s2;
        const char *path;

        assert(i);

        /* This shows pretty information about a unit. See
         * print_property() for a low-level property printer */

        printf("%s", strna(i->id));

        if (i->description && !streq_ptr(i->id, i->description))
                printf(" - %s", i->description);

        printf("\n");

        if (i->following)
                printf("\t  Follow: unit currently follows state of %s\n", i->following);

        if (streq_ptr(i->load_state, "error")) {
                on = ansi_highlight_red(true);
                off = ansi_highlight_red(false);
        } else
                on = off = "";

        path = i->source_path ? i->source_path : i->fragment_path;

        if (i->load_error)
                printf("\t  Loaded: %s%s%s (Reason: %s)\n", on, strna(i->load_state), off, i->load_error);
        else if (path && i->unit_file_state)
                printf("\t  Loaded: %s%s%s (%s; %s)\n", on, strna(i->load_state), off, path, i->unit_file_state);
        else if (path)
                printf("\t  Loaded: %s%s%s (%s)\n", on, strna(i->load_state), off, path);
        else
                printf("\t  Loaded: %s%s%s\n", on, strna(i->load_state), off);

        ss = streq_ptr(i->active_state, i->sub_state) ? NULL : i->sub_state;

        if (streq_ptr(i->active_state, "failed")) {
                on = ansi_highlight_red(true);
                off = ansi_highlight_red(false);
        } else if (streq_ptr(i->active_state, "active") || streq_ptr(i->active_state, "reloading")) {
                on = ansi_highlight_green(true);
                off = ansi_highlight_green(false);
        } else
                on = off = "";

        if (ss)
                printf("\t  Active: %s%s (%s)%s",
                       on,
                       strna(i->active_state),
                       ss,
                       off);
        else
                printf("\t  Active: %s%s%s",
                       on,
                       strna(i->active_state),
                       off);

        if (!isempty(i->result) && !streq(i->result, "success"))
                printf(" (Result: %s)", i->result);

        timestamp = (streq_ptr(i->active_state, "active")      ||
                     streq_ptr(i->active_state, "reloading"))   ? i->active_enter_timestamp :
                    (streq_ptr(i->active_state, "inactive")    ||
                     streq_ptr(i->active_state, "failed"))      ? i->inactive_enter_timestamp :
                    streq_ptr(i->active_state, "activating")    ? i->inactive_exit_timestamp :
                                                                  i->active_exit_timestamp;

        s1 = format_timestamp_pretty(since1, sizeof(since1), timestamp);
        s2 = format_timestamp(since2, sizeof(since2), timestamp);

        if (s1)
                printf(" since %s; %s\n", s2, s1);
        else if (s2)
                printf(" since %s\n", s2);
        else
                printf("\n");

        if (!i->condition_result && i->condition_timestamp > 0) {
                s1 = format_timestamp_pretty(since1, sizeof(since1), i->condition_timestamp);
                s2 = format_timestamp(since2, sizeof(since2), i->condition_timestamp);

                if (s1)
                        printf("\t          start condition failed at %s; %s\n", s2, s1);
                else if (s2)
                        printf("\t          start condition failed at %s\n", s2);
        }

        if (i->sysfs_path)
                printf("\t  Device: %s\n", i->sysfs_path);
        if (i->where)
                printf("\t   Where: %s\n", i->where);
        if (i->what)
                printf("\t    What: %s\n", i->what);

        if (!strv_isempty(i->documentation)) {
                char **t;
                bool first = true;

                STRV_FOREACH(t, i->documentation) {
                        if (first) {
                                printf("\t    Docs: %s\n", *t);
                                first = false;
                        } else
                                printf("\t          %s\n", *t);
                }
        }

        if (i->accept)
                printf("\tAccepted: %u; Connected: %u\n", i->n_accepted, i->n_connections);

        LIST_FOREACH(exec, p, i->exec) {
                char *t;
                bool good;

                /* Only show exited processes here */
                if (p->code == 0)
                        continue;

                t = strv_join(p->argv, " ");
                printf("\t Process: %u %s=%s ", p->pid, p->name, strna(t));
                free(t);

                good = is_clean_exit_lsb(p->code, p->status);
                if (!good) {
                        on = ansi_highlight_red(true);
                        off = ansi_highlight_red(false);
                } else
                        on = off = "";

                printf("%s(code=%s, ", on, sigchld_code_to_string(p->code));

                if (p->code == CLD_EXITED) {
                        const char *c;

                        printf("status=%i", p->status);

                        c = exit_status_to_string(p->status, EXIT_STATUS_SYSTEMD);
                        if (c)
                                printf("/%s", c);

                } else
                        printf("signal=%s", signal_to_string(p->status));

                printf(")%s\n", off);

                if (i->main_pid == p->pid &&
                    i->start_timestamp == p->start_timestamp &&
                    i->exit_timestamp == p->start_timestamp)
                        /* Let's not show this twice */
                        i->main_pid = 0;

                if (p->pid == i->control_pid)
                        i->control_pid = 0;
        }

        if (i->main_pid > 0 || i->control_pid > 0) {
                printf("\t");

                if (i->main_pid > 0) {
                        printf("Main PID: %u", (unsigned) i->main_pid);

                        if (i->running) {
                                char *t = NULL;
                                get_process_comm(i->main_pid, &t);
                                if (t) {
                                        printf(" (%s)", t);
                                        free(t);
                                }
                        } else if (i->exit_code > 0) {
                                printf(" (code=%s, ", sigchld_code_to_string(i->exit_code));

                                if (i->exit_code == CLD_EXITED) {
                                        const char *c;

                                        printf("status=%i", i->exit_status);

                                        c = exit_status_to_string(i->exit_status, EXIT_STATUS_SYSTEMD);
                                        if (c)
                                                printf("/%s", c);

                                } else
                                        printf("signal=%s", signal_to_string(i->exit_status));
                                printf(")");
                        }
                }

                if (i->main_pid > 0 && i->control_pid > 0)
                        printf(";");

                if (i->control_pid > 0) {
                        char *t = NULL;

                        printf(" Control: %u", (unsigned) i->control_pid);

                        get_process_comm(i->control_pid, &t);
                        if (t) {
                                printf(" (%s)", t);
                                free(t);
                        }
                }

                printf("\n");
        }

        if (i->status_text)
                printf("\t  Status: \"%s\"\n", i->status_text);

        if (i->default_control_group) {
                unsigned c;

                printf("\t  CGroup: %s\n", i->default_control_group);

                if (arg_transport != TRANSPORT_SSH) {
                        unsigned k = 0;
                        pid_t extra[2];

                        c = columns();
                        if (c > 18)
                                c -= 18;
                        else
                                c = 0;

                        if (i->main_pid > 0)
                                extra[k++] = i->main_pid;

                        if (i->control_pid > 0)
                                extra[k++] = i->control_pid;

                        show_cgroup_and_extra_by_spec(i->default_control_group, "\t\t  ", c, false, arg_all, extra, k);
                }
        }

        if (i->id && arg_transport != TRANSPORT_SSH) {
                printf("\n");
                show_journal_by_unit(i->id, arg_output, 0, i->inactive_exit_timestamp_monotonic, arg_lines, arg_all, arg_follow);
        }

        if (i->need_daemon_reload)
                printf("\n%sWarning:%s Unit file changed on disk, 'systemctl %s daemon-reload' recommended.\n",
                       ansi_highlight_red(true),
                       ansi_highlight_red(false),
                       arg_scope == UNIT_FILE_SYSTEM ? "--system" : "--user");
}

static void show_unit_help(UnitStatusInfo *i) {
        char **p;

        assert(i);

        if (!i->documentation) {
                log_info("Documentation for %s not known.", i->id);
                return;
        }

        STRV_FOREACH(p, i->documentation) {

                if (startswith(*p, "man:")) {
                        size_t k;
                        char *e = NULL;
                        char *page = NULL, *section = NULL;
                        const char *args[4] = { "man", NULL, NULL, NULL };
                        pid_t pid;

                        k = strlen(*p);

                        if ((*p)[k-1] == ')')
                                e = strrchr(*p, '(');

                        if (e) {
                                page = strndup((*p) + 4, e - *p - 4);
                                if (!page) {
                                        log_error("Out of memory.");
                                        return;
                                }

                                section = strndup(e + 1, *p + k - e - 2);
                                if (!section) {
                                        free(page);
                                        log_error("Out of memory");
                                        return;
                                }

                                args[1] = section;
                                args[2] = page;
                        } else
                                args[1] = *p + 4;

                        pid = fork();
                        if (pid < 0) {
                                log_error("Failed to fork: %m");
                                free(page);
                                free(section);
                                continue;
                        }

                        if (pid == 0) {
                                /* Child */
                                execvp(args[0], (char**) args);
                                log_error("Failed to execute man: %m");
                                _exit(EXIT_FAILURE);
                        }

                        free(page);
                        free(section);

                        wait_for_terminate(pid, NULL);
                } else
                        log_info("Can't show %s.", *p);
        }
}

static int status_property(const char *name, DBusMessageIter *iter, UnitStatusInfo *i) {

        assert(name);
        assert(iter);
        assert(i);

        switch (dbus_message_iter_get_arg_type(iter)) {

        case DBUS_TYPE_STRING: {
                const char *s;

                dbus_message_iter_get_basic(iter, &s);

                if (!isempty(s)) {
                        if (streq(name, "Id"))
                                i->id = s;
                        else if (streq(name, "LoadState"))
                                i->load_state = s;
                        else if (streq(name, "ActiveState"))
                                i->active_state = s;
                        else if (streq(name, "SubState"))
                                i->sub_state = s;
                        else if (streq(name, "Description"))
                                i->description = s;
                        else if (streq(name, "FragmentPath"))
                                i->fragment_path = s;
                        else if (streq(name, "SourcePath"))
                                i->source_path = s;
                        else if (streq(name, "DefaultControlGroup"))
                                i->default_control_group = s;
                        else if (streq(name, "StatusText"))
                                i->status_text = s;
                        else if (streq(name, "SysFSPath"))
                                i->sysfs_path = s;
                        else if (streq(name, "Where"))
                                i->where = s;
                        else if (streq(name, "What"))
                                i->what = s;
                        else if (streq(name, "Following"))
                                i->following = s;
                        else if (streq(name, "UnitFileState"))
                                i->unit_file_state = s;
                        else if (streq(name, "Result"))
                                i->result = s;
                }

                break;
        }

        case DBUS_TYPE_BOOLEAN: {
                dbus_bool_t b;

                dbus_message_iter_get_basic(iter, &b);

                if (streq(name, "Accept"))
                        i->accept = b;
                else if (streq(name, "NeedDaemonReload"))
                        i->need_daemon_reload = b;
                else if (streq(name, "ConditionResult"))
                        i->condition_result = b;

                break;
        }

        case DBUS_TYPE_UINT32: {
                uint32_t u;

                dbus_message_iter_get_basic(iter, &u);

                if (streq(name, "MainPID")) {
                        if (u > 0) {
                                i->main_pid = (pid_t) u;
                                i->running = true;
                        }
                } else if (streq(name, "ControlPID"))
                        i->control_pid = (pid_t) u;
                else if (streq(name, "ExecMainPID")) {
                        if (u > 0)
                                i->main_pid = (pid_t) u;
                } else if (streq(name, "NAccepted"))
                        i->n_accepted = u;
                else if (streq(name, "NConnections"))
                        i->n_connections = u;

                break;
        }

        case DBUS_TYPE_INT32: {
                int32_t j;

                dbus_message_iter_get_basic(iter, &j);

                if (streq(name, "ExecMainCode"))
                        i->exit_code = (int) j;
                else if (streq(name, "ExecMainStatus"))
                        i->exit_status = (int) j;

                break;
        }

        case DBUS_TYPE_UINT64: {
                uint64_t u;

                dbus_message_iter_get_basic(iter, &u);

                if (streq(name, "ExecMainStartTimestamp"))
                        i->start_timestamp = (usec_t) u;
                else if (streq(name, "ExecMainExitTimestamp"))
                        i->exit_timestamp = (usec_t) u;
                else if (streq(name, "ActiveEnterTimestamp"))
                        i->active_enter_timestamp = (usec_t) u;
                else if (streq(name, "InactiveEnterTimestamp"))
                        i->inactive_enter_timestamp = (usec_t) u;
                else if (streq(name, "InactiveExitTimestamp"))
                        i->inactive_exit_timestamp = (usec_t) u;
                else if (streq(name, "InactiveExitTimestampMonotonic"))
                        i->inactive_exit_timestamp_monotonic = (usec_t) u;
                else if (streq(name, "ActiveExitTimestamp"))
                        i->active_exit_timestamp = (usec_t) u;
                else if (streq(name, "ConditionTimestamp"))
                        i->condition_timestamp = (usec_t) u;

                break;
        }

        case DBUS_TYPE_ARRAY: {

                if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT &&
                    startswith(name, "Exec")) {
                        DBusMessageIter sub;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                ExecStatusInfo *info;
                                int r;

                                if (!(info = new0(ExecStatusInfo, 1)))
                                        return -ENOMEM;

                                if (!(info->name = strdup(name))) {
                                        free(info);
                                        return -ENOMEM;
                                }

                                if ((r = exec_status_info_deserialize(&sub, info)) < 0) {
                                        free(info);
                                        return r;
                                }

                                LIST_PREPEND(ExecStatusInfo, exec, i->exec, info);

                                dbus_message_iter_next(&sub);
                        }
                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRING &&
                           streq(name, "Documentation")) {

                        DBusMessageIter sub;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING) {
                                const char *s;
                                char **l;

                                dbus_message_iter_get_basic(&sub, &s);

                                l = strv_append(i->documentation, s);
                                if (!l)
                                        return -ENOMEM;

                                strv_free(i->documentation);
                                i->documentation = l;

                                dbus_message_iter_next(&sub);
                        }
                }

                break;
        }

        case DBUS_TYPE_STRUCT: {

                if (streq(name, "LoadError")) {
                        DBusMessageIter sub;
                        const char *n, *message;
                        int r;

                        dbus_message_iter_recurse(iter, &sub);

                        r = bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &n, true);
                        if (r < 0)
                                return r;

                        r = bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &message, false);
                        if (r < 0)
                                return r;

                        if (!isempty(message))
                                i->load_error = message;
                }

                break;
        }
        }

        return 0;
}

static int print_property(const char *name, DBusMessageIter *iter) {
        assert(name);
        assert(iter);

        /* This is a low-level property printer, see
         * print_status_info() for the nicer output */

        if (arg_property && !strv_find(arg_property, name))
                return 0;

        switch (dbus_message_iter_get_arg_type(iter)) {

        case DBUS_TYPE_STRUCT: {
                DBusMessageIter sub;
                dbus_message_iter_recurse(iter, &sub);

                if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_UINT32 && streq(name, "Job")) {
                        uint32_t u;

                        dbus_message_iter_get_basic(&sub, &u);

                        if (u)
                                printf("%s=%u\n", name, (unsigned) u);
                        else if (arg_all)
                                printf("%s=\n", name);

                        return 0;
                } else if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING && streq(name, "Unit")) {
                        const char *s;

                        dbus_message_iter_get_basic(&sub, &s);

                        if (arg_all || s[0])
                                printf("%s=%s\n", name, s);

                        return 0;
                } else if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING && streq(name, "LoadError")) {
                        const char *a = NULL, *b = NULL;

                        if (bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &a, true) >= 0)
                                bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &b, false);

                        if (arg_all || !isempty(a) || !isempty(b))
                                printf("%s=%s \"%s\"\n", name, strempty(a), strempty(b));

                        return 0;
                }

                break;
        }

        case DBUS_TYPE_ARRAY:

                if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "EnvironmentFiles")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *path;
                                dbus_bool_t ignore;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_BOOLEAN, &ignore, false) >= 0)
                                        printf("EnvironmentFile=%s (ignore_errors=%s)\n", path, yes_no(ignore));

                                dbus_message_iter_next(&sub);
                        }

                        return 0;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "Paths")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *type, *path;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &type, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, false) >= 0)
                                        printf("%s=%s\n", type, path);

                                dbus_message_iter_next(&sub);
                        }

                        return 0;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "Timers")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *base;
                                uint64_t value, next_elapse;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &base, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &value, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_UINT64, &next_elapse, false) >= 0) {
                                        char timespan1[FORMAT_TIMESPAN_MAX], timespan2[FORMAT_TIMESPAN_MAX];

                                        printf("%s={ value=%s ; next_elapse=%s }\n",
                                               base,
                                               format_timespan(timespan1, sizeof(timespan1), value),
                                               format_timespan(timespan2, sizeof(timespan2), next_elapse));
                                }

                                dbus_message_iter_next(&sub);
                        }

                        return 0;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && streq(name, "ControlGroupAttributes")) {
                        DBusMessageIter sub, sub2;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                const char *controller, *attr, *value;

                                dbus_message_iter_recurse(&sub, &sub2);

                                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &controller, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &attr, true) >= 0 &&
                                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &value, false) >= 0) {

                                        printf("ControlGroupAttribute={ controller=%s ; attribute=%s ; value=\"%s\" }\n",
                                               controller,
                                               attr,
                                               value);
                                }

                                dbus_message_iter_next(&sub);
                        }

                        return 0;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRUCT && startswith(name, "Exec")) {
                        DBusMessageIter sub;

                        dbus_message_iter_recurse(iter, &sub);
                        while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT) {
                                ExecStatusInfo info;

                                zero(info);
                                if (exec_status_info_deserialize(&sub, &info) >= 0) {
                                        char timestamp1[FORMAT_TIMESTAMP_MAX], timestamp2[FORMAT_TIMESTAMP_MAX];
                                        char *t;

                                        t = strv_join(info.argv, " ");

                                        printf("%s={ path=%s ; argv[]=%s ; ignore_errors=%s ; start_time=[%s] ; stop_time=[%s] ; pid=%u ; code=%s ; status=%i%s%s }\n",
                                               name,
                                               strna(info.path),
                                               strna(t),
                                               yes_no(info.ignore),
                                               strna(format_timestamp(timestamp1, sizeof(timestamp1), info.start_timestamp)),
                                               strna(format_timestamp(timestamp2, sizeof(timestamp2), info.exit_timestamp)),
                                               (unsigned) info. pid,
                                               sigchld_code_to_string(info.code),
                                               info.status,
                                               info.code == CLD_EXITED ? "" : "/",
                                               strempty(info.code == CLD_EXITED ? NULL : signal_to_string(info.status)));

                                        free(t);
                                }

                                free(info.path);
                                strv_free(info.argv);

                                dbus_message_iter_next(&sub);
                        }

                        return 0;
                }

                break;
        }

        if (generic_print_property(name, iter, arg_all) > 0)
                return 0;

        if (arg_all)
                printf("%s=[unprintable]\n", name);

        return 0;
}

static int show_one(const char *verb, DBusConnection *bus, const char *path, bool show_properties, bool *new_line) {
        DBusMessage *m = NULL, *reply = NULL;
        const char *interface = "";
        int r;
        DBusError error;
        DBusMessageIter iter, sub, sub2, sub3;
        UnitStatusInfo info;
        ExecStatusInfo *p;

        assert(bus);
        assert(path);
        assert(new_line);

        zero(info);
        dbus_error_init(&error);

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              path,
                              "org.freedesktop.DBus.Properties",
                              "GetAll"))) {
                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &interface,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_DICT_ENTRY)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (*new_line)
                printf("\n");

        *new_line = true;

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *name;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_DICT_ENTRY) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &name, true) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                if (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_VARIANT)  {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub2, &sub3);

                if (show_properties)
                        r = print_property(name, &sub3);
                else
                        r = status_property(name, &sub3, &info);

                if (r < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_next(&sub);
        }

        r = 0;

        if (!show_properties) {
                if (streq(verb, "help"))
                        show_unit_help(&info);
                else
                        print_status_info(&info);
        }

        strv_free(info.documentation);

        if (!streq_ptr(info.active_state, "active") &&
            !streq_ptr(info.active_state, "reloading") &&
            streq(verb, "status"))
                /* According to LSB: "program not running" */
                r = 3;

        while ((p = info.exec)) {
                LIST_REMOVE(ExecStatusInfo, exec, info.exec, p);
                exec_status_info_free(p);
        }

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int show_one_by_pid(const char *verb, DBusConnection *bus, uint32_t pid, bool *new_line) {
        DBusMessage *m = NULL, *reply = NULL;
        const char *path = NULL;
        DBusError error;
        int r;

        dbus_error_init(&error);

        m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "GetUnitByPID");
        if (!m) {
                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_UINT32, &pid,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_get_args(reply, &error,
                                   DBUS_TYPE_OBJECT_PATH, &path,
                                   DBUS_TYPE_INVALID)) {
                log_error("Failed to parse reply: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        r = show_one(verb, bus, path, false, new_line);

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int show(DBusConnection *bus, char **args) {
        int r, ret = 0;
        bool show_properties, new_line = false;
        char **name;

        assert(bus);
        assert(args);

        show_properties = streq(args[0], "show");

        if (show_properties)
                pager_open_if_enabled();

        if (show_properties && strv_length(args) <= 1) {
                /* If not argument is specified inspect the manager
                 * itself */

                return show_one(args[0], bus, "/org/freedesktop/systemd1", show_properties, &new_line);
        }

        STRV_FOREACH(name, args+1) {
                uint32_t id;

                if (safe_atou32(*name, &id) < 0) {

                        /* Interpret as unit name */

                        char *e, *p;
                        e = bus_path_escape(*name);
                        if (!e)
                                return -ENOMEM;
                        p = strappend("/org/freedesktop/systemd1/unit/", e);
                        free(e);
                        if (!p)
                                return -ENOMEM;

                        r = show_one(args[0], bus, p, show_properties, &new_line);
                        free(p);

                        if (r != 0)
                                ret = r;

                } else if (show_properties) {

                        /* Interpret as job id */

                        char *p;
                        if (asprintf(&p, "/org/freedesktop/systemd1/job/%u", id) < 0)
                                return -ENOMEM;

                        r = show_one(args[0], bus, p, show_properties, &new_line);
                        free(p);

                        if (r != 0)
                                ret = r;

                } else {

                        /* Interpret as PID */

                        r = show_one_by_pid(args[0], bus, id, &new_line);
                        if (r != 0)
                                ret = r;
                }
        }

        return ret;
}

static int dump(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        const char *text;

        dbus_error_init(&error);

        pager_open_if_enabled();

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "Dump"))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_get_args(reply, &error,
                                   DBUS_TYPE_STRING, &text,
                                   DBUS_TYPE_INVALID)) {
                log_error("Failed to parse reply: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        fputs(text, stdout);

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int snapshot(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        const char *name = "", *path, *id;
        dbus_bool_t cleanup = FALSE;
        DBusMessageIter iter, sub;
        const char
                *interface = "org.freedesktop.systemd1.Unit",
                *property = "Id";

        dbus_error_init(&error);

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "CreateSnapshot"))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (strv_length(args) > 1)
                name = args[1];

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &name,
                                      DBUS_TYPE_BOOLEAN, &cleanup,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_get_args(reply, &error,
                                   DBUS_TYPE_OBJECT_PATH, &path,
                                   DBUS_TYPE_INVALID)) {
                log_error("Failed to parse reply: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        dbus_message_unref(m);
        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              path,
                              "org.freedesktop.DBus.Properties",
                              "Get"))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &interface,
                                      DBUS_TYPE_STRING, &property,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        dbus_message_unref(reply);
        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_get_basic(&sub, &id);

        if (!arg_quiet)
                puts(id);
        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int delete_snapshot(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL, *reply = NULL;
        int r;
        DBusError error;
        char **name;

        assert(bus);
        assert(args);

        dbus_error_init(&error);

        STRV_FOREACH(name, args+1) {
                const char *path = NULL;

                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager",
                                      "GetUnit"))) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, name,
                                              DBUS_TYPE_INVALID)) {
                        log_error("Could not append arguments to message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                        log_error("Failed to issue method call: %s", bus_error_message(&error));
                        r = -EIO;
                        goto finish;
                }

                if (!dbus_message_get_args(reply, &error,
                                           DBUS_TYPE_OBJECT_PATH, &path,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse reply: %s", bus_error_message(&error));
                        r = -EIO;
                        goto finish;
                }

                dbus_message_unref(m);
                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      path,
                                      "org.freedesktop.systemd1.Snapshot",
                                      "Remove"))) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                dbus_message_unref(reply);
                if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                        log_error("Failed to issue method call: %s", bus_error_message(&error));
                        r = -EIO;
                        goto finish;
                }

                dbus_message_unref(m);
                dbus_message_unref(reply);
                m = reply = NULL;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int daemon_reload(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        const char *method;

        dbus_error_init(&error);

        if (arg_action == ACTION_RELOAD)
                method = "Reload";
        else if (arg_action == ACTION_REEXEC)
                method = "Reexecute";
        else {
                assert(arg_action == ACTION_SYSTEMCTL);

                method =
                        streq(args[0], "clear-jobs")    ||
                        streq(args[0], "cancel")        ? "ClearJobs" :
                        streq(args[0], "daemon-reexec") ? "Reexecute" :
                        streq(args[0], "reset-failed")  ? "ResetFailed" :
                        streq(args[0], "halt")          ? "Halt" :
                        streq(args[0], "poweroff")      ? "PowerOff" :
                        streq(args[0], "reboot")        ? "Reboot" :
                        streq(args[0], "kexec")         ? "KExec" :
                        streq(args[0], "exit")          ? "Exit" :
                                    /* "daemon-reload" */ "Reload";
        }

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              method))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {

                if (arg_action != ACTION_SYSTEMCTL && error_is_no_service(&error)) {
                        /* There's always a fallback possible for
                         * legacy actions. */
                        r = -EADDRNOTAVAIL;
                        goto finish;
                }

                if (streq(method, "Reexecute") && dbus_error_has_name(&error, DBUS_ERROR_NO_REPLY)) {
                        /* On reexecution, we expect a disconnect, not
                         * a reply */
                        r = 0;
                        goto finish;
                }

                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int reset_failed(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL;
        int r;
        DBusError error;
        char **name;

        assert(bus);
        dbus_error_init(&error);

        if (strv_length(args) <= 1)
                return daemon_reload(bus, args);

        STRV_FOREACH(name, args+1) {
                DBusMessage *reply;

                if (!(m = dbus_message_new_method_call(
                                      "org.freedesktop.systemd1",
                                      "/org/freedesktop/systemd1",
                                      "org.freedesktop.systemd1.Manager",
                                      "ResetFailedUnit"))) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, name,
                                              DBUS_TYPE_INVALID)) {
                        log_error("Could not append arguments to message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                        log_error("Failed to issue method call: %s", bus_error_message(&error));
                        r = -EIO;
                        goto finish;
                }

                dbus_message_unref(m);
                dbus_message_unref(reply);
                m = reply = NULL;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        dbus_error_free(&error);

        return r;
}

static int show_enviroment(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        DBusMessageIter iter, sub, sub2;
        int r;
        const char
                *interface = "org.freedesktop.systemd1.Manager",
                *property = "Environment";

        dbus_error_init(&error);

        pager_open_if_enabled();

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.DBus.Properties",
                              "Get"))) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &interface,
                                      DBUS_TYPE_STRING, &property,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&sub) != DBUS_TYPE_STRING)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&sub, &sub2);

        while (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_INVALID) {
                const char *text;

                if (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_STRING) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_get_basic(&sub2, &text);
                printf("%s\n", text);

                dbus_message_iter_next(&sub2);
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int switch_root(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL, *reply = NULL;
        unsigned l;
        const char *root, *init;
        DBusError error;
        int r;

        dbus_error_init(&error);

        l = strv_length(args);
        if (l < 2 || l > 3) {
                log_error("Wrong number of arguments.");
                return -EINVAL;
        }

        root = args[1];
        init = l >= 3 ? args[2] : "";

        m = dbus_message_new_method_call(
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "SwitchRoot");
        if (!m) {
                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        if (!dbus_message_append_args(
                            m,
                            DBUS_TYPE_STRING, &root,
                            DBUS_TYPE_STRING, &init,
                            DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int set_environment(DBusConnection *bus, char **args) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        const char *method;
        DBusMessageIter iter, sub;
        char **name;

        dbus_error_init(&error);

        method = streq(args[0], "set-environment")
                ? "SetEnvironment"
                : "UnsetEnvironment";

        if (!(m = dbus_message_new_method_call(
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              method))) {

                log_error("Could not allocate message.");
                return -ENOMEM;
        }

        dbus_message_iter_init_append(m, &iter);

        if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &sub)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        STRV_FOREACH(name, args+1)
                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, name)) {
                        log_error("Could not append arguments to message.");
                        r = -ENOMEM;
                        goto finish;
                }

        if (!dbus_message_iter_close_container(&iter, &sub)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return r;
}

static int enable_sysv_units(char **args) {
        int r = 0;

#if defined (HAVE_SYSV_COMPAT) && (defined(TARGET_FEDORA) || defined(TARGET_MANDRIVA) || defined(TARGET_SUSE) || defined(TARGET_MEEGO) || defined(TARGET_ALTLINUX) || defined(TARGET_MAGEIA))
        const char *verb = args[0];
        unsigned f = 1, t = 1;
        LookupPaths paths;

        if (arg_scope != UNIT_FILE_SYSTEM)
                return 0;

        if (!streq(verb, "enable") &&
            !streq(verb, "disable") &&
            !streq(verb, "is-enabled"))
                return 0;

        /* Processes all SysV units, and reshuffles the array so that
         * afterwards only the native units remain */

        zero(paths);
        r = lookup_paths_init(&paths, MANAGER_SYSTEM, false, NULL, NULL, NULL);
        if (r < 0)
                return r;

        r = 0;
        for (f = 1; args[f]; f++) {
                const char *name;
                char *p;
                bool found_native = false, found_sysv;
                unsigned c = 1;
                const char *argv[6] = { "/sbin/chkconfig", NULL, NULL, NULL, NULL };
                char **k, *l, *q = NULL;
                int j;
                pid_t pid;
                siginfo_t status;

                name = args[f];

                if (!endswith(name, ".service"))
                        continue;

                if (path_is_absolute(name))
                        continue;

                STRV_FOREACH(k, paths.unit_path) {
                        p = NULL;

                        if (!isempty(arg_root))
                                asprintf(&p, "%s/%s/%s", arg_root, *k, name);
                        else
                                asprintf(&p, "%s/%s", *k, name);

                        if (!p) {
                                log_error("No memory");
                                r = -ENOMEM;
                                goto finish;
                        }

                        found_native = access(p, F_OK) >= 0;
                        free(p);

                        if (found_native)
                                break;
                }

                if (found_native)
                        continue;

                p = NULL;
                if (!isempty(arg_root))
                        asprintf(&p, "%s/" SYSTEM_SYSVINIT_PATH "/%s", arg_root, name);
                else
                        asprintf(&p, SYSTEM_SYSVINIT_PATH "/%s", name);
                if (!p) {
                        log_error("No memory");
                        r = -ENOMEM;
                        goto finish;
                }

                p[strlen(p) - sizeof(".service") + 1] = 0;
                found_sysv = access(p, F_OK) >= 0;

                if (!found_sysv) {
                        free(p);
                        continue;
                }

                /* Mark this entry, so that we don't try enabling it as native unit */
                args[f] = (char*) "";

                log_info("%s is not a native service, redirecting to /sbin/chkconfig.", name);

                if (!isempty(arg_root))
                        argv[c++] = q = strappend("--root=", arg_root);

                argv[c++] = path_get_file_name(p);
                argv[c++] =
                        streq(verb, "enable") ? "on" :
                        streq(verb, "disable") ? "off" : "--level=5";
                argv[c] = NULL;

                l = strv_join((char**)argv, " ");
                if (!l) {
                        log_error("No memory.");
                        free(q);
                        free(p);
                        r = -ENOMEM;
                        goto finish;
                }

                log_info("Executing %s", l);
                free(l);

                pid = fork();
                if (pid < 0) {
                        log_error("Failed to fork: %m");
                        free(p);
                        free(q);
                        r = -errno;
                        goto finish;
                } else if (pid == 0) {
                        /* Child */

                        execv(argv[0], (char**) argv);
                        _exit(EXIT_FAILURE);
                }

                free(p);
                free(q);

                j = wait_for_terminate(pid, &status);
                if (j < 0) {
                        log_error("Failed to wait for child: %s", strerror(-r));
                        r = j;
                        goto finish;
                }

                if (status.si_code == CLD_EXITED) {
                        if (streq(verb, "is-enabled")) {
                                if (status.si_status == 0) {
                                        if (!arg_quiet)
                                                puts("enabled");
                                        r = 1;
                                } else {
                                        if (!arg_quiet)
                                                puts("disabled");
                                }

                        } else if (status.si_status != 0) {
                                r = -EINVAL;
                                goto finish;
                        }
                } else {
                        r = -EPROTO;
                        goto finish;
                }
        }

finish:
        lookup_paths_free(&paths);

        /* Drop all SysV units */
        for (f = 1, t = 1; args[f]; f++) {

                if (isempty(args[f]))
                        continue;

                args[t++] = args[f];
        }

        args[t] = NULL;

#endif
        return r;
}

static int enable_unit(DBusConnection *bus, char **args) {
        const char *verb = args[0];
        UnitFileChange *changes = NULL;
        unsigned n_changes = 0, i;
        int carries_install_info = -1;
        DBusMessage *m = NULL, *reply = NULL;
        int r;
        DBusError error;

        r = enable_sysv_units(args);
        if (r < 0)
                return r;

        if (!args[1])
                return 0;

        dbus_error_init(&error);

        if (!bus || avoid_bus()) {
                if (streq(verb, "enable")) {
                        r = unit_file_enable(arg_scope, arg_runtime, arg_root, args+1, arg_force, &changes, &n_changes);
                        carries_install_info = r;
                } else if (streq(verb, "disable"))
                        r = unit_file_disable(arg_scope, arg_runtime, arg_root, args+1, &changes, &n_changes);
                else if (streq(verb, "reenable")) {
                        r = unit_file_reenable(arg_scope, arg_runtime, arg_root, args+1, arg_force, &changes, &n_changes);
                        carries_install_info = r;
                } else if (streq(verb, "link"))
                        r = unit_file_link(arg_scope, arg_runtime, arg_root, args+1, arg_force, &changes, &n_changes);
                else if (streq(verb, "preset")) {
                        r = unit_file_preset(arg_scope, arg_runtime, arg_root, args+1, arg_force, &changes, &n_changes);
                        carries_install_info = r;
                } else if (streq(verb, "mask"))
                        r = unit_file_mask(arg_scope, arg_runtime, arg_root, args+1, arg_force, &changes, &n_changes);
                else if (streq(verb, "unmask"))
                        r = unit_file_unmask(arg_scope, arg_runtime, arg_root, args+1, &changes, &n_changes);
                else
                        assert_not_reached("Unknown verb");

                if (r < 0) {
                        log_error("Operation failed: %s", strerror(-r));
                        goto finish;
                }

                if (!arg_quiet) {
                        for (i = 0; i < n_changes; i++) {
                                if (changes[i].type == UNIT_FILE_SYMLINK)
                                        log_info("ln -s '%s' '%s'", changes[i].source, changes[i].path);
                                else
                                        log_info("rm '%s'", changes[i].path);
                        }
                }

        } else {
                const char *method;
                bool send_force = true, expect_carries_install_info = false;
                dbus_bool_t a, b;
                DBusMessageIter iter, sub, sub2;

                if (streq(verb, "enable")) {
                        method = "EnableUnitFiles";
                        expect_carries_install_info = true;
                } else if (streq(verb, "disable")) {
                        method = "DisableUnitFiles";
                        send_force = false;
                } else if (streq(verb, "reenable")) {
                        method = "ReenableUnitFiles";
                        expect_carries_install_info = true;
                } else if (streq(verb, "link"))
                        method = "LinkUnitFiles";
                else if (streq(verb, "preset")) {
                        method = "PresetUnitFiles";
                        expect_carries_install_info = true;
                } else if (streq(verb, "mask"))
                        method = "MaskUnitFiles";
                else if (streq(verb, "unmask")) {
                        method = "UnmaskUnitFiles";
                        send_force = false;
                } else
                        assert_not_reached("Unknown verb");

                m = dbus_message_new_method_call(
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                method);
                if (!m) {
                        log_error("Out of memory");
                        r = -ENOMEM;
                        goto finish;
                }

                dbus_message_iter_init_append(m, &iter);

                r = bus_append_strv_iter(&iter, args+1);
                if (r < 0) {
                        log_error("Failed to append unit files.");
                        goto finish;
                }

                a = arg_runtime;
                if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &a)) {
                        log_error("Failed to append runtime boolean.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (send_force) {
                        b = arg_force;

                        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &b)) {
                                log_error("Failed to append force boolean.");
                                r = -ENOMEM;
                                goto finish;
                        }
                }

                reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
                if (!reply) {
                        log_error("Failed to issue method call: %s", bus_error_message(&error));
                        r = -EIO;
                        goto finish;
                }

                if (!dbus_message_iter_init(reply, &iter)) {
                        log_error("Failed to initialize iterator.");
                        goto finish;
                }

                if (expect_carries_install_info) {
                        r = bus_iter_get_basic_and_next(&iter, DBUS_TYPE_BOOLEAN, &b, true);
                        if (r < 0) {
                                log_error("Failed to parse reply.");
                                goto finish;
                        }

                        carries_install_info = b;
                }

                if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
                    dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&iter, &sub);
                while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                        const char *type, *path, *source;

                        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                                log_error("Failed to parse reply.");
                                r = -EIO;
                                goto finish;
                        }

                        dbus_message_iter_recurse(&sub, &sub2);

                        if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &type, true) < 0 ||
                            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &path, true) < 0 ||
                            bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &source, false) < 0) {
                                log_error("Failed to parse reply.");
                                r = -EIO;
                                goto finish;
                        }

                        if (!arg_quiet) {
                                if (streq(type, "symlink"))
                                        log_info("ln -s '%s' '%s'", source, path);
                                else
                                        log_info("rm '%s'", path);
                        }

                        dbus_message_iter_next(&sub);
                }

                /* Try to reload if enabeld */
                if (!arg_no_reload)
                        r = daemon_reload(bus, args);
        }

        if (carries_install_info == 0)
                log_warning("Warning: unit files do not carry install information. No operation executed.");

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        unit_file_changes_free(changes, n_changes);

        dbus_error_free(&error);
        return r;
}

static int unit_is_enabled(DBusConnection *bus, char **args) {
        DBusError error;
        int r;
        DBusMessage *m = NULL, *reply = NULL;
        bool enabled;
        char **name;

        dbus_error_init(&error);

        r = enable_sysv_units(args);
        if (r < 0)
                return r;

        enabled = r > 0;

        if (!bus || avoid_bus()) {

                STRV_FOREACH(name, args+1) {
                        UnitFileState state;

                        state = unit_file_get_state(arg_scope, arg_root, *name);
                        if (state < 0) {
                                r = state;
                                goto finish;
                        }

                        if (state == UNIT_FILE_ENABLED ||
                            state == UNIT_FILE_ENABLED_RUNTIME ||
                            state == UNIT_FILE_STATIC)
                                enabled = true;

                        if (!arg_quiet)
                                puts(unit_file_state_to_string(state));
                }

        } else {
                STRV_FOREACH(name, args+1) {
                        const char *s;

                        m = dbus_message_new_method_call(
                                        "org.freedesktop.systemd1",
                                        "/org/freedesktop/systemd1",
                                        "org.freedesktop.systemd1.Manager",
                                        "GetUnitFileState");
                        if (!m) {
                                log_error("Out of memory");
                                r = -ENOMEM;
                                goto finish;
                        }

                        if (!dbus_message_append_args(m,
                                                      DBUS_TYPE_STRING, name,
                                                      DBUS_TYPE_INVALID)) {
                                log_error("Could not append arguments to message.");
                                r = -ENOMEM;
                                goto finish;
                        }

                        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
                        if (!reply) {
                                log_error("Failed to issue method call: %s", bus_error_message(&error));
                                r = -EIO;
                                goto finish;
                        }

                        if (!dbus_message_get_args(reply, &error,
                                                   DBUS_TYPE_STRING, &s,
                                                   DBUS_TYPE_INVALID)) {
                                log_error("Failed to parse reply: %s", bus_error_message(&error));
                                r = -EIO;
                                goto finish;
                        }

                        dbus_message_unref(m);
                        dbus_message_unref(reply);
                        m = reply = NULL;

                        if (streq(s, "enabled") ||
                            streq(s, "enabled-runtime") ||
                            streq(s, "static"))
                                enabled = true;

                        if (!arg_quiet)
                                puts(s);
                }
        }

        r = enabled ? 0 : 1;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);
        return r;
}

static int systemctl_help(void) {

        pager_open_if_enabled();

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Query or send control commands to the systemd manager.\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "  -t --type=TYPE      List only units of a particular type\n"
               "  -p --property=NAME  Show only properties by this name\n"
               "  -a --all            Show all units/properties, including dead/empty ones\n"
               "     --failed         Show only failed units\n"
               "     --full           Don't ellipsize unit names on output\n"
               "     --fail           When queueing a new job, fail if conflicting jobs are\n"
               "                      pending\n"
               "     --ignore-dependencies\n"
               "                      When queueing a new job, ignore all its dependencies\n"
               "     --kill-who=WHO   Who to send signal to\n"
               "  -s --signal=SIGNAL  Which signal to send\n"
               "  -H --host=[USER@]HOST\n"
               "                      Show information for remote host\n"
               "  -P --privileged     Acquire privileges before execution\n"
               "  -q --quiet          Suppress output\n"
               "     --no-block       Do not wait until operation finished\n"
               "     --no-wall        Don't send wall message before halt/power-off/reboot\n"
               "     --no-reload      When enabling/disabling unit files, don't reload daemon\n"
               "                      configuration\n"
               "     --no-legend      Do not print a legend (column headers and hints)\n"
               "     --no-pager       Do not pipe output into a pager\n"
               "     --no-ask-password\n"
               "                      Do not ask for system passwords\n"
               "     --order          When generating graph for dot, show only order\n"
               "     --require        When generating graph for dot, show only requirement\n"
               "     --system         Connect to system manager\n"
               "     --user           Connect to user service manager\n"
               "     --global         Enable/disable unit files globally\n"
               "  -f --force          When enabling unit files, override existing symlinks\n"
               "                      When shutting down, execute action immediately\n"
               "     --root=PATH      Enable unit files in the specified root directory\n"
               "     --runtime        Enable unit files only temporarily until next reboot\n"
               "  -n --lines=INTEGER  Journal entries to show\n"
               "     --follow         Follow journal\n"
               "  -o --output=STRING  Change journal output mode (short, short-monotonic,\n"
               "                      verbose, export, json, cat)\n\n"
               "Unit Commands:\n"
               "  list-units                      List loaded units\n"
               "  start [NAME...]                 Start (activate) one or more units\n"
               "  stop [NAME...]                  Stop (deactivate) one or more units\n"
               "  reload [NAME...]                Reload one or more units\n"
               "  restart [NAME...]               Start or restart one or more units\n"
               "  try-restart [NAME...]           Restart one or more units if active\n"
               "  reload-or-restart [NAME...]     Reload one or more units is possible,\n"
               "                                  otherwise start or restart\n"
               "  reload-or-try-restart [NAME...] Reload one or more units is possible,\n"
               "                                  otherwise restart if active\n"
               "  isolate [NAME]                  Start one unit and stop all others\n"
               "  kill [NAME...]                  Send signal to processes of a unit\n"
               "  is-active [NAME...]             Check whether units are active\n"
               "  status [NAME...|PID...]         Show runtime status of one or more units\n"
               "  show [NAME...|JOB...]           Show properties of one or more\n"
               "                                  units/jobs or the manager\n"
               "  help [NAME...|PID...]            Show manual for one or more units\n"
               "  reset-failed [NAME...]          Reset failed state for all, one, or more\n"
               "                                  units\n"
               "  load [NAME...]                  Load one or more units\n\n"
               "Unit File Commands:\n"
               "  list-unit-files                 List installed unit files\n"
               "  enable [NAME...]                Enable one or more unit files\n"
               "  disable [NAME...]               Disable one or more unit files\n"
               "  reenable [NAME...]              Reenable one or more unit files\n"
               "  preset [NAME...]                Enable/disable one or more unit files\n"
               "                                  based on preset configuration\n"
               "  mask [NAME...]                  Mask one or more units\n"
               "  unmask [NAME...]                Unmask one or more units\n"
               "  link [PATH...]                  Link one or more units files into\n"
               "                                  the search path\n"
               "  is-enabled [NAME...]            Check whether unit files are enabled\n\n"
               "Job Commands:\n"
               "  list-jobs                       List jobs\n"
               "  cancel [JOB...]                 Cancel all, one, or more jobs\n\n"
               "Status Commands:\n"
               "  dump                            Dump server status\n"
               "  dot                             Dump dependency graph for dot(1)\n\n"
               "Snapshot Commands:\n"
               "  snapshot [NAME]                 Create a snapshot\n"
               "  delete [NAME...]                Remove one or more snapshots\n\n"
               "Environment Commands:\n"
               "  show-environment                Dump environment\n"
               "  set-environment [NAME=VALUE...] Set one or more environment variables\n"
               "  unset-environment [NAME...]     Unset one or more environment variables\n\n"
               "Manager Lifecycle Commands:\n"
               "  daemon-reload                   Reload systemd manager configuration\n"
               "  daemon-reexec                   Reexecute systemd manager\n\n"
               "System Commands:\n"
               "  default                         Enter system default mode\n"
               "  rescue                          Enter system rescue mode\n"
               "  emergency                       Enter system emergency mode\n"
               "  halt                            Shut down and halt the system\n"
               "  poweroff                        Shut down and power-off the system\n"
               "  reboot                          Shut down and reboot the system\n"
               "  kexec                           Shut down and reboot the system with kexec\n"
               "  exit                            Request user instance exit\n"
               "  switch-root [ROOT] [INIT]       Change to a different root file system\n"
               "  suspend                         Suspend the system\n"
               "  hibernate                       Hibernate the system\n",
               program_invocation_short_name);

        return 0;
}

static int halt_help(void) {

        printf("%s [OPTIONS...]\n\n"
               "%s the system.\n\n"
               "     --help      Show this help\n"
               "     --halt      Halt the machine\n"
               "  -p --poweroff  Switch off the machine\n"
               "     --reboot    Reboot the machine\n"
               "  -f --force     Force immediate halt/power-off/reboot\n"
               "  -w --wtmp-only Don't halt/power-off/reboot, just write wtmp record\n"
               "  -d --no-wtmp   Don't write wtmp record\n"
               "  -n --no-sync   Don't sync before halt/power-off/reboot\n"
               "     --no-wall   Don't send wall message before halt/power-off/reboot\n",
               program_invocation_short_name,
               arg_action == ACTION_REBOOT   ? "Reboot" :
               arg_action == ACTION_POWEROFF ? "Power off" :
                                               "Halt");

        return 0;
}

static int shutdown_help(void) {

        printf("%s [OPTIONS...] [TIME] [WALL...]\n\n"
               "Shut down the system.\n\n"
               "     --help      Show this help\n"
               "  -H --halt      Halt the machine\n"
               "  -P --poweroff  Power-off the machine\n"
               "  -r --reboot    Reboot the machine\n"
               "  -h             Equivalent to --poweroff, overridden by --halt\n"
               "  -k             Don't halt/power-off/reboot, just send warnings\n"
               "     --no-wall   Don't send wall message before halt/power-off/reboot\n"
               "  -c             Cancel a pending shutdown\n",
               program_invocation_short_name);

        return 0;
}

static int telinit_help(void) {

        printf("%s [OPTIONS...] {COMMAND}\n\n"
               "Send control commands to the init daemon.\n\n"
               "     --help      Show this help\n"
               "     --no-wall   Don't send wall message before halt/power-off/reboot\n\n"
               "Commands:\n"
               "  0              Power-off the machine\n"
               "  6              Reboot the machine\n"
               "  2, 3, 4, 5     Start runlevelX.target unit\n"
               "  1, s, S        Enter rescue mode\n"
               "  q, Q           Reload init daemon configuration\n"
               "  u, U           Reexecute init daemon\n",
               program_invocation_short_name);

        return 0;
}

static int runlevel_help(void) {

        printf("%s [OPTIONS...]\n\n"
               "Prints the previous and current runlevel of the init system.\n\n"
               "     --help      Show this help\n",
               program_invocation_short_name);

        return 0;
}

static int systemctl_parse_argv(int argc, char *argv[]) {

        enum {
                ARG_FAIL = 0x100,
                ARG_IGNORE_DEPENDENCIES,
                ARG_VERSION,
                ARG_USER,
                ARG_SYSTEM,
                ARG_GLOBAL,
                ARG_NO_BLOCK,
                ARG_NO_LEGEND,
                ARG_NO_PAGER,
                ARG_NO_WALL,
                ARG_ORDER,
                ARG_REQUIRE,
                ARG_ROOT,
                ARG_FULL,
                ARG_NO_RELOAD,
                ARG_KILL_MODE,
                ARG_KILL_WHO,
                ARG_NO_ASK_PASSWORD,
                ARG_FAILED,
                ARG_RUNTIME,
                ARG_FOLLOW,
                ARG_FORCE
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "type",      required_argument, NULL, 't'           },
                { "property",  required_argument, NULL, 'p'           },
                { "all",       no_argument,       NULL, 'a'           },
                { "failed",    no_argument,       NULL, ARG_FAILED    },
                { "full",      no_argument,       NULL, ARG_FULL      },
                { "fail",      no_argument,       NULL, ARG_FAIL      },
                { "ignore-dependencies", no_argument, NULL, ARG_IGNORE_DEPENDENCIES },
                { "user",      no_argument,       NULL, ARG_USER      },
                { "system",    no_argument,       NULL, ARG_SYSTEM    },
                { "global",    no_argument,       NULL, ARG_GLOBAL    },
                { "no-block",  no_argument,       NULL, ARG_NO_BLOCK  },
                { "no-legend", no_argument,       NULL, ARG_NO_LEGEND },
                { "no-pager",  no_argument,       NULL, ARG_NO_PAGER  },
                { "no-wall",   no_argument,       NULL, ARG_NO_WALL   },
                { "quiet",     no_argument,       NULL, 'q'           },
                { "order",     no_argument,       NULL, ARG_ORDER     },
                { "require",   no_argument,       NULL, ARG_REQUIRE   },
                { "root",      required_argument, NULL, ARG_ROOT      },
                { "force",     no_argument,       NULL, ARG_FORCE     },
                { "no-reload", no_argument,       NULL, ARG_NO_RELOAD },
                { "kill-mode", required_argument, NULL, ARG_KILL_MODE }, /* undocumented on purpose */
                { "kill-who",  required_argument, NULL, ARG_KILL_WHO  },
                { "signal",    required_argument, NULL, 's'           },
                { "no-ask-password", no_argument, NULL, ARG_NO_ASK_PASSWORD },
                { "host",      required_argument, NULL, 'H'           },
                { "privileged",no_argument,       NULL, 'P'           },
                { "runtime",   no_argument,       NULL, ARG_RUNTIME   },
                { "lines",     required_argument, NULL, 'n'           },
                { "follow",    no_argument,       NULL, ARG_FOLLOW    },
                { "output",    required_argument, NULL, 'o'           },
                { NULL,        0,                 NULL, 0             }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ht:p:aqfs:H:Pn:o:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        systemctl_help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(DISTRIBUTION);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case 't':
                        arg_type = optarg;
                        break;

                case 'p': {
                        char **l;

                        if (!(l = strv_append(arg_property, optarg)))
                                return -ENOMEM;

                        strv_free(arg_property);
                        arg_property = l;

                        /* If the user asked for a particular
                         * property, show it to him, even if it is
                         * empty. */
                        arg_all = true;
                        break;
                }

                case 'a':
                        arg_all = true;
                        break;

                case ARG_FAIL:
                        arg_job_mode = "fail";
                        break;

                case ARG_IGNORE_DEPENDENCIES:
                        arg_job_mode = "ignore-dependencies";
                        break;

                case ARG_USER:
                        arg_scope = UNIT_FILE_USER;
                        break;

                case ARG_SYSTEM:
                        arg_scope = UNIT_FILE_SYSTEM;
                        break;

                case ARG_GLOBAL:
                        arg_scope = UNIT_FILE_GLOBAL;
                        break;

                case ARG_NO_BLOCK:
                        arg_no_block = true;
                        break;

                case ARG_NO_LEGEND:
                        arg_no_legend = true;
                        break;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case ARG_ORDER:
                        arg_dot = DOT_ORDER;
                        break;

                case ARG_REQUIRE:
                        arg_dot = DOT_REQUIRE;
                        break;

                case ARG_ROOT:
                        arg_root = optarg;
                        break;

                case ARG_FULL:
                        arg_full = true;
                        break;

                case ARG_FAILED:
                        arg_failed = true;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_FORCE:
                        arg_force ++;
                        break;

                case ARG_FOLLOW:
                        arg_follow = true;
                        break;

                case 'f':
                        /* -f is short for both --follow and --force! */
                        arg_force ++;
                        arg_follow = true;
                        break;

                case ARG_NO_RELOAD:
                        arg_no_reload = true;
                        break;

                case ARG_KILL_WHO:
                        arg_kill_who = optarg;
                        break;

                case ARG_KILL_MODE:
                        arg_kill_mode = optarg;
                        break;

                case 's':
                        if ((arg_signal = signal_from_string_try_harder(optarg)) < 0) {
                                log_error("Failed to parse signal string %s.", optarg);
                                return -EINVAL;
                        }
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case 'P':
                        arg_transport = TRANSPORT_POLKIT;
                        break;

                case 'H':
                        arg_transport = TRANSPORT_SSH;
                        arg_host = optarg;
                        break;

                case ARG_RUNTIME:
                        arg_runtime = true;
                        break;

                case 'n':
                        if (safe_atou(optarg, &arg_lines) < 0) {
                                log_error("Failed to parse lines '%s'", optarg);
                                return -EINVAL;
                        }
                        break;

                case 'o':
                        arg_output = output_mode_from_string(optarg);
                        if (arg_output < 0) {
                                log_error("Unknown output '%s'.", optarg);
                                return -EINVAL;
                        }
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (arg_transport != TRANSPORT_NORMAL && arg_scope != UNIT_FILE_SYSTEM) {
                log_error("Cannot access user instance remotely.");
                return -EINVAL;
        }

        return 1;
}

static int halt_parse_argv(int argc, char *argv[]) {

        enum {
                ARG_HELP = 0x100,
                ARG_HALT,
                ARG_REBOOT,
                ARG_NO_WALL
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, ARG_HELP    },
                { "halt",      no_argument,       NULL, ARG_HALT    },
                { "poweroff",  no_argument,       NULL, 'p'         },
                { "reboot",    no_argument,       NULL, ARG_REBOOT  },
                { "force",     no_argument,       NULL, 'f'         },
                { "wtmp-only", no_argument,       NULL, 'w'         },
                { "no-wtmp",   no_argument,       NULL, 'd'         },
                { "no-sync",   no_argument,       NULL, 'n'         },
                { "no-wall",   no_argument,       NULL, ARG_NO_WALL },
                { NULL,        0,                 NULL, 0           }
        };

        int c, runlevel;

        assert(argc >= 0);
        assert(argv);

        if (utmp_get_runlevel(&runlevel, NULL) >= 0)
                if (runlevel == '0' || runlevel == '6')
                        arg_force = 2;

        while ((c = getopt_long(argc, argv, "pfwdnih", options, NULL)) >= 0) {
                switch (c) {

                case ARG_HELP:
                        halt_help();
                        return 0;

                case ARG_HALT:
                        arg_action = ACTION_HALT;
                        break;

                case 'p':
                        if (arg_action != ACTION_REBOOT)
                                arg_action = ACTION_POWEROFF;
                        break;

                case ARG_REBOOT:
                        arg_action = ACTION_REBOOT;
                        break;

                case 'f':
                        arg_force = 2;
                        break;

                case 'w':
                        arg_dry = true;
                        break;

                case 'd':
                        arg_no_wtmp = true;
                        break;

                case 'n':
                        arg_no_sync = true;
                        break;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case 'i':
                case 'h':
                        /* Compatibility nops */
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind < argc) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        return 1;
}

static int parse_time_spec(const char *t, usec_t *_u) {
        assert(t);
        assert(_u);

        if (streq(t, "now"))
                *_u = 0;
        else if (!strchr(t, ':')) {
                uint64_t u;

                if (safe_atou64(t, &u) < 0)
                        return -EINVAL;

                *_u = now(CLOCK_REALTIME) + USEC_PER_MINUTE * u;
        } else {
                char *e = NULL;
                long hour, minute;
                struct tm tm;
                time_t s;
                usec_t n;

                errno = 0;
                hour = strtol(t, &e, 10);
                if (errno != 0 || *e != ':' || hour < 0 || hour > 23)
                        return -EINVAL;

                minute = strtol(e+1, &e, 10);
                if (errno != 0 || *e != 0 || minute < 0 || minute > 59)
                        return -EINVAL;

                n = now(CLOCK_REALTIME);
                s = (time_t) (n / USEC_PER_SEC);

                zero(tm);
                assert_se(localtime_r(&s, &tm));

                tm.tm_hour = (int) hour;
                tm.tm_min = (int) minute;
                tm.tm_sec = 0;

                assert_se(s = mktime(&tm));

                *_u = (usec_t) s * USEC_PER_SEC;

                while (*_u <= n)
                        *_u += USEC_PER_DAY;
        }

        return 0;
}

static int shutdown_parse_argv(int argc, char *argv[]) {

        enum {
                ARG_HELP = 0x100,
                ARG_NO_WALL
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, ARG_HELP    },
                { "halt",      no_argument,       NULL, 'H'         },
                { "poweroff",  no_argument,       NULL, 'P'         },
                { "reboot",    no_argument,       NULL, 'r'         },
                { "kexec",     no_argument,       NULL, 'K'         }, /* not documented extension */
                { "no-wall",   no_argument,       NULL, ARG_NO_WALL },
                { NULL,        0,                 NULL, 0           }
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "HPrhkt:afFc", options, NULL)) >= 0) {
                switch (c) {

                case ARG_HELP:
                        shutdown_help();
                        return 0;

                case 'H':
                        arg_action = ACTION_HALT;
                        break;

                case 'P':
                        arg_action = ACTION_POWEROFF;
                        break;

                case 'r':
                        if (kexec_loaded())
                                arg_action = ACTION_KEXEC;
                        else
                                arg_action = ACTION_REBOOT;
                        break;

                case 'K':
                        arg_action = ACTION_KEXEC;
                        break;

                case 'h':
                        if (arg_action != ACTION_HALT)
                                arg_action = ACTION_POWEROFF;
                        break;

                case 'k':
                        arg_dry = true;
                        break;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case 't':
                case 'a':
                        /* Compatibility nops */
                        break;

                case 'c':
                        arg_action = ACTION_CANCEL_SHUTDOWN;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (argc > optind) {
                r = parse_time_spec(argv[optind], &arg_when);
                if (r < 0) {
                        log_error("Failed to parse time specification: %s", argv[optind]);
                        return r;
                }
        } else
                arg_when = now(CLOCK_REALTIME) + USEC_PER_MINUTE;

        /* We skip the time argument */
        if (argc > optind + 1)
                arg_wall = argv + optind + 1;

        optind = argc;

        return 1;
}

static int telinit_parse_argv(int argc, char *argv[]) {

        enum {
                ARG_HELP = 0x100,
                ARG_NO_WALL
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, ARG_HELP    },
                { "no-wall",   no_argument,       NULL, ARG_NO_WALL },
                { NULL,        0,                 NULL, 0           }
        };

        static const struct {
                char from;
                enum action to;
        } table[] = {
                { '0', ACTION_POWEROFF },
                { '6', ACTION_REBOOT },
                { '1', ACTION_RESCUE },
                { '2', ACTION_RUNLEVEL2 },
                { '3', ACTION_RUNLEVEL3 },
                { '4', ACTION_RUNLEVEL4 },
                { '5', ACTION_RUNLEVEL5 },
                { 's', ACTION_RESCUE },
                { 'S', ACTION_RESCUE },
                { 'q', ACTION_RELOAD },
                { 'Q', ACTION_RELOAD },
                { 'u', ACTION_REEXEC },
                { 'U', ACTION_REEXEC }
        };

        unsigned i;
        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "", options, NULL)) >= 0) {
                switch (c) {

                case ARG_HELP:
                        telinit_help();
                        return 0;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind >= argc) {
                telinit_help();
                return -EINVAL;
        }

        if (optind + 1 < argc) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        if (strlen(argv[optind]) != 1) {
                log_error("Expected single character argument.");
                return -EINVAL;
        }

        for (i = 0; i < ELEMENTSOF(table); i++)
                if (table[i].from == argv[optind][0])
                        break;

        if (i >= ELEMENTSOF(table)) {
                log_error("Unknown command %s.", argv[optind]);
                return -EINVAL;
        }

        arg_action = table[i].to;

        optind ++;

        return 1;
}

static int runlevel_parse_argv(int argc, char *argv[]) {

        enum {
                ARG_HELP = 0x100,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, ARG_HELP    },
                { NULL,        0,                 NULL, 0           }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "", options, NULL)) >= 0) {
                switch (c) {

                case ARG_HELP:
                        runlevel_help();
                        return 0;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind < argc) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        return 1;
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        if (program_invocation_short_name) {

                if (strstr(program_invocation_short_name, "halt")) {
                        arg_action = ACTION_HALT;
                        return halt_parse_argv(argc, argv);
                } else if (strstr(program_invocation_short_name, "poweroff")) {
                        arg_action = ACTION_POWEROFF;
                        return halt_parse_argv(argc, argv);
                } else if (strstr(program_invocation_short_name, "reboot")) {
                        if (kexec_loaded())
                                arg_action = ACTION_KEXEC;
                        else
                                arg_action = ACTION_REBOOT;
                        return halt_parse_argv(argc, argv);
                } else if (strstr(program_invocation_short_name, "shutdown")) {
                        arg_action = ACTION_POWEROFF;
                        return shutdown_parse_argv(argc, argv);
                } else if (strstr(program_invocation_short_name, "init")) {

                        if (sd_booted() > 0) {
                                arg_action = ACTION_INVALID;
                                return telinit_parse_argv(argc, argv);
                        } else {
                                /* Hmm, so some other init system is
                                 * running, we need to forward this
                                 * request to it. For now we simply
                                 * guess that it is Upstart. */

                                execv("/lib/upstart/telinit", argv);

                                log_error("Couldn't find an alternative telinit implementation to spawn.");
                                return -EIO;
                        }

                } else if (strstr(program_invocation_short_name, "runlevel")) {
                        arg_action = ACTION_RUNLEVEL;
                        return runlevel_parse_argv(argc, argv);
                }
        }

        arg_action = ACTION_SYSTEMCTL;
        return systemctl_parse_argv(argc, argv);
}

static int action_to_runlevel(void) {

        static const char table[_ACTION_MAX] = {
                [ACTION_HALT] =      '0',
                [ACTION_POWEROFF] =  '0',
                [ACTION_REBOOT] =    '6',
                [ACTION_RUNLEVEL2] = '2',
                [ACTION_RUNLEVEL3] = '3',
                [ACTION_RUNLEVEL4] = '4',
                [ACTION_RUNLEVEL5] = '5',
                [ACTION_RESCUE] =    '1'
        };

        assert(arg_action < _ACTION_MAX);

        return table[arg_action];
}

static int talk_upstart(void) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int previous, rl, r;
        char
                env1_buf[] = "RUNLEVEL=X",
                env2_buf[] = "PREVLEVEL=X";
        char *env1 = env1_buf, *env2 = env2_buf;
        const char *emit = "runlevel";
        dbus_bool_t b_false = FALSE;
        DBusMessageIter iter, sub;
        DBusConnection *bus;

        dbus_error_init(&error);

        if (!(rl = action_to_runlevel()))
                return 0;

        if (utmp_get_runlevel(&previous, NULL) < 0)
                previous = 'N';

        if (!(bus = dbus_connection_open_private("unix:abstract=/com/ubuntu/upstart", &error))) {
                if (dbus_error_has_name(&error, DBUS_ERROR_NO_SERVER)) {
                        r = 0;
                        goto finish;
                }

                log_error("Failed to connect to Upstart bus: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        if ((r = bus_check_peercred(bus)) < 0) {
                log_error("Failed to verify owner of bus.");
                goto finish;
        }

        if (!(m = dbus_message_new_method_call(
                              "com.ubuntu.Upstart",
                              "/com/ubuntu/Upstart",
                              "com.ubuntu.Upstart0_6",
                              "EmitEvent"))) {

                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        dbus_message_iter_init_append(m, &iter);

        env1_buf[sizeof(env1_buf)-2] = rl;
        env2_buf[sizeof(env2_buf)-2] = previous;

        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &emit) ||
            !dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &sub) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &env1) ||
            !dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &env2) ||
            !dbus_message_iter_close_container(&iter, &sub) ||
            !dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &b_false)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {

                if (error_is_no_service(&error)) {
                        r = -EADDRNOTAVAIL;
                        goto finish;
                }

                log_error("Failed to issue method call: %s", bus_error_message(&error));
                r = -EIO;
                goto finish;
        }

        r = 1;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        if (bus) {
                dbus_connection_flush(bus);
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        dbus_error_free(&error);

        return r;
}

static int talk_initctl(void) {
        struct init_request request;
        int r, fd;
        char rl;

        if (!(rl = action_to_runlevel()))
                return 0;

        zero(request);
        request.magic = INIT_MAGIC;
        request.sleeptime = 0;
        request.cmd = INIT_CMD_RUNLVL;
        request.runlevel = rl;

        if ((fd = open(INIT_FIFO, O_WRONLY|O_NDELAY|O_CLOEXEC|O_NOCTTY)) < 0) {

                if (errno == ENOENT)
                        return 0;

                log_error("Failed to open "INIT_FIFO": %m");
                return -errno;
        }

        errno = 0;
        r = loop_write(fd, &request, sizeof(request), false) != sizeof(request);
        close_nointr_nofail(fd);

        if (r < 0) {
                log_error("Failed to write to "INIT_FIFO": %m");
                return errno ? -errno : -EIO;
        }

        return 1;
}

static int systemctl_main(DBusConnection *bus, int argc, char *argv[], DBusError *error) {

        static const struct {
                const char* verb;
                const enum {
                        MORE,
                        LESS,
                        EQUAL
                } argc_cmp;
                const int argc;
                int (* const dispatch)(DBusConnection *bus, char **args);
        } verbs[] = {
                { "list-units",            LESS,  1, list_units        },
                { "list-unit-files",       EQUAL, 1, list_unit_files   },
                { "list-jobs",             EQUAL, 1, list_jobs         },
                { "clear-jobs",            EQUAL, 1, daemon_reload     },
                { "load",                  MORE,  2, load_unit         },
                { "cancel",                MORE,  2, cancel_job        },
                { "start",                 MORE,  2, start_unit        },
                { "stop",                  MORE,  2, start_unit        },
                { "condstop",              MORE,  2, start_unit        }, /* For compatibility with ALTLinux */
                { "reload",                MORE,  2, start_unit        },
                { "restart",               MORE,  2, start_unit        },
                { "try-restart",           MORE,  2, start_unit        },
                { "reload-or-restart",     MORE,  2, start_unit        },
                { "reload-or-try-restart", MORE,  2, start_unit        },
                { "force-reload",          MORE,  2, start_unit        }, /* For compatibility with SysV */
                { "condreload",            MORE,  2, start_unit        }, /* For compatibility with ALTLinux */
                { "condrestart",           MORE,  2, start_unit        }, /* For compatibility with RH */
                { "isolate",               EQUAL, 2, start_unit        },
                { "kill",                  MORE,  2, kill_unit         },
                { "is-active",             MORE,  2, check_unit        },
                { "check",                 MORE,  2, check_unit        },
                { "show",                  MORE,  1, show              },
                { "status",                MORE,  2, show              },
                { "help",                  MORE,  2, show              },
                { "dump",                  EQUAL, 1, dump              },
                { "dot",                   EQUAL, 1, dot               },
                { "snapshot",              LESS,  2, snapshot          },
                { "delete",                MORE,  2, delete_snapshot   },
                { "daemon-reload",         EQUAL, 1, daemon_reload     },
                { "daemon-reexec",         EQUAL, 1, daemon_reload     },
                { "show-environment",      EQUAL, 1, show_enviroment   },
                { "set-environment",       MORE,  2, set_environment   },
                { "unset-environment",     MORE,  2, set_environment   },
                { "halt",                  EQUAL, 1, start_special     },
                { "poweroff",              EQUAL, 1, start_special     },
                { "reboot",                EQUAL, 1, start_special     },
                { "kexec",                 EQUAL, 1, start_special     },
                { "suspend",               EQUAL, 1, start_special     },
                { "hibernate",             EQUAL, 1, start_special     },
                { "default",               EQUAL, 1, start_special     },
                { "rescue",                EQUAL, 1, start_special     },
                { "emergency",             EQUAL, 1, start_special     },
                { "exit",                  EQUAL, 1, start_special     },
                { "reset-failed",          MORE,  1, reset_failed      },
                { "enable",                MORE,  2, enable_unit       },
                { "disable",               MORE,  2, enable_unit       },
                { "is-enabled",            MORE,  2, unit_is_enabled   },
                { "reenable",              MORE,  2, enable_unit       },
                { "preset",                MORE,  2, enable_unit       },
                { "mask",                  MORE,  2, enable_unit       },
                { "unmask",                MORE,  2, enable_unit       },
                { "link",                  MORE,  2, enable_unit       },
                { "switch-root",           MORE,  2, switch_root       },
        };

        int left;
        unsigned i;

        assert(argc >= 0);
        assert(argv);
        assert(error);

        left = argc - optind;

        if (left <= 0)
                /* Special rule: no arguments means "list-units" */
                i = 0;
        else {
                if (streq(argv[optind], "help") && !argv[optind+1]) {
                        log_error("This command expects one or more "
                                  "unit names. Did you mean --help?");
                        return -EINVAL;
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

        /* Require a bus connection for all operations but
         * enable/disable */
        if (!streq(verbs[i].verb, "enable") &&
            !streq(verbs[i].verb, "disable") &&
            !streq(verbs[i].verb, "is-enabled") &&
            !streq(verbs[i].verb, "list-unit-files") &&
            !streq(verbs[i].verb, "reenable") &&
            !streq(verbs[i].verb, "preset") &&
            !streq(verbs[i].verb, "mask") &&
            !streq(verbs[i].verb, "unmask") &&
            !streq(verbs[i].verb, "link")) {

                if (running_in_chroot() > 0) {
                        log_info("Running in chroot, ignoring request.");
                        return 0;
                }

                if (((!streq(verbs[i].verb, "reboot") &&
                      !streq(verbs[i].verb, "halt") &&
                      !streq(verbs[i].verb, "poweroff")) || arg_force <= 0) && !bus) {
                        log_error("Failed to get D-Bus connection: %s",
                                  dbus_error_is_set(error) ? error->message : "No connection to service manager.");
                        return -EIO;
                }

        } else {

                if (!bus && !avoid_bus()) {
                        log_error("Failed to get D-Bus connection: %s",
                                  dbus_error_is_set(error) ? error->message : "No connection to service manager.");
                        return -EIO;
                }
        }

        return verbs[i].dispatch(bus, argv + optind);
}

static int send_shutdownd(usec_t t, char mode, bool dry_run, bool warn, const char *message) {
        int fd;
        struct msghdr msghdr;
        struct iovec iovec[2];
        union sockaddr_union sockaddr;
        struct sd_shutdown_command c;

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        zero(c);
        c.usec = t;
        c.mode = mode;
        c.dry_run = dry_run;
        c.warn_wall = warn;

        zero(sockaddr);
        sockaddr.sa.sa_family = AF_UNIX;
        strncpy(sockaddr.un.sun_path, "/run/systemd/shutdownd", sizeof(sockaddr.un.sun_path));

        zero(msghdr);
        msghdr.msg_name = &sockaddr;
        msghdr.msg_namelen = offsetof(struct sockaddr_un, sun_path) + sizeof("/run/systemd/shutdownd") - 1;

        zero(iovec);
        iovec[0].iov_base = (char*) &c;
        iovec[0].iov_len = offsetof(struct sd_shutdown_command, wall_message);

        if (isempty(message))
                msghdr.msg_iovlen = 1;
        else {
                iovec[1].iov_base = (char*) message;
                iovec[1].iov_len = strlen(message);
                msghdr.msg_iovlen = 2;
        }
        msghdr.msg_iov = iovec;

        if (sendmsg(fd, &msghdr, MSG_NOSIGNAL) < 0) {
                close_nointr_nofail(fd);
                return -errno;
        }

        close_nointr_nofail(fd);
        return 0;
}

static int reload_with_fallback(DBusConnection *bus) {

        if (bus) {
                /* First, try systemd via D-Bus. */
                if (daemon_reload(bus, NULL) >= 0)
                        return 0;
        }

        /* Nothing else worked, so let's try signals */
        assert(arg_action == ACTION_RELOAD || arg_action == ACTION_REEXEC);

        if (kill(1, arg_action == ACTION_RELOAD ? SIGHUP : SIGTERM) < 0) {
                log_error("kill() failed: %m");
                return -errno;
        }

        return 0;
}

static int start_with_fallback(DBusConnection *bus) {

        if (bus) {
                /* First, try systemd via D-Bus. */
                if (start_unit(bus, NULL) >= 0)
                        goto done;
        }

        /* Hmm, talking to systemd via D-Bus didn't work. Then
         * let's try to talk to Upstart via D-Bus. */
        if (talk_upstart() > 0)
                goto done;

        /* Nothing else worked, so let's try
         * /dev/initctl */
        if (talk_initctl() > 0)
                goto done;

        log_error("Failed to talk to init daemon.");
        return -EIO;

done:
        warn_wall(arg_action);
        return 0;
}

static void halt_now(enum action a) {

       /* Make sure C-A-D is handled by the kernel from this
         * point on... */
        reboot(RB_ENABLE_CAD);

        switch (a) {

        case ACTION_HALT:
                log_info("Halting.");
                reboot(RB_HALT_SYSTEM);
                break;

        case ACTION_POWEROFF:
                log_info("Powering off.");
                reboot(RB_POWER_OFF);
                break;

        case ACTION_REBOOT:
                log_info("Rebooting.");
                reboot(RB_AUTOBOOT);
                break;

        default:
                assert_not_reached("Unknown halt action.");
        }

        assert_not_reached("Uh? This shouldn't happen.");
}

static int halt_main(DBusConnection *bus) {
        int r;

        if (geteuid() != 0) {
                /* Try logind if we are a normal user and no special
                 * mode applies. Maybe PolicyKit allows us to shutdown
                 * the machine. */

                if (arg_when <= 0 &&
                    !arg_dry &&
                    !arg_force &&
                    (arg_action == ACTION_POWEROFF ||
                     arg_action == ACTION_REBOOT)) {
                        r = reboot_with_logind(bus, arg_action);
                        if (r >= 0)
                                return r;
                }

                log_error("Must be root.");
                return -EPERM;
        }

        if (arg_when > 0) {
                char *m;

                m = strv_join(arg_wall, " ");
                r = send_shutdownd(arg_when,
                                   arg_action == ACTION_HALT     ? 'H' :
                                   arg_action == ACTION_POWEROFF ? 'P' :
                                   arg_action == ACTION_KEXEC    ? 'K' :
                                                                   'r',
                                   arg_dry,
                                   !arg_no_wall,
                                   m);
                free(m);

                if (r < 0)
                        log_warning("Failed to talk to shutdownd, proceeding with immediate shutdown: %s", strerror(-r));
                else {
                        char date[FORMAT_TIMESTAMP_MAX];

                        log_info("Shutdown scheduled for %s, use 'shutdown -c' to cancel.",
                                 format_timestamp(date, sizeof(date), arg_when));
                        return 0;
                }
        }

        if (!arg_dry && !arg_force)
                return start_with_fallback(bus);

        if (!arg_no_wtmp) {
                if (sd_booted() > 0)
                        log_debug("Not writing utmp record, assuming that systemd-update-utmp is used.");
                else {
                        r = utmp_put_shutdown();
                        if (r < 0)
                                log_warning("Failed to write utmp record: %s", strerror(-r));
                }
        }

        if (!arg_no_sync)
                sync();

        if (arg_dry)
                return 0;

        halt_now(arg_action);
        /* We should never reach this. */
        return -ENOSYS;
}

static int runlevel_main(void) {
        int r, runlevel, previous;

        r = utmp_get_runlevel(&runlevel, &previous);
        if (r < 0) {
                puts("unknown");
                return r;
        }

        printf("%c %c\n",
               previous <= 0 ? 'N' : previous,
               runlevel <= 0 ? 'N' : runlevel);

        return 0;
}

int main(int argc, char*argv[]) {
        int r, retval = EXIT_FAILURE;
        DBusConnection *bus = NULL;
        DBusError error;

        dbus_error_init(&error);

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r < 0)
                goto finish;
        else if (r == 0) {
                retval = EXIT_SUCCESS;
                goto finish;
        }

        /* /sbin/runlevel doesn't need to communicate via D-Bus, so
         * let's shortcut this */
        if (arg_action == ACTION_RUNLEVEL) {
                r = runlevel_main();
                retval = r < 0 ? EXIT_FAILURE : r;
                goto finish;
        }

        if (running_in_chroot() > 0 && arg_action != ACTION_SYSTEMCTL) {
                log_info("Running in chroot, ignoring request.");
                retval = 0;
                goto finish;
        }

        if (!avoid_bus()) {
                if (arg_transport == TRANSPORT_NORMAL)
                        bus_connect(arg_scope == UNIT_FILE_SYSTEM ? DBUS_BUS_SYSTEM : DBUS_BUS_SESSION, &bus, &private_bus, &error);
                else if (arg_transport == TRANSPORT_POLKIT) {
                        bus_connect_system_polkit(&bus, &error);
                        private_bus = false;
                } else if (arg_transport == TRANSPORT_SSH) {
                        bus_connect_system_ssh(NULL, arg_host, &bus, &error);
                        private_bus = false;
                } else
                        assert_not_reached("Uh, invalid transport...");
        }

        switch (arg_action) {

        case ACTION_SYSTEMCTL:
                r = systemctl_main(bus, argc, argv, &error);
                break;

        case ACTION_HALT:
        case ACTION_POWEROFF:
        case ACTION_REBOOT:
        case ACTION_KEXEC:
                r = halt_main(bus);
                break;

        case ACTION_RUNLEVEL2:
        case ACTION_RUNLEVEL3:
        case ACTION_RUNLEVEL4:
        case ACTION_RUNLEVEL5:
        case ACTION_RESCUE:
        case ACTION_EMERGENCY:
        case ACTION_DEFAULT:
                r = start_with_fallback(bus);
                break;

        case ACTION_RELOAD:
        case ACTION_REEXEC:
                r = reload_with_fallback(bus);
                break;

        case ACTION_CANCEL_SHUTDOWN:
                r = send_shutdownd(0, 0, false, false, NULL);
                break;

        case ACTION_INVALID:
        case ACTION_RUNLEVEL:
        default:
                assert_not_reached("Unknown action");
        }

        retval = r < 0 ? EXIT_FAILURE : r;

finish:
        if (bus) {
                dbus_connection_flush(bus);
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        dbus_error_free(&error);

        dbus_shutdown();

        strv_free(arg_property);

        pager_close();
        ask_password_agent_close();
        polkit_agent_close();

        return retval;
}
