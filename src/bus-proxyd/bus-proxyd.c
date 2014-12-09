/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2013 Daniel Mack
  Copyright 2014 Kay Sievers

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

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/poll.h>
#include <stddef.h>
#include <getopt.h>

#include "log.h"
#include "util.h"
#include "socket-util.h"
#include "sd-daemon.h"
#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-util.h"
#include "build.h"
#include "strv.h"
#include "def.h"
#include "capability.h"
#include "bus-policy.h"
#include "bus-control.h"
#include "smack-util.h"

static char *arg_address = NULL;
static char *arg_command_line_buffer = NULL;
static bool arg_drop_privileges = false;
static char **arg_configuration = NULL;

static int help(void) {

        printf("%s [OPTIONS...]\n\n"
               "Connect STDIO or a socket to a given bus address.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --drop-privileges    Drop privileges\n"
               "     --configuration=PATH Configuration file or directory\n"
               "     --machine=MACHINE    Connect to specified machine\n"
               "     --address=ADDRESS    Connect to the bus specified by ADDRESS\n"
               "                          (default: " DEFAULT_SYSTEM_BUS_ADDRESS ")\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_ADDRESS,
                ARG_DROP_PRIVILEGES,
                ARG_CONFIGURATION,
                ARG_MACHINE,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "address",         required_argument, NULL, ARG_ADDRESS         },
                { "drop-privileges", no_argument,       NULL, ARG_DROP_PRIVILEGES },
                { "configuration",   required_argument, NULL, ARG_CONFIGURATION   },
                { "machine",         required_argument, NULL, ARG_MACHINE         },
                {},
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_ADDRESS: {
                        char *a;

                        a = strdup(optarg);
                        if (!a)
                                return log_oom();

                        free(arg_address);
                        arg_address = a;
                        break;
                }

                case ARG_DROP_PRIVILEGES:
                        arg_drop_privileges = true;
                        break;

                case ARG_CONFIGURATION:
                        r = strv_extend(&arg_configuration, optarg);
                        if (r < 0)
                                return log_oom();
                        break;

                case ARG_MACHINE: {
                        _cleanup_free_ char *e = NULL;
                        char *a;

                        e = bus_address_escape(optarg);
                        if (!e)
                                return log_oom();

#ifdef ENABLE_KDBUS
                        a = strjoin("x-container-kernel:machine=", e, ";x-container-unix:machine=", e, NULL);
#else
                        a = strjoin("x-container-unix:machine=", e, NULL);
#endif
                        if (!a)
                                return log_oom();

                        free(arg_address);
                        arg_address = a;

                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        /* If the first command line argument is only "x" characters
         * we'll write who we are talking to into it, so that "ps" is
         * explanatory */
        arg_command_line_buffer = argv[optind];
        if (argc > optind + 1 || (arg_command_line_buffer && !in_charset(arg_command_line_buffer, "x"))) {
                log_error("Too many arguments");
                return -EINVAL;
        }

        if (!arg_address) {
                arg_address = strdup(DEFAULT_SYSTEM_BUS_ADDRESS);
                if (!arg_address)
                        return log_oom();
        }

        return 1;
}

static int rename_service(sd_bus *a, sd_bus *b) {
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        _cleanup_free_ char *p = NULL, *name = NULL;
        const char *comm;
        char **cmdline;
        uid_t uid;
        pid_t pid;
        int r;

        assert(a);
        assert(b);

        r = sd_bus_get_owner_creds(b, SD_BUS_CREDS_UID|SD_BUS_CREDS_PID|SD_BUS_CREDS_CMDLINE|SD_BUS_CREDS_COMM, &creds);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_uid(creds, &uid);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_pid(creds, &pid);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_cmdline(creds, &cmdline);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_comm(creds, &comm);
        if (r < 0)
                return r;

        name = uid_to_name(uid);
        if (!name)
                return -ENOMEM;

        p = strv_join(cmdline, " ");
        if (!p)
                return -ENOMEM;

        /* The status string gets the full command line ... */
        sd_notifyf(false,
                   "STATUS=Processing requests from client PID "PID_FMT" (%s); UID "UID_FMT" (%s)",
                   pid, p,
                   uid, name);

        /* ... and the argv line only the short comm */
        if (arg_command_line_buffer) {
                size_t m, w;

                m = strlen(arg_command_line_buffer);
                w = snprintf(arg_command_line_buffer, m,
                             "[PID "PID_FMT"/%s; UID "UID_FMT"/%s]",
                             pid, comm,
                             uid, name);

                if (m > w)
                        memzero(arg_command_line_buffer + w, m - w);
        }

        log_debug("Running on behalf of PID "PID_FMT" (%s), UID "UID_FMT" (%s), %s",
                  pid, p,
                  uid, name,
                  a->unique_name);

        return 0;
}

static int synthesize_name_acquired(sd_bus *a, sd_bus *b, sd_bus_message *m) {
        _cleanup_bus_message_unref_ sd_bus_message *n = NULL;
        const char *name, *old_owner, *new_owner;
        int r;

        assert(a);
        assert(b);
        assert(m);

        /* If we get NameOwnerChanged for our own name, we need to
         * synthesize NameLost/NameAcquired, since socket clients need
         * that, even though it is obsoleted on kdbus */

        if (!a->is_kernel)
                return 0;

        if (!sd_bus_message_is_signal(m, "org.freedesktop.DBus", "NameOwnerChanged") ||
            !streq_ptr(m->path, "/org/freedesktop/DBus") ||
            !streq_ptr(m->sender, "org.freedesktop.DBus"))
                return 0;

        r = sd_bus_message_read(m, "sss", &name, &old_owner, &new_owner);
        if (r < 0)
                return r;

        r = sd_bus_message_rewind(m, true);
        if (r < 0)
                return r;

        if (streq(old_owner, a->unique_name)) {

                r = sd_bus_message_new_signal(
                                b,
                                &n,
                                "/org/freedesktop/DBus",
                                "org.freedesktop.DBus",
                                "NameLost");

        } else if (streq(new_owner, a->unique_name)) {

                r = sd_bus_message_new_signal(
                                b,
                                &n,
                                "/org/freedesktop/DBus",
                                "org.freedesktop.DBus",
                                "NameAcquired");
        } else
                return 0;

        if (r < 0)
                return r;

        r = sd_bus_message_append(n, "s", name);
        if (r < 0)
                return r;

        r = bus_message_append_sender(n, "org.freedesktop.DBus");
        if (r < 0)
                return r;

        r = bus_seal_synthetic_message(b, n);
        if (r < 0)
                return r;

        return sd_bus_send(b, n, NULL);
}

static int synthetic_driver_send(sd_bus *b, sd_bus_message *m) {
        int r;

        assert(b);
        assert(m);

        r = bus_message_append_sender(m, "org.freedesktop.DBus");
        if (r < 0)
                return r;

        r = bus_seal_synthetic_message(b, m);
        if (r < 0)
                return r;

        return sd_bus_send(b, m, NULL);
}

static int synthetic_reply_method_error(sd_bus_message *call, const sd_bus_error *e) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(call);

        if (call->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        r = sd_bus_message_new_method_error(call, &m, e);
        if (r < 0)
                return r;

        return synthetic_driver_send(call->bus, m);
}

static int synthetic_reply_method_errno(sd_bus_message *call, int error, const sd_bus_error *p) {

        _cleanup_bus_error_free_ sd_bus_error berror = SD_BUS_ERROR_NULL;

        assert(call);

        if (call->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        if (sd_bus_error_is_set(p))
                return synthetic_reply_method_error(call, p);

        sd_bus_error_set_errno(&berror, error);

        return synthetic_reply_method_error(call, &berror);
}

static int synthetic_reply_method_return(sd_bus_message *call, const char *types, ...) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(call);

        if (call->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 0;

        r = sd_bus_message_new_method_return(call, &m);
        if (r < 0)
                return r;

        if (!isempty(types)) {
                va_list ap;

                va_start(ap, types);
                r = bus_message_append_ap(m, types, ap);
                va_end(ap);
                if (r < 0)
                        return r;
        }

        return synthetic_driver_send(call->bus, m);
}

static int synthetic_reply_return_strv(sd_bus_message *call, char **l) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(call);

        r = sd_bus_message_new_method_return(call, &m);
        if (r < 0)
                return synthetic_reply_method_errno(call, r, NULL);

        r = sd_bus_message_append_strv(m, l);
        if (r < 0)
                return synthetic_reply_method_errno(call, r, NULL);

        return synthetic_driver_send(call->bus, m);
}

static int get_creds_by_name(sd_bus *bus, const char *name, uint64_t mask, sd_bus_creds **_creds, sd_bus_error *error) {
        _cleanup_bus_creds_unref_ sd_bus_creds *c = NULL;
        int r;

        assert(bus);
        assert(name);
        assert(_creds);

        r = sd_bus_get_name_creds(bus, name, mask, &c);
        if (r == -ESRCH || r == -ENXIO)
                return sd_bus_error_setf(error, SD_BUS_ERROR_NAME_HAS_NO_OWNER, "Name %s is currently not owned by anyone.", name);
        if (r < 0)
                return r;

        if ((c->mask & mask) != mask)
                return -ENOTSUP;

        *_creds = c;
        c = NULL;

        return 0;
}

static int get_creds_by_message(sd_bus *bus, sd_bus_message *m, uint64_t mask, sd_bus_creds **_creds, sd_bus_error *error) {
        const char *name;
        int r;

        assert(bus);
        assert(m);
        assert(_creds);

        r = sd_bus_message_read(m, "s", &name);
        if (r < 0)
                return r;

        return get_creds_by_name(bus, name, mask, _creds, error);
}

static int process_driver(sd_bus *a, sd_bus *b, sd_bus_message *m, Policy *policy, const struct ucred *ucred, Set *owned_names) {
        int r;

        assert(a);
        assert(b);
        assert(m);

        if (!a->is_kernel)
                return 0;

        if (!streq_ptr(sd_bus_message_get_destination(m), "org.freedesktop.DBus"))
                return 0;

        /* The "Hello()" call is is handled in process_hello() */

        if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus.Introspectable", "Introspect")) {

                if (!sd_bus_message_has_signature(m, ""))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                return synthetic_reply_method_return(m, "s",
                        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\" "
                          "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
                        "<node>\n"
                        " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
                        "  <method name=\"Introspect\">\n"
                        "   <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"
                        "  </method>\n"
                        " </interface>\n"
                        " <interface name=\"org.freedesktop.DBus\">\n"
                        "  <method name=\"AddMatch\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "  </method>\n"
                        "  <method name=\"RemoveMatch\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "  </method>\n"
                        "  <method name=\"GetConnectionSELinuxSecurityContext\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"ay\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"GetConnectionUnixProcessID\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"u\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"GetConnectionUnixUser\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"u\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"GetId\">\n"
                        "   <arg type=\"s\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"GetNameOwner\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"s\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"Hello\">\n"
                        "   <arg type=\"s\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"ListActivatableNames\">\n"
                        "   <arg type=\"as\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"ListNames\">\n"
                        "   <arg type=\"as\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"ListQueuedOwners\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"as\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"NameHasOwner\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"b\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"ReleaseName\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"u\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"ReloadConfig\">\n"
                        "  </method>\n"
                        "  <method name=\"RequestName\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"u\" direction=\"in\"/>\n"
                        "   <arg type=\"u\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"StartServiceByName\">\n"
                        "   <arg type=\"s\" direction=\"in\"/>\n"
                        "   <arg type=\"u\" direction=\"in\"/>\n"
                        "   <arg type=\"u\" direction=\"out\"/>\n"
                        "  </method>\n"
                        "  <method name=\"UpdateActivationEnvironment\">\n"
                        "   <arg type=\"a{ss}\" direction=\"in\"/>\n"
                        "  </method>\n"
                        "  <signal name=\"NameAcquired\">\n"
                        "   <arg type=\"s\"/>\n"
                        "  </signal>\n"
                        "  <signal name=\"NameLost\">\n"
                        "   <arg type=\"s\"/>\n"
                        "  </signal>\n"
                        "  <signal name=\"NameOwnerChanged\">\n"
                        "   <arg type=\"s\"/>\n"
                        "   <arg type=\"s\"/>\n"
                        "   <arg type=\"s\"/>\n"
                        "  </signal>\n"
                        " </interface>\n"
                        "</node>\n");

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "AddMatch")) {
                const char *match;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "s", &match);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_add_match(a, NULL, match, NULL, NULL);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                return synthetic_reply_method_return(m, NULL);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "RemoveMatch")) {
                const char *match;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "s", &match);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = bus_remove_match_by_string(a, match, NULL, NULL);
                if (r == 0)
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_MATCH_RULE_NOT_FOUND, "Match rule not found"));
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                return synthetic_reply_method_return(m, NULL);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "GetConnectionSELinuxSecurityContext")) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = get_creds_by_message(a, m, SD_BUS_CREDS_SELINUX_CONTEXT, &creds, &error);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, &error);

                return synthetic_reply_method_return(m, "y", creds->label, strlen(creds->label));

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "GetConnectionUnixProcessID")) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = get_creds_by_message(a, m, SD_BUS_CREDS_PID, &creds, &error);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, &error);

                return synthetic_reply_method_return(m, "u", (uint32_t) creds->pid);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "GetConnectionUnixUser")) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = get_creds_by_message(a, m, SD_BUS_CREDS_UID, &creds, &error);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, &error);

                return synthetic_reply_method_return(m, "u", (uint32_t) creds->uid);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "GetId")) {
                sd_id128_t server_id;
                char buf[SD_ID128_STRING_MAX];

                if (!sd_bus_message_has_signature(m, ""))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_get_bus_id(a, &server_id);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                return synthetic_reply_method_return(m, "s", sd_id128_to_string(server_id, buf));

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "GetNameOwner")) {
                const char *name;
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "s", &name);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                if (streq(name, "org.freedesktop.DBus"))
                        return synthetic_reply_method_return(m, "s", "org.freedesktop.DBus");

                r = get_creds_by_name(a, name, SD_BUS_CREDS_UNIQUE_NAME, &creds, &error);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, &error);

                return synthetic_reply_method_return(m, "s", creds->unique_name);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "ListActivatableNames")) {
                _cleanup_strv_free_ char **names = NULL;

                if (!sd_bus_message_has_signature(m, ""))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_list_names(a, NULL, &names);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                /* Let's sort the names list to make it stable */
                strv_sort(names);

                return synthetic_reply_return_strv(m, names);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "ListNames")) {
                _cleanup_strv_free_ char **names = NULL;

                if (!sd_bus_message_has_signature(m, ""))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_list_names(a, &names, NULL);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = strv_extend(&names, "org.freedesktop.DBus");
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                /* Let's sort the names list to make it stable */
                strv_sort(names);

                return synthetic_reply_return_strv(m, names);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "ListQueuedOwners")) {
                struct kdbus_cmd_name_list cmd = {};
                struct kdbus_name_list *name_list;
                struct kdbus_name_info *name;
                _cleanup_strv_free_ char **owners = NULL;
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
                char *arg0;
                int err = 0;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "s", &arg0);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_get_name_creds(a, arg0, 0, NULL);
                if (r == -ESRCH || r == -ENXIO) {
                        sd_bus_error_setf(&error, SD_BUS_ERROR_NAME_HAS_NO_OWNER, "Could not get owners of name '%s': no such name.", arg0);
                        return synthetic_reply_method_errno(m, r, &error);
                }
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                cmd.flags = KDBUS_NAME_LIST_QUEUED;
                r = ioctl(a->input_fd, KDBUS_CMD_NAME_LIST, &cmd);
                if (r < 0)
                        return synthetic_reply_method_errno(m, -errno, NULL);

                name_list = (struct kdbus_name_list *) ((uint8_t *) a->kdbus_buffer + cmd.offset);

                KDBUS_ITEM_FOREACH(name, name_list, names) {
                        const char *entry_name = NULL;
                        struct kdbus_item *item;
                        char *n;

                        KDBUS_ITEM_FOREACH(item, name, items)
                                if (item->type == KDBUS_ITEM_OWNED_NAME)
                                        entry_name = item->name.name;

                        if (!streq_ptr(entry_name, arg0))
                                continue;

                        if (asprintf(&n, ":1.%llu", (unsigned long long) name->owner_id) < 0) {
                                err  = -ENOMEM;
                                break;
                        }

                        r = strv_consume(&owners, n);
                        if (r < 0) {
                                err = r;
                                break;
                        }
                }

                r = bus_kernel_cmd_free(a, cmd.offset);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                if (err < 0)
                        return synthetic_reply_method_errno(m, err, NULL);

                return synthetic_reply_return_strv(m, owners);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "NameHasOwner")) {
                const char *name;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "s", &name);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                if (streq(name, "org.freedesktop.DBus"))
                        return synthetic_reply_method_return(m, "b", true);

                r = sd_bus_get_name_creds(a, name, 0, NULL);
                if (r < 0 && r != -ESRCH && r != -ENXIO)
                        return synthetic_reply_method_errno(m, r, NULL);

                return synthetic_reply_method_return(m, "b", r >= 0);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "ReleaseName")) {
                const char *name;

                if (!sd_bus_message_has_signature(m, "s"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "s", &name);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_release_name(a, name);
                if (r < 0) {
                        if (r == -ESRCH)
                                return synthetic_reply_method_return(m, "u", BUS_NAME_NON_EXISTENT);
                        if (r == -EADDRINUSE)
                                return synthetic_reply_method_return(m, "u", BUS_NAME_NOT_OWNER);

                        return synthetic_reply_method_errno(m, r, NULL);
                }

                set_remove(owned_names, (char*) name);

                return synthetic_reply_method_return(m, "u", BUS_NAME_RELEASED);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "ReloadConfig")) {
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                if (!sd_bus_message_has_signature(m, ""))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_error_setf(&error, SD_BUS_ERROR_NOT_SUPPORTED, "%s() is not supported", sd_bus_message_get_member(m));

                return synthetic_reply_method_errno(m, r, &error);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "RequestName")) {
                const char *name;
                uint32_t flags, param;
                bool in_queue;

                if (!sd_bus_message_has_signature(m, "su"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "su", &name, &flags);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                if (policy && !policy_check_own(policy, ucred->uid, ucred->gid, name))
                        return synthetic_reply_method_errno(m, -EPERM, NULL);

                if ((flags & ~(BUS_NAME_ALLOW_REPLACEMENT|BUS_NAME_REPLACE_EXISTING|BUS_NAME_DO_NOT_QUEUE)) != 0)
                        return synthetic_reply_method_errno(m, -EINVAL, NULL);

                param = 0;
                if (flags & BUS_NAME_ALLOW_REPLACEMENT)
                        param |= SD_BUS_NAME_ALLOW_REPLACEMENT;
                if (flags & BUS_NAME_REPLACE_EXISTING)
                        param |= SD_BUS_NAME_REPLACE_EXISTING;
                if (!(flags & BUS_NAME_DO_NOT_QUEUE))
                        param |= SD_BUS_NAME_QUEUE;

                r = set_put_strdup(owned_names, name);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_request_name(a, name, param);
                if (r < 0) {
                        if (r == -EALREADY)
                                return synthetic_reply_method_return(m, "u", BUS_NAME_ALREADY_OWNER);

                        set_remove(owned_names, (char*) name);

                        if (r == -EEXIST)
                                return synthetic_reply_method_return(m, "u", BUS_NAME_EXISTS);
                        return synthetic_reply_method_errno(m, r, NULL);
                }

                in_queue = (r == 0);

                if (in_queue)
                        return synthetic_reply_method_return(m, "u", BUS_NAME_IN_QUEUE);

                return synthetic_reply_method_return(m, "u", BUS_NAME_PRIMARY_OWNER);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "StartServiceByName")) {
                _cleanup_bus_message_unref_ sd_bus_message *msg = NULL;
                const char *name;
                uint32_t flags;

                if (!sd_bus_message_has_signature(m, "su"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_read(m, "su", &name, &flags);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                if (flags != 0)
                        return synthetic_reply_method_errno(m, -EINVAL, NULL);

                r = sd_bus_get_name_creds(a, name, 0, NULL);
                if (r >= 0 || streq(name, "org.freedesktop.DBus"))
                        return synthetic_reply_method_return(m, "u", BUS_START_REPLY_ALREADY_RUNNING);
                if (r != -ESRCH)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_message_new_method_call(
                                a,
                                &msg,
                                name,
                                "/",
                                "org.freedesktop.DBus.Peer",
                                "Ping");
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_send(a, msg, NULL);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                return synthetic_reply_method_return(m, "u", BUS_START_REPLY_SUCCESS);

        } else if (sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "UpdateActivationEnvironment")) {
                _cleanup_bus_message_unref_ sd_bus_message *msg = NULL;
                _cleanup_strv_free_ char **args = NULL;

                if (!sd_bus_message_has_signature(m, "a{ss}"))
                        return synthetic_reply_method_error(m, &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INVALID_ARGS, "Invalid parameters"));

                r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{ss}");
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                while ((r = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "ss")) > 0) {
                        _cleanup_free_ char *s = NULL;
                        const char *key;
                        const char *value;

                        r = sd_bus_message_read(m, "ss", &key, &value);
                        if (r < 0)
                                return synthetic_reply_method_errno(m, r, NULL);

                        s = strjoin(key, "=", value, NULL);
                        if (!s)
                                return synthetic_reply_method_errno(m, -ENOMEM, NULL);

                        r  = strv_extend(&args, s);
                        if (r < 0)
                                return synthetic_reply_method_errno(m, r, NULL);

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return synthetic_reply_method_errno(m, r, NULL);
                }

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                if (!args)
                        return synthetic_reply_method_errno(m, -EINVAL, NULL);

                r = sd_bus_message_new_method_call(
                                a,
                                &msg,
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "SetEnvironment");
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_message_append_strv(msg, args);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

                r = sd_bus_call(a, msg, 0, NULL, NULL);
                if (r < 0)
                        return synthetic_reply_method_errno(m, r, NULL);

               return synthetic_reply_method_return(m, NULL);

        } else {
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                r = sd_bus_error_setf(&error, SD_BUS_ERROR_UNKNOWN_METHOD, "Unknown method '%s'.", m->member);

                return synthetic_reply_method_errno(m, r, &error);
        }
}

static int process_policy(sd_bus *from, sd_bus *to, sd_bus_message *m, Policy *policy, const struct ucred *our_ucred, Set *owned_names) {
        int r;

        assert(from);
        assert(to);
        assert(m);

        if (!policy)
                return 0;

        if (from->is_kernel) {
                uid_t sender_uid = UID_INVALID;
                gid_t sender_gid = GID_INVALID;
                char **sender_names = NULL;
                bool granted = false;

                /* Driver messages are always OK */
                if (streq_ptr(m->sender, "org.freedesktop.DBus"))
                        return 0;

                /* The message came from the kernel, and is sent to our legacy client. */
                r = sd_bus_creds_get_well_known_names(&m->creds, &sender_names);
                if (r < 0)
                        return r;

                (void) sd_bus_creds_get_uid(&m->creds, &sender_uid);
                (void) sd_bus_creds_get_gid(&m->creds, &sender_gid);

                /* First check whether the sender can send the message to our name */
                if (set_isempty(owned_names)) {
                        if (policy_check_send(policy, sender_uid, sender_gid, m->header->type, NULL, m->path, m->interface, m->member))
                                granted = true;
                } else {
                        Iterator i;
                        char *n;

                        SET_FOREACH(n, owned_names, i)
                                if (policy_check_send(policy, sender_uid, sender_gid, m->header->type, n, m->path, m->interface, m->member)) {
                                        granted = true;
                                        break;
                                }
                }

                if (granted) {
                        /* Then check whether us (the recipient) can recieve from the sender's name */
                        if (strv_isempty(sender_names)) {
                                if (policy_check_recv(policy, our_ucred->uid, our_ucred->gid, m->header->type, NULL, m->path, m->interface, m->member))
                                        return 0;
                        } else {
                                char **n;

                                STRV_FOREACH(n, sender_names) {
                                        if (policy_check_recv(policy, our_ucred->uid, our_ucred->gid, m->header->type, *n, m->path, m->interface, m->member))
                                                return 0;
                                }
                        }
                }

                /* Return an error back to the caller */
                if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
                        return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_ACCESS_DENIED, "Access prohibited by XML receiver policy.");

                /* Return 1, indicating that the message shall not be processed any further */
                return 1;
        }

        if (to->is_kernel) {
                _cleanup_bus_creds_unref_ sd_bus_creds *destination_creds = NULL;
                uid_t destination_uid = UID_INVALID;
                gid_t destination_gid = GID_INVALID;
                const char *destination_unique = NULL;
                char **destination_names = NULL;
                bool granted = false;

                /* Driver messages are always OK */
                if (streq_ptr(m->destination, "org.freedesktop.DBus"))
                        return 0;

                /* The message came from the legacy client, and is sent to kdbus. */
                if (m->destination) {
                        r = bus_get_name_creds_kdbus(to, m->destination,
                                                     SD_BUS_CREDS_WELL_KNOWN_NAMES|SD_BUS_CREDS_UNIQUE_NAME|
                                                     SD_BUS_CREDS_UID|SD_BUS_CREDS_GID|SD_BUS_CREDS_PID,
                                                     true, &destination_creds);
                        if (r < 0)
                                return r;

                        r = sd_bus_creds_get_well_known_names(destination_creds, &destination_names);
                        if (r < 0)
                                return r;

                        r = sd_bus_creds_get_unique_name(destination_creds, &destination_unique);
                        if (r < 0)
                                return r;

                        (void) sd_bus_creds_get_uid(destination_creds, &destination_uid);
                        (void) sd_bus_creds_get_gid(destination_creds, &destination_gid);
                }

                /* First check if we (the sender) can send to this name */
                if (strv_isempty(destination_names)) {
                        if (policy_check_send(policy, our_ucred->uid, our_ucred->gid, m->header->type, NULL, m->path, m->interface, m->member))
                                granted = true;
                } else {
                        char **n;

                        STRV_FOREACH(n, destination_names) {
                                if (policy_check_send(policy, our_ucred->uid, our_ucred->gid, m->header->type, *n, m->path, m->interface, m->member)) {

                                        /* If we made a receiver decision,
                                           then remember which name's policy
                                           we used, and to which unique ID it
                                           mapped when we made the
                                           decision. Then, let's pass this to
                                           the kernel when sending the
                                           message, so that it refuses the
                                           operation should the name and
                                           unique ID not map to each other
                                           anymore. */

                                        r = free_and_strdup(&m->destination_ptr, *n);
                                        if (r < 0)
                                                return r;

                                        r = bus_kernel_parse_unique_name(destination_unique, &m->verify_destination_id);
                                        if (r < 0)
                                                break;

                                        granted = true;
                                        break;
                                }
                        }
                }

                /* Then check if the recipient can receive from our name */
                if (granted) {
                        if (set_isempty(owned_names)) {
                                if (policy_check_recv(policy, destination_uid, destination_gid, m->header->type, NULL, m->path, m->interface, m->member))
                                        return 0;
                        } else {
                                Iterator i;
                                char *n;

                                SET_FOREACH(n, owned_names, i)
                                        if (policy_check_recv(policy, destination_uid, destination_gid, m->header->type, n, m->path, m->interface, m->member))
                                                return 0;
                        }
                }

                /* Return an error back to the caller */
                if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
                        return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_ACCESS_DENIED, "Access prohibited by XML sender policy.");

                /* Return 1, indicating that the message shall not be processed any further */
                return 1;
        }

        return 0;
}

static int process_hello(sd_bus *a, sd_bus *b, sd_bus_message *m, bool *got_hello) {
        _cleanup_bus_message_unref_ sd_bus_message *n = NULL;
        bool is_hello;
        int r;

        assert(a);
        assert(b);
        assert(m);
        assert(got_hello);

        /* As reaction to hello we need to respond with two messages:
         * the callback reply and the NameAcquired for the unique
         * name, since hello is otherwise obsolete on kdbus. */

        is_hello =
                sd_bus_message_is_method_call(m, "org.freedesktop.DBus", "Hello") &&
                streq_ptr(m->destination, "org.freedesktop.DBus");

        if (!is_hello) {

                if (*got_hello)
                        return 0;

                log_error("First packet isn't hello (it's %s.%s), aborting.", m->interface, m->member);
                return -EIO;
        }

        if (*got_hello) {
                log_error("Got duplicate hello, aborting.");
                return -EIO;
        }

        *got_hello = true;

        if (!a->is_kernel)
                return 0;

        r = sd_bus_message_new_method_return(m, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to generate HELLO reply: %m");

        r = sd_bus_message_append(n, "s", a->unique_name);
        if (r < 0)
                return log_error_errno(r, "Failed to append unique name to HELLO reply: %m");

        r = bus_message_append_sender(n, "org.freedesktop.DBus");
        if (r < 0)
                return log_error_errno(r, "Failed to append sender to HELLO reply: %m");

        r = bus_seal_synthetic_message(b, n);
        if (r < 0)
                return log_error_errno(r, "Failed to seal HELLO reply: %m");

        r = sd_bus_send(b, n, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to send HELLO reply: %m");

        n = sd_bus_message_unref(n);
        r = sd_bus_message_new_signal(
                        b,
                        &n,
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "NameAcquired");
        if (r < 0)
                return log_error_errno(r, "Failed to allocate initial NameAcquired message: %m");

        r = sd_bus_message_append(n, "s", a->unique_name);
        if (r < 0)
                return log_error_errno(r, "Failed to append unique name to NameAcquired message: %m");

        r = bus_message_append_sender(n, "org.freedesktop.DBus");
        if (r < 0)
                return log_error_errno(r, "Failed to append sender to NameAcquired message: %m");

        r = bus_seal_synthetic_message(b, n);
        if (r < 0)
                return log_error_errno(r, "Failed to seal NameAcquired message: %m");

        r = sd_bus_send(b, n, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to send NameAcquired message: %m");

        return 1;
}

static int patch_sender(sd_bus *a, sd_bus_message *m) {
        char **well_known = NULL;
        sd_bus_creds *c;
        int r;

        assert(a);
        assert(m);

        if (!a->is_kernel)
                return 0;

        /* We will change the sender of messages from the bus driver
         * so that they originate from the bus driver. This is a
         * speciality originating from dbus1, where the bus driver did
         * not have a unique id, but only the well-known name. */

        c = sd_bus_message_get_creds(m);
        if (!c)
                return 0;

        r = sd_bus_creds_get_well_known_names(c, &well_known);
        if (r < 0)
                return r;

        if (strv_contains(well_known, "org.freedesktop.DBus"))
                m->sender = "org.freedesktop.DBus";

        return 0;
}

static int mac_smack_apply_label_and_drop_cap_mac_admin(pid_t its_pid, const char *new_label) {
#ifdef HAVE_SMACK
        int r = 0, k;

        if (!mac_smack_use())
                return 0;

        if (new_label && its_pid > 0)
                r = mac_smack_apply_pid(its_pid, new_label);

        k = drop_capability(CAP_MAC_ADMIN);
        return r < 0 ? r : k;
#else
        return 0;
#endif
}

int main(int argc, char *argv[]) {

        _cleanup_bus_close_unref_ sd_bus *a = NULL, *b = NULL;
        sd_id128_t server_id;
        int r, in_fd, out_fd;
        bool got_hello = false;
        bool is_unix;
        struct ucred ucred = {};
        _cleanup_free_ char *peersec = NULL;
        Policy policy_buffer = {}, *policy = NULL;
        _cleanup_set_free_free_ Set *owned_names = NULL;

        log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = sd_listen_fds(0);
        if (r == 0) {
                in_fd = STDIN_FILENO;
                out_fd = STDOUT_FILENO;
        } else if (r == 1) {
                in_fd = SD_LISTEN_FDS_START;
                out_fd = SD_LISTEN_FDS_START;
        } else {
                log_error("Illegal number of file descriptors passed");
                goto finish;
        }

        is_unix =
                sd_is_socket(in_fd, AF_UNIX, 0, 0) > 0 &&
                sd_is_socket(out_fd, AF_UNIX, 0, 0) > 0;

        if (is_unix) {
                (void) getpeercred(in_fd, &ucred);
                (void) getpeersec(in_fd, &peersec);

                r = mac_smack_apply_label_and_drop_cap_mac_admin(getpid(), peersec);
                if (r < 0)
                        log_warning_errno(r, "Failed to set SMACK label (%s) and drop CAP_MAC_ADMIN: %m", peersec);
        }

        if (arg_drop_privileges) {
                const char *user = "systemd-bus-proxy";
                uid_t uid;
                gid_t gid;

                r = get_user_creds(&user, &uid, &gid, NULL, NULL);
                if (r < 0) {
                        log_error_errno(r, "Cannot resolve user name %s: %m", user);
                        goto finish;
                }

                r = drop_privileges(uid, gid, 1ULL << CAP_IPC_OWNER);
                if (r < 0)
                        goto finish;
        }

        owned_names = set_new(&string_hash_ops);
        if (!owned_names) {
                log_oom();
                goto finish;
        }

        r = sd_bus_new(&a);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate bus: %m");
                goto finish;
        }

        r = sd_bus_set_description(a, "sd-proxy");
        if (r < 0) {
                log_error_errno(r, "Failed to set bus name: %m");
                goto finish;
        }

        r = sd_bus_set_address(a, arg_address);
        if (r < 0) {
                log_error_errno(r, "Failed to set address to connect to: %m");
                goto finish;
        }

        r = sd_bus_negotiate_fds(a, is_unix);
        if (r < 0) {
                log_error_errno(r, "Failed to set FD negotiation: %m");
                goto finish;
        }

        r = sd_bus_negotiate_creds(a, true, SD_BUS_CREDS_UID|SD_BUS_CREDS_PID|SD_BUS_CREDS_GID|SD_BUS_CREDS_SELINUX_CONTEXT);
        if (r < 0) {
                log_error_errno(r, "Failed to set credential negotiation: %m");
                goto finish;
        }

        if (ucred.pid > 0) {
                a->fake_pids.pid = ucred.pid;
                a->fake_pids_valid = true;

                a->fake_creds.uid = ucred.uid;
                a->fake_creds.euid = UID_INVALID;
                a->fake_creds.suid = UID_INVALID;
                a->fake_creds.fsuid = UID_INVALID;
                a->fake_creds.gid = ucred.gid;
                a->fake_creds.egid = GID_INVALID;
                a->fake_creds.sgid = GID_INVALID;
                a->fake_creds.fsgid = GID_INVALID;
                a->fake_creds_valid = true;
        }

        if (peersec) {
                a->fake_label = peersec;
                peersec = NULL;
        }

        a->manual_peer_interface = true;

        r = sd_bus_start(a);
        if (r < 0) {
                log_error_errno(r, "Failed to start bus client: %m");
                goto finish;
        }

        r = sd_bus_get_bus_id(a, &server_id);
        if (r < 0) {
                log_error_errno(r, "Failed to get server ID: %m");
                goto finish;
        }

        if (a->is_kernel) {
                if (!arg_configuration) {
                        const char *scope;

                        r = sd_bus_get_scope(a, &scope);
                        if (r < 0) {
                                log_error_errno(r, "Couldn't determine bus scope: %m");
                                goto finish;
                        }

                        if (streq(scope, "system"))
                                arg_configuration = strv_new(
                                                "/etc/dbus-1/system.conf",
                                                "/etc/dbus-1/system.d/",
                                                "/etc/dbus-1/system-local.conf",
                                                NULL);
                        else if (streq(scope, "user"))
                                arg_configuration = strv_new(
                                                "/etc/dbus-1/session.conf",
                                                "/etc/dbus-1/session.d/",
                                                "/etc/dbus-1/session-local.conf",
                                                NULL);
                        else {
                                log_error("Unknown scope %s, don't know which policy to load. Refusing.", scope);
                                goto finish;
                        }

                        if (!arg_configuration) {
                                r = log_oom();
                                goto finish;
                        }
                }

                r = policy_load(&policy_buffer, arg_configuration);
                if (r < 0) {
                        log_error_errno(r, "Failed to load policy: %m");
                        goto finish;
                }

                policy = &policy_buffer;
                /* policy_dump(policy); */

                if (!policy_check_hello(policy, ucred.uid, ucred.gid)) {
                        r = log_error_errno(EPERM, "Policy denied connection.");
                        goto finish;
                }
        }

        r = sd_bus_new(&b);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate bus: %m");
                goto finish;
        }

        r = sd_bus_set_fd(b, in_fd, out_fd);
        if (r < 0) {
                log_error_errno(r, "Failed to set fds: %m");
                goto finish;
        }

        r = sd_bus_set_server(b, 1, server_id);
        if (r < 0) {
                log_error_errno(r, "Failed to set server mode: %m");
                goto finish;
        }

        r = sd_bus_negotiate_fds(b, is_unix);
        if (r < 0) {
                log_error_errno(r, "Failed to set FD negotiation: %m");
                goto finish;
        }

        r = sd_bus_negotiate_creds(b, true, SD_BUS_CREDS_UID|SD_BUS_CREDS_PID|SD_BUS_CREDS_GID|SD_BUS_CREDS_SELINUX_CONTEXT);
        if (r < 0) {
                log_error_errno(r, "Failed to set credential negotiation: %m");
                goto finish;
        }

        r = sd_bus_set_anonymous(b, true);
        if (r < 0) {
                log_error_errno(r, "Failed to set anonymous authentication: %m");
                goto finish;
        }

        b->manual_peer_interface = true;

        r = sd_bus_start(b);
        if (r < 0) {
                log_error_errno(r, "Failed to start bus client: %m");
                goto finish;
        }

        r = rename_service(a, b);
        if (r < 0)
                log_debug_errno(r, "Failed to rename process: %m");

        if (a->is_kernel) {
                _cleanup_free_ char *match = NULL;
                const char *unique;

                r = sd_bus_get_unique_name(a, &unique);
                if (r < 0) {
                        log_error_errno(r, "Failed to get unique name: %m");
                        goto finish;
                }

                match = strjoin("type='signal',"
                                "sender='org.freedesktop.DBus',"
                                "path='/org/freedesktop/DBus',"
                                "interface='org.freedesktop.DBus',"
                                "member='NameOwnerChanged',"
                                "arg1='",
                                unique,
                                "'",
                                NULL);
                if (!match) {
                        log_oom();
                        goto finish;
                }

                r = sd_bus_add_match(a, NULL, match, NULL, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to add match for NameLost: %m");
                        goto finish;
                }

                free(match);
                match = strjoin("type='signal',"
                                "sender='org.freedesktop.DBus',"
                                "path='/org/freedesktop/DBus',"
                                "interface='org.freedesktop.DBus',"
                                "member='NameOwnerChanged',"
                                "arg2='",
                                unique,
                                "'",
                                NULL);
                if (!match) {
                        log_oom();
                        goto finish;
                }

                r = sd_bus_add_match(a, NULL, match, NULL, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to add match for NameAcquired: %m");
                        goto finish;
                }
        }

        for (;;) {
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
                int events_a, events_b, fd;
                uint64_t timeout_a, timeout_b, t;
                struct timespec _ts, *ts;
                struct pollfd *pollfd;
                int k;

                if (got_hello) {
                        /* Read messages from bus, to pass them on to our client */

                        r = sd_bus_process(a, &m);
                        if (r < 0) {
                                /* treat 'connection reset by peer' as clean exit condition */
                                if (r == -ECONNRESET)
                                        r = 0;
                                else
                                        log_error_errno(r, "Failed to process bus a: %m");

                                goto finish;
                        }

                        if (m) {
                                bool processed = false;

                                /* We officially got EOF, let's quit */
                                if (sd_bus_message_is_signal(m, "org.freedesktop.DBus.Local", "Disconnected")) {
                                        r = 0;
                                        goto finish;
                                }

                                k = synthesize_name_acquired(a, b, m);
                                if (k < 0) {
                                        r = k;
                                        log_error_errno(r, "Failed to synthesize message: %m");
                                        goto finish;
                                }

                                patch_sender(a, m);

                                if (policy) {
                                        k = process_policy(a, b, m, policy, &ucred, owned_names);
                                        if (k < 0) {
                                                r = k;
                                                log_error_errno(r, "Failed to process policy: %m");
                                                goto finish;
                                        } else if (k > 0) {
                                                r = 1;
                                                processed = true;
                                        }
                                }

                                if (!processed) {
                                        k = sd_bus_send(b, m, NULL);
                                        if (k < 0) {
                                                if (k == -ECONNRESET)
                                                        r = 0;
                                                else {
                                                        r = k;
                                                        log_error_errno(r, "Failed to send message to client: %m");
                                                }

                                                goto finish;
                                        } else
                                                r = 1;
                                }
                        }

                        if (r > 0)
                                continue;
                }

                /* Read messages from our client, to pass them on to the bus */
                r = sd_bus_process(b, &m);
                if (r < 0) {
                        /* treat 'connection reset by peer' as clean exit condition */
                        if (r == -ECONNRESET)
                                r = 0;
                        else
                                log_error_errno(r, "Failed to process bus b: %m");

                        goto finish;
                }

                if (m) {
                        bool processed = false;

                        /* We officially got EOF, let's quit */
                        if (sd_bus_message_is_signal(m, "org.freedesktop.DBus.Local", "Disconnected")) {
                                r = 0;
                                goto finish;
                        }

                        k = process_hello(a, b, m, &got_hello);
                        if (k < 0) {
                                r = k;
                                log_error_errno(r, "Failed to process HELLO: %m");
                                goto finish;
                        } else if (k > 0) {
                                processed = true;
                                r = 1;
                        }

                        if (!processed) {
                                k = process_driver(a, b, m, policy, &ucred, owned_names);
                                if (k < 0) {
                                        r = k;
                                        log_error_errno(r, "Failed to process driver calls: %m");
                                        goto finish;
                                } else if (k > 0) {
                                        processed = true;
                                        r = 1;
                                }

                                if (!processed) {

                                        for (;;) {
                                                if (policy) {
                                                        k = process_policy(b, a, m, policy, &ucred, owned_names);
                                                        if (k < 0) {
                                                                r = k;
                                                                log_error_errno(r, "Failed to process policy: %m");
                                                                goto finish;
                                                        } else if (k > 0) {
                                                                processed = true;
                                                                r = 1;
                                                                break;
                                                        }
                                                }

                                                k = sd_bus_send(a, m, NULL);
                                                if (k < 0) {
                                                        if (k == -EREMCHG)
                                                                /* The name database changed since the policy check, hence let's check again */
                                                                continue;
                                                        else if (k == -ECONNRESET)
                                                                r = 0;
                                                        else {
                                                                r = k;
                                                                log_error_errno(r, "Failed to send message to bus: %m");
                                                        }

                                                        goto finish;
                                                } else
                                                        r = 1;

                                                break;
                                        }
                                }
                        }
                }

                if (r > 0)
                        continue;

                fd = sd_bus_get_fd(a);
                if (fd < 0) {
                        log_error_errno(r, "Failed to get fd: %m");
                        goto finish;
                }

                events_a = sd_bus_get_events(a);
                if (events_a < 0) {
                        log_error_errno(r, "Failed to get events mask: %m");
                        goto finish;
                }

                r = sd_bus_get_timeout(a, &timeout_a);
                if (r < 0) {
                        log_error_errno(r, "Failed to get timeout: %m");
                        goto finish;
                }

                events_b = sd_bus_get_events(b);
                if (events_b < 0) {
                        log_error_errno(r, "Failed to get events mask: %m");
                        goto finish;
                }

                r = sd_bus_get_timeout(b, &timeout_b);
                if (r < 0) {
                        log_error_errno(r, "Failed to get timeout: %m");
                        goto finish;
                }

                t = timeout_a;
                if (t == (uint64_t) -1 || (timeout_b != (uint64_t) -1 && timeout_b < timeout_a))
                        t = timeout_b;

                if (t == (uint64_t) -1)
                        ts = NULL;
                else {
                        usec_t nw;

                        nw = now(CLOCK_MONOTONIC);
                        if (t > nw)
                                t -= nw;
                        else
                                t = 0;

                        ts = timespec_store(&_ts, t);
                }

                pollfd = (struct pollfd[3]) {
                        {.fd = fd,     .events = events_a,           },
                        {.fd = in_fd,  .events = events_b & POLLIN,  },
                        {.fd = out_fd, .events = events_b & POLLOUT, }
                };

                r = ppoll(pollfd, 3, ts, NULL);
                if (r < 0) {
                        log_error_errno(errno, "ppoll() failed: %m");
                        goto finish;
                }
        }

finish:
        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Shutting down.");

        policy_free(&policy_buffer);
        strv_free(arg_configuration);
        free(arg_address);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
