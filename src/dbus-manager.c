/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <unistd.h>

#include "dbus.h"
#include "log.h"
#include "dbus-manager.h"
#include "strv.h"
#include "bus-errors.h"
#include "build.h"
#include "dbus-common.h"

#define BUS_MANAGER_INTERFACE_BEGIN                                     \
        " <interface name=\"org.freedesktop.systemd1.Manager\">\n"

#define BUS_MANAGER_INTERFACE_METHODS                                   \
        "  <method name=\"GetUnit\">\n"                                 \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"unit\" type=\"o\" direction=\"out\"/>\n"        \
        "  </method>\n"                                                 \
        "  <method name=\"GetUnitByPID\">\n"                            \
        "   <arg name=\"pid\" type=\"u\" direction=\"in\"/>\n"          \
        "   <arg name=\"unit\" type=\"o\" direction=\"out\"/>\n"        \
        "  </method>\n"                                                 \
        "  <method name=\"LoadUnit\">\n"                                \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"unit\" type=\"o\" direction=\"out\"/>\n"        \
        "  </method>\n"                                                 \
        "  <method name=\"StartUnit\">\n"                               \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"StartUnitReplace\">\n"                        \
        "   <arg name=\"old_unit\" type=\"s\" direction=\"in\"/>\n"     \
        "   <arg name=\"new_unit\" type=\"s\" direction=\"in\"/>\n"     \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"StopUnit\">\n"                                \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"ReloadUnit\">\n"                              \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"RestartUnit\">\n"                             \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"TryRestartUnit\">\n"                          \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"ReloadOrRestartUnit\">\n"                     \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"ReloadOrTryRestartUnit\">\n"                  \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"KillUnit\">\n"                                \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"who\" type=\"s\" direction=\"in\"/>\n"          \
        "   <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"signal\" type=\"i\" direction=\"in\"/>\n"       \
        "  </method>\n"                                                 \
        "  <method name=\"ResetFailedUnit\">\n"                         \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"GetJob\">\n"                                  \
        "   <arg name=\"id\" type=\"u\" direction=\"in\"/>\n"           \
        "   <arg name=\"job\" type=\"o\" direction=\"out\"/>\n"         \
        "  </method>\n"                                                 \
        "  <method name=\"ClearJobs\"/>\n"                              \
        "  <method name=\"ResetFailed\"/>\n"                            \
        "  <method name=\"ListUnits\">\n"                               \
        "   <arg name=\"units\" type=\"a(ssssssouso)\" direction=\"out\"/>\n" \
        "  </method>\n"                                                 \
        "  <method name=\"ListJobs\">\n"                                \
        "   <arg name=\"jobs\" type=\"a(usssoo)\" direction=\"out\"/>\n" \
        "  </method>\n"                                                 \
        "  <method name=\"Subscribe\"/>\n"                              \
        "  <method name=\"Unsubscribe\"/>\n"                            \
        "  <method name=\"Dump\"/>\n"                                   \
        "  <method name=\"CreateSnapshot\">\n"                          \
        "   <arg name=\"name\" type=\"s\" direction=\"in\"/>\n"         \
        "   <arg name=\"cleanup\" type=\"b\" direction=\"in\"/>\n"      \
        "   <arg name=\"unit\" type=\"o\" direction=\"out\"/>\n"        \
        "  </method>\n"                                                 \
        "  <method name=\"Reload\"/>\n"                                 \
        "  <method name=\"Reexecute\"/>\n"                              \
        "  <method name=\"Exit\"/>\n"                                   \
        "  <method name=\"Reboot\"/>\n"                                 \
        "  <method name=\"PowerOff\"/>\n"                               \
        "  <method name=\"Halt\"/>\n"                                   \
        "  <method name=\"KExec\"/>\n"                                  \
        "  <method name=\"SetEnvironment\">\n"                          \
        "   <arg name=\"names\" type=\"as\" direction=\"in\"/>\n"       \
        "  </method>\n"                                                 \
        "  <method name=\"UnsetEnvironment\">\n"                        \
        "   <arg name=\"names\" type=\"as\" direction=\"in\"/>\n"       \
        "  </method>\n"                                                 \
        "  <method name=\"UnsetAndSetEnvironment\">\n"                  \
        "   <arg name=\"unset\" type=\"as\" direction=\"in\"/>\n"       \
        "   <arg name=\"set\" type=\"as\" direction=\"in\"/>\n"         \
        "  </method>\n"

#define BUS_MANAGER_INTERFACE_SIGNALS                                   \
        "  <signal name=\"UnitNew\">\n"                                 \
        "   <arg name=\"id\" type=\"s\"/>\n"                            \
        "   <arg name=\"unit\" type=\"o\"/>\n"                          \
        "  </signal>\n"                                                 \
        "  <signal name=\"UnitRemoved\">\n"                             \
        "   <arg name=\"id\" type=\"s\"/>\n"                            \
        "   <arg name=\"unit\" type=\"o\"/>\n"                          \
        "  </signal>\n"                                                 \
        "  <signal name=\"JobNew\">\n"                                  \
        "   <arg name=\"id\" type=\"u\"/>\n"                            \
        "   <arg name=\"job\" type=\"o\"/>\n"                           \
        "  </signal>\n"                                                 \
        "  <signal name=\"JobRemoved\">\n"                              \
        "   <arg name=\"id\" type=\"u\"/>\n"                            \
        "   <arg name=\"job\" type=\"o\"/>\n"                           \
        "   <arg name=\"result\" type=\"s\"/>\n"                        \
        "  </signal>"                                                   \
        "  <signal name=\"StartupFinished\">\n"                         \
        "   <arg name=\"kernel\" type=\"t\"/>\n"                        \
        "   <arg name=\"initrd\" type=\"t\"/>\n"                        \
        "   <arg name=\"userspace\" type=\"t\"/>\n"                     \
        "   <arg name=\"total\" type=\"t\"/>\n"                         \
        "  </signal>"

#define BUS_MANAGER_INTERFACE_PROPERTIES_GENERAL                        \
        "  <property name=\"Version\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"Distribution\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"Features\" type=\"s\" access=\"read\"/>\n"  \
        "  <property name=\"Tainted\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"RunningAs\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"InitRDTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"InitRDTimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"StartupTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"StartupTimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"FinishTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"FinishTimestampMonotonic\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LogLevel\" type=\"s\" access=\"readwrite\"/>\n"  \
        "  <property name=\"LogTarget\" type=\"s\" access=\"readwrite\"/>\n" \
        "  <property name=\"NNames\" type=\"u\" access=\"read\"/>\n"    \
        "  <property name=\"NJobs\" type=\"u\" access=\"read\"/>\n"     \
        "  <property name=\"NInstalledJobs\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"NFailedJobs\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"Progress\" type=\"d\" access=\"read\"/>\n"  \
        "  <property name=\"Environment\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"ConfirmSpawn\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"ShowStatus\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"UnitPath\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"NotifySocket\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"ControlGroupHierarchy\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"MountAuto\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"SwapAuto\" type=\"b\" access=\"read\"/>\n"  \
        "  <property name=\"DefaultControllers\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"DefaultStandardOutput\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"DefaultStandardError\" type=\"s\" access=\"read\"/>\n"

#ifdef HAVE_SYSV_COMPAT
#define BUS_MANAGER_INTERFACE_PROPERTIES_SYSV                           \
        "  <property name=\"SysVConsole\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"SysVInitPath\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"SysVRcndPath\" type=\"as\" access=\"read\"/>\n"
#else
#define BUS_MANAGER_INTERFACE_PROPERTIES_SYSV
#endif

#define BUS_MANAGER_INTERFACE_END                                       \
        " </interface>\n"

#define BUS_MANAGER_INTERFACE                                           \
        BUS_MANAGER_INTERFACE_BEGIN                                     \
        BUS_MANAGER_INTERFACE_METHODS                                   \
        BUS_MANAGER_INTERFACE_SIGNALS                                   \
        BUS_MANAGER_INTERFACE_PROPERTIES_GENERAL                        \
        BUS_MANAGER_INTERFACE_PROPERTIES_SYSV                           \
        BUS_MANAGER_INTERFACE_END

#define INTROSPECTION_BEGIN                                             \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        BUS_MANAGER_INTERFACE                                           \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_PEER_INTERFACE                                              \
        BUS_INTROSPECTABLE_INTERFACE

#define INTROSPECTION_END                                               \
        "</node>\n"

#define INTERFACES_LIST                              \
        BUS_GENERIC_INTERFACES_LIST                  \
        "org.freedesktop.systemd1.Manager\0"

const char bus_manager_interface[] _introspect_("Manager") = BUS_MANAGER_INTERFACE;

static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_manager_append_running_as, manager_running_as, ManagerRunningAs);
static DEFINE_BUS_PROPERTY_APPEND_ENUM(bus_manager_append_exec_output, exec_output, ExecOutput);

static int bus_manager_append_tainted(DBusMessageIter *i, const char *property, void *data) {
        const char *t;
        Manager *m = data;
        char buf[LINE_MAX] = "", *e = buf, *p = NULL;

        assert(i);
        assert(property);
        assert(m);

        if (m->taint_usr)
                e = stpcpy(e, "usr-separate-fs ");

        if (readlink_malloc("/etc/mtab", &p) < 0)
                e = stpcpy(e, "etc-mtab-not-symlink ");
        else
                free(p);

        if (access("/proc/cgroups", F_OK) < 0)
                e = stpcpy(e, "cgroups-missing ");

        t = strstrip(buf);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &t))
                return -ENOMEM;

        return 0;
}

static int bus_manager_append_log_target(DBusMessageIter *i, const char *property, void *data) {
        const char *t;

        assert(i);
        assert(property);

        t = log_target_to_string(log_get_target());

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &t))
                return -ENOMEM;

        return 0;
}

static int bus_manager_set_log_target(DBusMessageIter *i, const char *property) {
        const char *t;

        assert(i);
        assert(property);

        dbus_message_iter_get_basic(i, &t);

        return log_set_target_from_string(t);
}

static int bus_manager_append_log_level(DBusMessageIter *i, const char *property, void *data) {
        const char *t;

        assert(i);
        assert(property);

        t = log_level_to_string(log_get_max_level());

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &t))
                return -ENOMEM;

        return 0;
}

static int bus_manager_set_log_level(DBusMessageIter *i, const char *property) {
        const char *t;

        assert(i);
        assert(property);

        dbus_message_iter_get_basic(i, &t);

        return log_set_max_level_from_string(t);
}

static int bus_manager_append_n_names(DBusMessageIter *i, const char *property, void *data) {
        Manager *m = data;
        uint32_t u;

        assert(i);
        assert(property);
        assert(m);

        u = hashmap_size(m->units);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT32, &u))
                return -ENOMEM;

        return 0;
}

static int bus_manager_append_n_jobs(DBusMessageIter *i, const char *property, void *data) {
        Manager *m = data;
        uint32_t u;

        assert(i);
        assert(property);
        assert(m);

        u = hashmap_size(m->jobs);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT32, &u))
                return -ENOMEM;

        return 0;
}

static int bus_manager_append_progress(DBusMessageIter *i, const char *property, void *data) {
        double d;
        Manager *m = data;

        assert(i);
        assert(property);
        assert(m);

        if (dual_timestamp_is_set(&m->finish_timestamp))
                d = 1.0;
        else
                d = 1.0 - ((double) hashmap_size(m->jobs) / (double) m->n_installed_jobs);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_DOUBLE, &d))
                return -ENOMEM;

        return 0;
}

static const char *message_get_sender_with_fallback(DBusMessage *m) {
        const char *s;

        assert(m);

        if ((s = dbus_message_get_sender(m)))
                return s;

        /* When the message came in from a direct connection the
         * message will have no sender. We fix that here. */

        return ":no-sender";
}

static DBusHandlerResult bus_manager_message_handler(DBusConnection *connection, DBusMessage *message, void *data) {
        Manager *m = data;

        const BusProperty properties[] = {
                { "org.freedesktop.systemd1.Manager", "Version",       bus_property_append_string,    "s",  PACKAGE_STRING     },
                { "org.freedesktop.systemd1.Manager", "Distribution",  bus_property_append_string,    "s",  DISTRIBUTION       },
                { "org.freedesktop.systemd1.Manager", "Features",      bus_property_append_string,    "s",  SYSTEMD_FEATURES   },
                { "org.freedesktop.systemd1.Manager", "RunningAs",     bus_manager_append_running_as, "s",  &m->running_as     },
                { "org.freedesktop.systemd1.Manager", "Tainted",       bus_manager_append_tainted,    "s",  m                  },
                { "org.freedesktop.systemd1.Manager", "InitRDTimestamp", bus_property_append_uint64,  "t",  &m->initrd_timestamp.realtime },
                { "org.freedesktop.systemd1.Manager", "InitRDTimestampMonotonic", bus_property_append_uint64, "t", &m->initrd_timestamp.monotonic },
                { "org.freedesktop.systemd1.Manager", "StartupTimestamp", bus_property_append_uint64, "t",  &m->startup_timestamp.realtime },
                { "org.freedesktop.systemd1.Manager", "StartupTimestampMonotonic", bus_property_append_uint64, "t", &m->startup_timestamp.monotonic },
                { "org.freedesktop.systemd1.Manager", "FinishTimestamp", bus_property_append_uint64,  "t",  &m->finish_timestamp.realtime },
                { "org.freedesktop.systemd1.Manager", "FinishTimestampMonotonic", bus_property_append_uint64, "t",&m->finish_timestamp.monotonic },
                { "org.freedesktop.systemd1.Manager", "LogLevel",      bus_manager_append_log_level,  "s",  m, bus_manager_set_log_level },
                { "org.freedesktop.systemd1.Manager", "LogTarget",     bus_manager_append_log_target, "s",  m, bus_manager_set_log_target },
                { "org.freedesktop.systemd1.Manager", "NNames",        bus_manager_append_n_names,    "u",  m                  },
                { "org.freedesktop.systemd1.Manager", "NJobs",         bus_manager_append_n_jobs,     "u",  m                  },
                { "org.freedesktop.systemd1.Manager", "NInstalledJobs",bus_property_append_uint32,    "u",  &m->n_installed_jobs },
                { "org.freedesktop.systemd1.Manager", "NFailedJobs",   bus_property_append_uint32,    "u",  &m->n_failed_jobs  },
                { "org.freedesktop.systemd1.Manager", "Progress",      bus_manager_append_progress,   "d",  m                  },
                { "org.freedesktop.systemd1.Manager", "Environment",   bus_property_append_strv,      "as", m->environment     },
                { "org.freedesktop.systemd1.Manager", "ConfirmSpawn",  bus_property_append_bool,      "b",  &m->confirm_spawn  },
                { "org.freedesktop.systemd1.Manager", "ShowStatus",    bus_property_append_bool,      "b",  &m->show_status    },
                { "org.freedesktop.systemd1.Manager", "UnitPath",      bus_property_append_strv,      "as", m->lookup_paths.unit_path },
                { "org.freedesktop.systemd1.Manager", "NotifySocket",  bus_property_append_string,    "s",  m->notify_socket   },
                { "org.freedesktop.systemd1.Manager", "ControlGroupHierarchy", bus_property_append_string, "s", m->cgroup_hierarchy },
                { "org.freedesktop.systemd1.Manager", "MountAuto",     bus_property_append_bool,      "b",  &m->mount_auto     },
                { "org.freedesktop.systemd1.Manager", "SwapAuto",      bus_property_append_bool,      "b",  &m->swap_auto      },
                { "org.freedesktop.systemd1.Manager", "DefaultControllers", bus_property_append_strv, "as", m->default_controllers },
                { "org.freedesktop.systemd1.Manager", "DefaultStandardOutput", bus_manager_append_exec_output, "s", &m->default_std_output },
                { "org.freedesktop.systemd1.Manager", "DefaultStandardError",  bus_manager_append_exec_output, "s", &m->default_std_error  },
#ifdef HAVE_SYSV_COMPAT
                { "org.freedesktop.systemd1.Manager", "SysVConsole",   bus_property_append_bool,      "b",  &m->sysv_console   },
                { "org.freedesktop.systemd1.Manager", "SysVInitPath",  bus_property_append_strv,      "as", m->lookup_paths.sysvinit_path },
                { "org.freedesktop.systemd1.Manager", "SysVRcndPath",  bus_property_append_strv,      "as", m->lookup_paths.sysvrcnd_path },
#endif
                { NULL, NULL, NULL, NULL, NULL }
        };

        int r;
        DBusError error;
        DBusMessage *reply = NULL;
        char * path = NULL;
        JobType job_type = _JOB_TYPE_INVALID;
        bool reload_if_possible = false;

        assert(connection);
        assert(message);
        assert(m);

        dbus_error_init(&error);

        if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "GetUnit")) {
                const char *name;
                Unit *u;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (!(u = manager_get_unit(m, name))) {
                        dbus_set_error(&error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s is not loaded.", name);
                        return bus_send_error_reply(connection, message, &error, -ENOENT);
                }

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                if (!(path = unit_dbus_path(u)))
                        goto oom;

                if (!dbus_message_append_args(
                                    reply,
                                    DBUS_TYPE_OBJECT_PATH, &path,
                                    DBUS_TYPE_INVALID))
                        goto oom;
        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "GetUnitByPID")) {
                Unit *u;
                uint32_t pid;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_UINT32, &pid,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (!(u = cgroup_unit_by_pid(m, (pid_t) pid))) {
                        dbus_set_error(&error, BUS_ERROR_NO_SUCH_UNIT, "No unit for PID %lu is loaded.", (unsigned long) pid);
                        return bus_send_error_reply(connection, message, &error, -ENOENT);
                }

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                if (!(path = unit_dbus_path(u)))
                        goto oom;

                if (!dbus_message_append_args(
                                    reply,
                                    DBUS_TYPE_OBJECT_PATH, &path,
                                    DBUS_TYPE_INVALID))
                        goto oom;
        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "LoadUnit")) {
                const char *name;
                Unit *u;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if ((r = manager_load_unit(m, name, NULL, &error, &u)) < 0)
                        return bus_send_error_reply(connection, message, &error, r);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                if (!(path = unit_dbus_path(u)))
                        goto oom;

                if (!dbus_message_append_args(
                                    reply,
                                    DBUS_TYPE_OBJECT_PATH, &path,
                                    DBUS_TYPE_INVALID))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "StartUnit"))
                job_type = JOB_START;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "StartUnitReplace"))
                job_type = JOB_START;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "StopUnit"))
                job_type = JOB_STOP;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "ReloadUnit"))
                job_type = JOB_RELOAD;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "RestartUnit"))
                job_type = JOB_RESTART;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "TryRestartUnit"))
                job_type = JOB_TRY_RESTART;
        else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "ReloadOrRestartUnit")) {
                reload_if_possible = true;
                job_type = JOB_RESTART;
        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "ReloadOrTryRestartUnit")) {
                reload_if_possible = true;
                job_type = JOB_TRY_RESTART;
        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "KillUnit")) {
                const char *name, *swho, *smode;
                int32_t signo;
                Unit *u;
                KillMode mode;
                KillWho who;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_STRING, &swho,
                                    DBUS_TYPE_STRING, &smode,
                                    DBUS_TYPE_INT32, &signo,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if ((mode = kill_mode_from_string(smode)) < 0 ||
                    (who = kill_who_from_string(swho)) < 0 ||
                    signo <= 0 ||
                    signo >= _NSIG)
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (!(u = manager_get_unit(m, name))) {
                        dbus_set_error(&error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s is not loaded.", name);
                        return bus_send_error_reply(connection, message, &error, -ENOENT);
                }

                if ((r = unit_kill(u, who, mode, signo, &error)) < 0)
                        return bus_send_error_reply(connection, message, &error, r);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "GetJob")) {
                uint32_t id;
                Job *j;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_UINT32, &id,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (!(j = manager_get_job(m, id))) {
                        dbus_set_error(&error, BUS_ERROR_NO_SUCH_JOB, "Job %u does not exist.", (unsigned) id);
                        return bus_send_error_reply(connection, message, &error, -ENOENT);
                }

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                if (!(path = job_dbus_path(j)))
                        goto oom;

                if (!dbus_message_append_args(
                                    reply,
                                    DBUS_TYPE_OBJECT_PATH, &path,
                                    DBUS_TYPE_INVALID))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "ClearJobs")) {

                manager_clear_jobs(m);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "ResetFailed")) {

                manager_reset_failed(m);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "ResetFailedUnit")) {
                const char *name;
                Unit *u;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (!(u = manager_get_unit(m, name))) {
                        dbus_set_error(&error, BUS_ERROR_NO_SUCH_UNIT, "Unit %s is not loaded.", name);
                        return bus_send_error_reply(connection, message, &error, -ENOENT);
                }

                unit_reset_failed(u);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "ListUnits")) {
                DBusMessageIter iter, sub;
                Iterator i;
                Unit *u;
                const char *k;

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(ssssssouso)", &sub))
                        goto oom;

                HASHMAP_FOREACH_KEY(u, k, m->units, i) {
                        char *u_path, *j_path;
                        const char *description, *load_state, *active_state, *sub_state, *sjob_type, *following;
                        DBusMessageIter sub2;
                        uint32_t job_id;
                        Unit *f;

                        if (k != u->meta.id)
                                continue;

                        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2))
                                goto oom;

                        description = unit_description(u);
                        load_state = unit_load_state_to_string(u->meta.load_state);
                        active_state = unit_active_state_to_string(unit_active_state(u));
                        sub_state = unit_sub_state_to_string(u);

                        f = unit_following(u);
                        following = f ? f->meta.id : "";

                        if (!(u_path = unit_dbus_path(u)))
                                goto oom;

                        if (u->meta.job) {
                                job_id = (uint32_t) u->meta.job->id;

                                if (!(j_path = job_dbus_path(u->meta.job))) {
                                        free(u_path);
                                        goto oom;
                                }

                                sjob_type = job_type_to_string(u->meta.job->type);
                        } else {
                                job_id = 0;
                                j_path = u_path;
                                sjob_type = "";
                        }

                        if (!dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &u->meta.id) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &description) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &load_state) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &active_state) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &sub_state) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &following) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &u_path) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_UINT32, &job_id) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &sjob_type) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &j_path)) {
                                free(u_path);
                                if (u->meta.job)
                                        free(j_path);
                                goto oom;
                        }

                        free(u_path);
                        if (u->meta.job)
                                free(j_path);

                        if (!dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "ListJobs")) {
                DBusMessageIter iter, sub;
                Iterator i;
                Job *j;

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(usssoo)", &sub))
                        goto oom;

                HASHMAP_FOREACH(j, m->jobs, i) {
                        char *u_path, *j_path;
                        const char *state, *type;
                        uint32_t id;
                        DBusMessageIter sub2;

                        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_STRUCT, NULL, &sub2))
                                goto oom;

                        id = (uint32_t) j->id;
                        state = job_state_to_string(j->state);
                        type = job_type_to_string(j->type);

                        if (!(j_path = job_dbus_path(j)))
                                goto oom;

                        if (!(u_path = unit_dbus_path(j->unit))) {
                                free(j_path);
                                goto oom;
                        }

                        if (!dbus_message_iter_append_basic(&sub2, DBUS_TYPE_UINT32, &id) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &j->unit->meta.id) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &type) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &state) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &j_path) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_OBJECT_PATH, &u_path)) {
                                free(j_path);
                                free(u_path);
                                goto oom;
                        }

                        free(j_path);
                        free(u_path);

                        if (!dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "Subscribe")) {
                char *client;
                Set *s;

                if (!(s = BUS_CONNECTION_SUBSCRIBED(m, connection))) {
                        if (!(s = set_new(string_hash_func, string_compare_func)))
                                goto oom;

                        if (!(dbus_connection_set_data(connection, m->subscribed_data_slot, s, NULL))) {
                                set_free(s);
                                goto oom;
                        }
                }

                if (!(client = strdup(message_get_sender_with_fallback(message))))
                        goto oom;

                if ((r = set_put(s, client)) < 0) {
                        free(client);
                        return bus_send_error_reply(connection, message, NULL, r);
                }

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "Unsubscribe")) {
                char *client;

                if (!(client = set_remove(BUS_CONNECTION_SUBSCRIBED(m, connection), (char*) message_get_sender_with_fallback(message)))) {
                        dbus_set_error(&error, BUS_ERROR_NOT_SUBSCRIBED, "Client is not subscribed.");
                        return bus_send_error_reply(connection, message, &error, -ENOENT);
                }

                free(client);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "Dump")) {
                FILE *f;
                char *dump = NULL;
                size_t size;

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                if (!(f = open_memstream(&dump, &size)))
                        goto oom;

                manager_dump_units(m, f, NULL);
                manager_dump_jobs(m, f, NULL);

                if (ferror(f)) {
                        fclose(f);
                        free(dump);
                        goto oom;
                }

                fclose(f);

                if (!dbus_message_append_args(reply, DBUS_TYPE_STRING, &dump, DBUS_TYPE_INVALID)) {
                        free(dump);
                        goto oom;
                }

                free(dump);
        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "CreateSnapshot")) {
                const char *name;
                dbus_bool_t cleanup;
                Snapshot *s;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_BOOLEAN, &cleanup,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (name && name[0] == 0)
                        name = NULL;

                if ((r = snapshot_create(m, name, cleanup, &error, &s)) < 0)
                        return bus_send_error_reply(connection, message, &error, r);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                if (!(path = unit_dbus_path(UNIT(s))))
                        goto oom;

                if (!dbus_message_append_args(
                                    reply,
                                    DBUS_TYPE_OBJECT_PATH, &path,
                                    DBUS_TYPE_INVALID))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.DBus.Introspectable", "Introspect")) {
                char *introspection = NULL;
                FILE *f;
                Iterator i;
                Unit *u;
                Job *j;
                const char *k;
                size_t size;

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                /* We roll our own introspection code here, instead of
                 * relying on bus_default_message_handler() because we
                 * need to generate our introspection string
                 * dynamically. */

                if (!(f = open_memstream(&introspection, &size)))
                        goto oom;

                fputs(INTROSPECTION_BEGIN, f);

                HASHMAP_FOREACH_KEY(u, k, m->units, i) {
                        char *p;

                        if (k != u->meta.id)
                                continue;

                        if (!(p = bus_path_escape(k))) {
                                fclose(f);
                                free(introspection);
                                goto oom;
                        }

                        fprintf(f, "<node name=\"unit/%s\"/>", p);
                        free(p);
                }

                HASHMAP_FOREACH(j, m->jobs, i)
                        fprintf(f, "<node name=\"job/%lu\"/>", (unsigned long) j->id);

                fputs(INTROSPECTION_END, f);

                if (ferror(f)) {
                        fclose(f);
                        free(introspection);
                        goto oom;
                }

                fclose(f);

                if (!introspection)
                        goto oom;

                if (!dbus_message_append_args(reply, DBUS_TYPE_STRING, &introspection, DBUS_TYPE_INVALID)) {
                        free(introspection);
                        goto oom;
                }

                free(introspection);

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "Reload")) {

                assert(!m->queued_message);

                /* Instead of sending the reply back right away, we
                 * just remember that we need to and then send it
                 * after the reload is finished. That way the caller
                 * knows when the reload finished. */

                if (!(m->queued_message = dbus_message_new_method_return(message)))
                        goto oom;

                m->queued_message_connection = connection;
                m->exit_code = MANAGER_RELOAD;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "Reexecute")) {

                /* We don't send a reply back here, the client should
                 * just wait for us disconnecting. */

                m->exit_code = MANAGER_REEXECUTE;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "Exit")) {

                if (m->running_as == MANAGER_SYSTEM) {
                        dbus_set_error(&error, BUS_ERROR_NOT_SUPPORTED, "Exit is only supported for user service managers.");
                        return bus_send_error_reply(connection, message, &error, -ENOTSUP);
                }

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                m->exit_code = MANAGER_EXIT;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "Reboot")) {

                if (m->running_as != MANAGER_SYSTEM) {
                        dbus_set_error(&error, BUS_ERROR_NOT_SUPPORTED, "Reboot is only supported for system managers.");
                        return bus_send_error_reply(connection, message, &error, -ENOTSUP);
                }

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                m->exit_code = MANAGER_REBOOT;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "PowerOff")) {

                if (m->running_as != MANAGER_SYSTEM) {
                        dbus_set_error(&error, BUS_ERROR_NOT_SUPPORTED, "Powering off is only supported for system managers.");
                        return bus_send_error_reply(connection, message, &error, -ENOTSUP);
                }

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                m->exit_code = MANAGER_POWEROFF;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "Halt")) {

                if (m->running_as != MANAGER_SYSTEM) {
                        dbus_set_error(&error, BUS_ERROR_NOT_SUPPORTED, "Halting is only supported for system managers.");
                        return bus_send_error_reply(connection, message, &error, -ENOTSUP);
                }

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                m->exit_code = MANAGER_HALT;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "KExec")) {

                if (m->running_as != MANAGER_SYSTEM) {
                        dbus_set_error(&error, BUS_ERROR_NOT_SUPPORTED, "kexec is only supported for system managers.");
                        return bus_send_error_reply(connection, message, &error, -ENOTSUP);
                }

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                m->exit_code = MANAGER_KEXEC;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "SetEnvironment")) {
                char **l = NULL, **e = NULL;

                if ((r = bus_parse_strv(message, &l)) < 0) {
                        if (r == -ENOMEM)
                                goto oom;

                        return bus_send_error_reply(connection, message, NULL, r);
                }

                e = strv_env_merge(2, m->environment, l);
                strv_free(l);

                if (!e)
                        goto oom;

                if (!(reply = dbus_message_new_method_return(message))) {
                        strv_free(e);
                        goto oom;
                }

                strv_free(m->environment);
                m->environment = e;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "UnsetEnvironment")) {
                char **l = NULL, **e = NULL;

                if ((r = bus_parse_strv(message, &l)) < 0) {
                        if (r == -ENOMEM)
                                goto oom;

                        return bus_send_error_reply(connection, message, NULL, r);
                }

                e = strv_env_delete(m->environment, 1, l);
                strv_free(l);

                if (!e)
                        goto oom;

                if (!(reply = dbus_message_new_method_return(message))) {
                        strv_free(e);
                        goto oom;
                }

                strv_free(m->environment);
                m->environment = e;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "UnsetAndSetEnvironment")) {
                char **l_set = NULL, **l_unset = NULL, **e = NULL, **f = NULL;
                DBusMessageIter iter;

                if (!dbus_message_iter_init(message, &iter))
                        return bus_send_error_reply(connection, message, NULL, -EINVAL);

                r = bus_parse_strv_iter(&iter, &l_unset);
                if (r < 0) {
                        if (r == -ENOMEM)
                                goto oom;

                        return bus_send_error_reply(connection, message, NULL, r);
                }

                if (!dbus_message_iter_next(&iter)) {
                        strv_free(l_unset);
                        return bus_send_error_reply(connection, message, NULL, -EINVAL);
                }

                r = bus_parse_strv_iter(&iter, &l_set);
                if (r < 0) {
                        strv_free(l_unset);
                        if (r == -ENOMEM)
                                goto oom;

                        return bus_send_error_reply(connection, message, NULL, r);
                }

                e = strv_env_delete(m->environment, 1, l_unset);
                strv_free(l_unset);

                if (!e) {
                        strv_free(l_set);
                        goto oom;
                }

                f = strv_env_merge(2, e, l_set);
                strv_free(l_set);
                strv_free(e);

                if (!f)
                        goto oom;

                if (!(reply = dbus_message_new_method_return(message))) {
                        strv_free(f);
                        goto oom;
                }

                strv_free(m->environment);
                m->environment = f;

        } else
                return bus_default_message_handler(connection, message, NULL, INTERFACES_LIST, properties);

        if (job_type != _JOB_TYPE_INVALID) {
                const char *name, *smode, *old_name = NULL;
                JobMode mode;
                Job *j;
                Unit *u;
                bool b;

                if (dbus_message_is_method_call(message, "org.freedesktop.systemd1.Manager", "StartUnitReplace"))
                        b = dbus_message_get_args(
                                        message,
                                        &error,
                                        DBUS_TYPE_STRING, &old_name,
                                        DBUS_TYPE_STRING, &name,
                                        DBUS_TYPE_STRING, &smode,
                                        DBUS_TYPE_INVALID);
                else
                        b = dbus_message_get_args(
                                        message,
                                        &error,
                                        DBUS_TYPE_STRING, &name,
                                        DBUS_TYPE_STRING, &smode,
                                        DBUS_TYPE_INVALID);

                if (!b)
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (old_name)
                        if (!(u = manager_get_unit(m, old_name)) ||
                            !u->meta.job ||
                            u->meta.job->type != JOB_START) {
                                dbus_set_error(&error, BUS_ERROR_NO_SUCH_JOB, "No job queued for unit %s", old_name);
                                return bus_send_error_reply(connection, message, &error, -ENOENT);
                        }


                if ((mode = job_mode_from_string(smode)) == _JOB_MODE_INVALID) {
                        dbus_set_error(&error, BUS_ERROR_INVALID_JOB_MODE, "Job mode %s is invalid.", smode);
                        return bus_send_error_reply(connection, message, &error, -EINVAL);
                }

                if ((r = manager_load_unit(m, name, NULL, &error, &u)) < 0)
                        return bus_send_error_reply(connection, message, &error, r);

                if (reload_if_possible && unit_can_reload(u)) {
                        if (job_type == JOB_RESTART)
                                job_type = JOB_RELOAD_OR_START;
                        else if (job_type == JOB_TRY_RESTART)
                                job_type = JOB_RELOAD;
                }

                if ((job_type == JOB_START && u->meta.refuse_manual_start) ||
                    (job_type == JOB_STOP && u->meta.refuse_manual_stop) ||
                    ((job_type == JOB_RESTART || job_type == JOB_TRY_RESTART) &&
                     (u->meta.refuse_manual_start || u->meta.refuse_manual_stop))) {
                        dbus_set_error(&error, BUS_ERROR_ONLY_BY_DEPENDENCY, "Operation refused, may be requested by dependency only.");
                        return bus_send_error_reply(connection, message, &error, -EPERM);
                }

                if ((r = manager_add_job(m, job_type, u, mode, true, &error, &j)) < 0)
                        return bus_send_error_reply(connection, message, &error, r);

                if (!(j->bus_client = strdup(message_get_sender_with_fallback(message))))
                        goto oom;

                j->bus = connection;

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                if (!(path = job_dbus_path(j)))
                        goto oom;

                if (!dbus_message_append_args(
                                    reply,
                                    DBUS_TYPE_OBJECT_PATH, &path,
                                    DBUS_TYPE_INVALID))
                        goto oom;
        }

        if (reply) {
                if (!dbus_connection_send(connection, reply, NULL))
                        goto oom;

                dbus_message_unref(reply);
        }

        free(path);

        return DBUS_HANDLER_RESULT_HANDLED;

oom:
        free(path);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

const DBusObjectPathVTable bus_manager_vtable = {
        .message_function = bus_manager_message_handler
};
