/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foodbusexecutehfoo
#define foodbusexecutehfoo

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

#include <dbus/dbus.h>

#include "manager.h"

#define BUS_EXEC_CONTEXT_INTERFACE                                      \
        "  <property name=\"Environment\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"UMask\" type=\"u\" access=\"read\"/>\n"     \
        "  <property name=\"WorkingDirectory\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"RootDirectory\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"CPUSchedulingResetOnFork\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"NonBlocking\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"StandardInput\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"StandardOutput\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"StandardError\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"TTYPath\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"SyslogPriority\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"SyslogIdentifier\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"SecureBits\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"CapabilityBoundingSetDrop\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"User\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Group\" type=\"s\" access=\"read\"/>\n"     \
        "  <property name=\"SupplementaryGroups\" type=\"as\" access=\"read\"/>\n"

#define BUS_EXEC_CONTEXT_PROPERTIES(interface, context)                 \
        { interface, "Environment",                   bus_property_append_strv,   "as",    (context).environment                   }, \
        { interface, "UMask",                         bus_property_append_mode,   "u",     &(context).umask                        }, \
            /* RLimits */                                               \
        { interface, "WorkingDirectory",              bus_property_append_string, "s",     (context).working_directory             }, \
        { interface, "RootDirectory",                 bus_property_append_string, "s",     (context).root_directory                }, \
            /* OOM Adjust */                                            \
            /* Nice */                                                  \
            /* IOPrio */                                                \
            /* CPUSchedPolicy */                                        \
            /* CPUSchedPriority */                                      \
            /* CPUAffinity */                                           \
            /* TimerSlackNS */                                          \
        { interface, "CPUSchedulingResetOnFork",      bus_property_append_bool,   "b",     &(context).cpu_sched_reset_on_fork      }, \
        { interface, "NonBlocking",                   bus_property_append_bool,   "b",     &(context).non_blocking                 }, \
        { interface, "StandardInput",                 bus_execute_append_input,   "s",     &(context).std_input                    }, \
        { interface, "StandardOutput",                bus_execute_append_output,  "s",     &(context).std_output                   }, \
        { interface, "StandardError",                 bus_execute_append_output,  "s",     &(context).std_error                    }, \
        { interface, "TTYPath",                       bus_property_append_string, "s",     (context).tty_path                      }, \
        { interface, "SyslogPriority",                bus_property_append_int,    "i",     &(context).syslog_priority              }, \
        { interface, "SyslogIdentifier",              bus_property_append_string, "s",     (context).syslog_identifier             }, \
            /* CAPABILITIES */                                          \
        { interface, "SecureBits",                    bus_property_append_int,    "i",     &(context).secure_bits                  }, \
        { interface, "CapabilityBoundingSetDrop",     bus_property_append_uint64, "t",     &(context).capability_bounding_set_drop }, \
        { interface, "User",                          bus_property_append_string, "s",     (context).user                          }, \
        { interface, "Group",                         bus_property_append_string, "s",     (context).group                         }, \
        { interface, "SupplementaryGroups",           bus_property_append_strv,   "as",    (context).supplementary_groups          }

int bus_execute_append_output(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_execute_append_input(Manager *m, DBusMessageIter *i, const char *property, void *data);

#endif
