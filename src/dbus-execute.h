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

#define BUS_EXEC_STATUS_INTERFACE(prefix)                               \
        "  <property name=\"" prefix "StartTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"" prefix "ExitTimestamp\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"" prefix "PID\" type=\"u\" access=\"read\"/>\n" \
        "  <property name=\"" prefix "Code\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"" prefix "Status\" type=\"i\" access=\"read\"/>\n"

#define BUS_EXEC_CONTEXT_INTERFACE                                      \
        "  <property name=\"Environment\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"UMask\" type=\"u\" access=\"read\"/>\n"     \
        "  <property name=\"LimitCPU\" type=\"t\" access=\"read\"/>\n"  \
        "  <property name=\"LimitFSIZE\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitDATA\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitSTACK\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitCORE\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitRSS\" type=\"t\" access=\"read\"/>\n"  \
        "  <property name=\"LimitNOFILE\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitAS\" type=\"t\" access=\"read\"/>\n"   \
        "  <property name=\"LimitNPROC\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitMEMLOCK\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitLOCKS\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitSIGPENDING\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitMSGQUEUE\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitNICE\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitRTPRIO\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"LimitRTTIME\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"WorkingDirectory\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"RootDirectory\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"OOMAdjust\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"Nice\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"IOScheduling\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"CPUSchedulingPolicy\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"CPUSchedulingPriority\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"CPUAffinity\" type=\"ay\" access=\"read\"/>\n" \
        "  <property name=\"TimerSlackNS\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"CPUSchedulingResetOnFork\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"NonBlocking\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"StandardInput\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"StandardOutput\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"StandardError\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"TTYPath\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"SyslogPriority\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"SyslogIdentifier\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"SyslogNoPrefix\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"Capabilities\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"SecureBits\" type=\"i\" access=\"read\"/>\n" \
        "  <property name=\"CapabilityBoundingSetDrop\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"User\" type=\"s\" access=\"read\"/>\n"      \
        "  <property name=\"Group\" type=\"s\" access=\"read\"/>\n"     \
        "  <property name=\"SupplementaryGroups\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"TCPWrapName\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"PAMName\" type=\"s\" access=\"read\"/>\n"   \
        "  <property name=\"ReadWriteDirectories\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"ReadOnlyDirectories\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"InaccessibleDirectories\" type=\"as\" access=\"read\"/>\n" \
        "  <property name=\"MountFlags\" type=\"t\" access=\"read\"/>\n" \
        "  <property name=\"PrivateTmp\" type=\"b\" access=\"read\"/>\n" \
        "  <property name=\"NoSetSID\" type=\"b\" access=\"read\"/>\n"

#define BUS_EXEC_COMMAND_INTERFACE(name)                             \
        "  <property name=\"" name "\" type=\"a(sasttuii)\" access=\"read\"/>\n"

#define BUS_EXEC_CONTEXT_PROPERTIES(interface, context)                 \
        { interface, "Environment",                   bus_property_append_strv,   "as",    (context).environment                   }, \
        { interface, "UMask",                         bus_property_append_mode,   "u",     &(context).umask                        }, \
        { interface, "LimitCPU",                      bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitFSIZE",                    bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitDATA",                     bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitSTACK",                    bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitCORE",                     bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitRSS",                      bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitNOFILE",                   bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitAS",                       bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitNPROC",                    bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitMEMLOCK",                  bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitLOCKS",                    bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitSIGPENDING",               bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitMSGQUEUE",                 bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitNICE",                     bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitRTPRIO",                   bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "LimitRTTIME",                   bus_execute_append_rlimits, "t",     &(context)                              }, \
        { interface, "WorkingDirectory",              bus_property_append_string, "s",     (context).working_directory             }, \
        { interface, "RootDirectory",                 bus_property_append_string, "s",     (context).root_directory                }, \
        { interface, "OOMAdjust",                     bus_execute_append_oom_adjust, "i",  &(context)                              }, \
        { interface, "Nice",                          bus_execute_append_nice,    "i",     &(context)                              }, \
        { interface, "IOScheduling",                  bus_execute_append_ioprio,  "i",     &(context)                              }, \
        { interface, "CPUSchedulingPolicy",           bus_execute_append_cpu_sched_policy, "i", &(context)                         }, \
        { interface, "CPUSchedulingPriority",         bus_execute_append_cpu_sched_priority, "i", &(context)                       }, \
        { interface, "CPUAffinity",                   bus_execute_append_affinity,"ay",    &(context)                              }, \
        { interface, "TimerSlackNSec",                bus_execute_append_timer_slack_nsec, "t", &(context)                           }, \
        { interface, "CPUSchedulingResetOnFork",      bus_property_append_bool,   "b",     &(context).cpu_sched_reset_on_fork      }, \
        { interface, "NonBlocking",                   bus_property_append_bool,   "b",     &(context).non_blocking                 }, \
        { interface, "StandardInput",                 bus_execute_append_input,   "s",     &(context).std_input                    }, \
        { interface, "StandardOutput",                bus_execute_append_output,  "s",     &(context).std_output                   }, \
        { interface, "StandardError",                 bus_execute_append_output,  "s",     &(context).std_error                    }, \
        { interface, "TTYPath",                       bus_property_append_string, "s",     (context).tty_path                      }, \
        { interface, "SyslogPriority",                bus_property_append_int,    "i",     &(context).syslog_priority              }, \
        { interface, "SyslogIdentifier",              bus_property_append_string, "s",     (context).syslog_identifier             }, \
        { interface, "SyslogNoPrefix",                bus_property_append_bool,   "b",     &(context).syslog_no_prefix             }, \
        { interface, "Capabilities",                  bus_property_append_string, "s",     (context).capabilities                  }, \
        { interface, "SecureBits",                    bus_property_append_int,    "i",     &(context).secure_bits                  }, \
        { interface, "CapabilityBoundingSetDrop",     bus_property_append_uint64, "t",     &(context).capability_bounding_set_drop }, \
        { interface, "User",                          bus_property_append_string, "s",     (context).user                          }, \
        { interface, "Group",                         bus_property_append_string, "s",     (context).group                         }, \
        { interface, "SupplementaryGroups",           bus_property_append_strv,   "as",    (context).supplementary_groups          }, \
        { interface, "TCPWrapName",                   bus_property_append_string, "s",     (context).tcpwrap_name                  }, \
        { interface, "PAMName",                       bus_property_append_string, "s",     (context).pam_name                      }, \
        { interface, "ReadWriteDirectories",          bus_property_append_strv,   "as",    (context).read_write_dirs               }, \
        { interface, "ReadOnlyDirectories",           bus_property_append_strv,   "as",    (context).read_only_dirs                }, \
        { interface, "InaccessibleDirectories",       bus_property_append_strv,   "as",    (context).inaccessible_dirs             }, \
        { interface, "MountFlags",                    bus_property_append_ul,     "t",     &(context).mount_flags                  }, \
        { interface, "PrivateTmp",                    bus_property_append_bool,   "b",     &(context).private_tmp                  }, \
        { interface, "NoSetSID",                      bus_property_append_bool,   "b",     &(context).no_setsid                    }

#define BUS_EXEC_STATUS_PROPERTIES(interface, estatus, prefix)           \
        { interface, prefix "StartTimestamp",         bus_property_append_usec,   "t",     &(estatus).start_timestamp.realtime     }, \
        { interface, prefix "ExitTimestamp",          bus_property_append_usec,   "t",     &(estatus).start_timestamp.realtime     }, \
        { interface, prefix "PID",                    bus_property_append_pid,    "u",     &(estatus).pid                          }, \
        { interface, prefix "Code",                   bus_property_append_int,    "i",     &(estatus).code                         }, \
        { interface, prefix "Status",                 bus_property_append_int,    "i",     &(estatus).status                       }

#define BUS_EXEC_COMMAND_PROPERTY(interface, command, name)            \
        { interface, name, bus_execute_append_command, "a(sasttuii)", (command) }

int bus_execute_append_output(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_execute_append_input(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_execute_append_oom_adjust(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_execute_append_nice(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_execute_append_ioprio(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_execute_append_cpu_sched_policy(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_execute_append_cpu_sched_priority(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_execute_append_affinity(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_execute_append_timer_slack_nsec(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_execute_append_capabilities(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_execute_append_rlimits(Manager *m, DBusMessageIter *i, const char *property, void *data);
int bus_execute_append_command(Manager *m, DBusMessageIter *u, const char *property, void *data);

#endif
