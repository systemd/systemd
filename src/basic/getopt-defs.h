/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <getopt.h>

#define SYSTEMD_GETOPT_SHORT_OPTIONS "hDbsz:"

#define COMMON_GETOPT_ARGS                      \
        ARG_LOG_LEVEL = 0x100,                  \
        ARG_LOG_TARGET,                         \
        ARG_LOG_COLOR,                          \
        ARG_LOG_LOCATION,                       \
        ARG_LOG_TIME

#define SYSTEMD_GETOPT_ARGS                     \
        ARG_UNIT,                               \
        ARG_SYSTEM,                             \
        ARG_USER,                               \
        ARG_TEST,                               \
        ARG_NO_PAGER,                           \
        ARG_VERSION,                            \
        ARG_DUMP_CONFIGURATION_ITEMS,           \
        ARG_DUMP_BUS_PROPERTIES,                \
        ARG_BUS_INTROSPECT,                     \
        ARG_DUMP_CORE,                          \
        ARG_CRASH_CHVT,                         \
        ARG_CRASH_SHELL,                        \
        ARG_CRASH_REBOOT,                       \
        ARG_CRASH_ACTION,                       \
        ARG_CONFIRM_SPAWN,                      \
        ARG_SHOW_STATUS,                        \
        ARG_DESERIALIZE,                        \
        ARG_SWITCHED_ROOT,                      \
        ARG_DEFAULT_STD_OUTPUT,                 \
        ARG_DEFAULT_STD_ERROR,                  \
        ARG_MACHINE_ID,                         \
        ARG_SERVICE_WATCHDOGS

#define SHUTDOWN_GETOPT_ARGS                    \
        ARG_EXIT_CODE,                          \
        ARG_TIMEOUT

#define COMMON_GETOPT_OPTIONS                                           \
        { "log-level",                required_argument, NULL, ARG_LOG_LEVEL                }, \
        { "log-target",               required_argument, NULL, ARG_LOG_TARGET               }, \
        { "log-color",                optional_argument, NULL, ARG_LOG_COLOR                }, \
        { "log-location",             optional_argument, NULL, ARG_LOG_LOCATION             }, \
        { "log-time",                 optional_argument, NULL, ARG_LOG_TIME                 }

#define SYSTEMD_GETOPT_OPTIONS                                          \
        { "unit",                     required_argument, NULL, ARG_UNIT                     }, \
        { "system",                   no_argument,       NULL, ARG_SYSTEM                   }, \
        { "user",                     no_argument,       NULL, ARG_USER                     }, \
        { "test",                     no_argument,       NULL, ARG_TEST                     }, \
        { "no-pager",                 no_argument,       NULL, ARG_NO_PAGER                 }, \
        { "help",                     no_argument,       NULL, 'h'                          }, \
        { "version",                  no_argument,       NULL, ARG_VERSION                  }, \
        { "dump-configuration-items", no_argument,       NULL, ARG_DUMP_CONFIGURATION_ITEMS }, \
        { "dump-bus-properties",      no_argument,       NULL, ARG_DUMP_BUS_PROPERTIES      }, \
        { "bus-introspect",           required_argument, NULL, ARG_BUS_INTROSPECT           }, \
        { "dump-core",                optional_argument, NULL, ARG_DUMP_CORE                }, \
        { "crash-chvt",               required_argument, NULL, ARG_CRASH_CHVT               }, \
        { "crash-shell",              optional_argument, NULL, ARG_CRASH_SHELL              }, \
        { "crash-reboot",             optional_argument, NULL, ARG_CRASH_REBOOT             }, \
        { "crash-action",             required_argument, NULL, ARG_CRASH_ACTION             }, \
        { "confirm-spawn",            optional_argument, NULL, ARG_CONFIRM_SPAWN            }, \
        { "show-status",              optional_argument, NULL, ARG_SHOW_STATUS              }, \
        { "deserialize",              required_argument, NULL, ARG_DESERIALIZE              }, \
        { "switched-root",            no_argument,       NULL, ARG_SWITCHED_ROOT            }, \
        { "default-standard-output",  required_argument, NULL, ARG_DEFAULT_STD_OUTPUT,      }, \
        { "default-standard-error",   required_argument, NULL, ARG_DEFAULT_STD_ERROR,       }, \
        { "machine-id",               required_argument, NULL, ARG_MACHINE_ID               }, \
        { "service-watchdogs",        required_argument, NULL, ARG_SERVICE_WATCHDOGS        }

#define SHUTDOWN_GETOPT_OPTIONS                                         \
        { "exit-code",                required_argument, NULL, ARG_EXIT_CODE    }, \
        { "timeout",                  required_argument, NULL, ARG_TIMEOUT      }
