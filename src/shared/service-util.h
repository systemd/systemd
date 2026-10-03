/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "verbs.h"

int _service_parse_argv(
                const Verb *verbs,
                const Verb *verbs_end,
                const Option *options,
                const Option *options_end,
                const BusObjectImplementation* const* bus_objects,
                RuntimeScope *runtime_scope,
                int argc, char *argv[]);

/* The service is expected to define a COMMAND() with .option_namespace = "service" and the option
 * groups matching the features it supports: "Options" always, "Bus introspection" iff bus_objects
 * is passed, "Runtime scope" iff runtime_scope is passed. The macro inserts the calling binary's
 * verb section, where that COMMAND is found, while the options are defined in _service_parse_argv().
 * A plain service has no option section of its own, so none is passed.
 */
#define service_parse_argv(bus_objects, runtime_scope, argc, argv)      \
        _service_parse_argv(                                            \
                        __start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS,    \
                        /* options= */ NULL, /* options_end= */ NULL,   \
                        bus_objects, runtime_scope, argc, argv)

/* A variant for services that are part of a multicall binary which also implements commands with
 * options of their own. The calling binary's option section is inserted too, so that those other
 * commands can be described by --introspect-cli. */
#define service_parse_argv_multicall(bus_objects, runtime_scope, argc, argv) \
        _service_parse_argv(                                            \
                        __start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS,    \
                        __start_SYSTEMD_OPTIONS, __stop_SYSTEMD_OPTIONS, \
                        bus_objects, runtime_scope, argc, argv)
