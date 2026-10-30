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
 * verb section, where that COMMAND is found, and its option section. The options of the service
 * itself are defined in _service_parse_argv(), so the latter is empty (both symbols are NULL) for a
 * plain service, but a service that is part of a multicall binary which also implements commands
 * with options of their own needs it, so that those other commands can be described by
 * --introspect-cli.
 */
#define service_parse_argv(bus_objects, runtime_scope, argc, argv)      \
        _service_parse_argv(                                            \
                        __start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS,    \
                        __start_SYSTEMD_OPTIONS, __stop_SYSTEMD_OPTIONS, \
                        bus_objects, runtime_scope, argc, argv)
