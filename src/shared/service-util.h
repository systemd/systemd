/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "verbs.h"

int _service_parse_argv(
                const Verb *verbs,
                const Verb *verbs_end,
                const BusObjectImplementation* const* bus_objects,
                RuntimeScope *runtime_scope,
                int argc, char *argv[]);

/* The service is expected to define a COMMAND() with .option_namespace = "service" and the option
 * groups matching the features it supports: "Options" always, "Bus introspection" iff bus_objects
 * is passed, "Runtime scope" iff runtime_scope is passed. The macro inserts the calling binary's
 * verb section, where that COMMAND is found, while the options are defined in _service_parse_argv().
 */
#define service_parse_argv(bus_objects, runtime_scope, argc, argv)      \
        _service_parse_argv(                                            \
                        __start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS,    \
                        bus_objects, runtime_scope, argc, argv)
