/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "verbs.h"

int _service_parse_argv(
                const Verb *verbs,
                const Verb *verbs_end,
                const BusObjectImplementation* const* bus_objects,
                RuntimeScope *runtime_scope,
                int argc, char *argv[],
                char ***ret_args);

/* The service is expected to define a COMMAND() with .option_namespace = "service" and the option
 * groups matching the features it supports: "Options" always, "Bus introspection" iff bus_objects
 * is passed, "Runtime scope" iff runtime_scope is passed. The macro inserts the calling binary's
 * verb section, where that COMMAND is found, while the options are defined in _service_parse_argv().
 */
#define service_parse_argv(bus_objects, runtime_scope, argc, argv)      \
        _service_parse_argv(                                            \
                        __start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS,    \
                        bus_objects, runtime_scope, argc, argv,         \
                        /* ret_args= */ NULL)

/* For services that also offer verbs: positional arguments are returned to the caller for
 * dispatch_verb() instead of being rejected. The returned strv is a slice of argv. */
#define service_parse_argv_full(bus_objects, runtime_scope, argc, argv, ret_args) \
        _service_parse_argv(                                            \
                        __start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS,    \
                        bus_objects, runtime_scope, argc, argv, ret_args)
