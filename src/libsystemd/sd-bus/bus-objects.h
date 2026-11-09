/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bus-forward.h"

_sync_ const sd_bus_vtable* bus_vtable_next(const sd_bus_vtable *vtable, const sd_bus_vtable *v);
_sync_ bool bus_vtable_has_names(const sd_bus_vtable *vtable);
_may_suspend_ int bus_process_object(sd_bus *bus, sd_bus_message *m);
_sync_ void bus_node_gc(sd_bus *b, BusNode *n);

_sync_ int introspect_path(
                sd_bus *bus,
                const char *path,
                BusNode *n,
                bool require_fallback,
                bool ignore_nodes_modified,
                bool *found_object,
                char **ret,
                sd_bus_error *reterr_error);
