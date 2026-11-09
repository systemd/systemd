/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bus-forward.h"
#include "memstream-util.h"

typedef struct BusIntrospect {
        MemStream m;
        char *interface_name;
        bool trusted;
} BusIntrospect;

_sync_ int introspect_begin(BusIntrospect *i, bool trusted);
_sync_ int introspect_write_default_interfaces(BusIntrospect *i, bool object_manager);
_sync_ int introspect_write_child_nodes(BusIntrospect *i, OrderedSet *s, const char *prefix);
_sync_ int introspect_write_interface(
                BusIntrospect *i,
                const char *interface_name,
                const sd_bus_vtable *v);
_sync_ int introspect_finish(BusIntrospect *i, char **ret);
_sync_ void introspect_done(BusIntrospect *i);
