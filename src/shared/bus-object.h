/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdio.h>

#include "sd-bus.h"

typedef struct BusObjectImplementation BusObjectImplementation;

typedef struct BusObjectVtablePair {
        const sd_bus_vtable *vtable;
        sd_bus_object_find_t object_find;
} BusObjectVtablePair;

struct BusObjectImplementation {
        const char *path;
        const char *interface;
        const sd_bus_vtable **vtables;
        const BusObjectVtablePair *fallback_vtables;
        sd_bus_node_enumerator_t node_enumerator;
        bool manager;
        const BusObjectImplementation **children;
};

#define BUS_VTABLES(...) ((const sd_bus_vtable* []){ __VA_ARGS__, NULL })
#define BUS_FALLBACK_VTABLES(...) ((const BusObjectVtablePair[]) { __VA_ARGS__, {} })
#define BUS_IMPLEMENTATIONS(...) ((const BusObjectImplementation* []) { __VA_ARGS__, NULL })

int bus_add_implementation(sd_bus *bus, const BusObjectImplementation *impl, void *userdata);
int bus_introspect_implementations(
                FILE *out,
                const char *pattern,
                const BusObjectImplementation* const* bus_objects);
