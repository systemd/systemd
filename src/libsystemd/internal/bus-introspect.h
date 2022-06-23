/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "sd-bus.h"
#include "sd-bus-vtable.h"

#include "ordered-set.h"

bool bus_vtable_has_names(const sd_bus_vtable *vtable);

static inline const sd_bus_vtable* bus_vtable_next(const sd_bus_vtable *vtable, const sd_bus_vtable *v) {
        return (const sd_bus_vtable*) ((char*) v + vtable[0].x.start.element_size);
}

struct introspect {
        FILE *f;
        char *interface_name;
        char *introspection;
        size_t size;
        bool trusted;
};

int introspect_begin(struct introspect *i, bool trusted);
int introspect_write_default_interfaces(struct introspect *i, bool object_manager);
int introspect_write_child_nodes(struct introspect *i, OrderedSet *s, const char *prefix);
int introspect_write_interface(
                struct introspect *i,
                const char *interface_name,
                const sd_bus_vtable *v);
int introspect_finish(struct introspect *i, char **ret);
void introspect_free(struct introspect *i);
