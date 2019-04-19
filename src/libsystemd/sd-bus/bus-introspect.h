/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdio.h>

#include "sd-bus.h"

#include "set.h"

struct introspect {
        FILE *f;
        char *introspection;
        size_t size;
        bool trusted;
};

int introspect_begin(struct introspect *i, bool trusted);
int introspect_write_default_interfaces(struct introspect *i, bool object_manager);
int introspect_write_child_nodes(struct introspect *i, Set *s, const char *prefix);
int introspect_write_interface(struct introspect *i, const sd_bus_vtable *v);
int introspect_finish(struct introspect *i, char **ret);
void introspect_free(struct introspect *i);
