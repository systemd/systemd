/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "bus-internal.h"

const sd_bus_vtable* bus_vtable_next(const sd_bus_vtable *vtable, const sd_bus_vtable *v);
bool bus_vtable_has_names(const sd_bus_vtable *vtable);
int bus_process_object(sd_bus *bus, sd_bus_message *m);
void bus_node_gc(sd_bus *b, struct node *n);
