/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bus-internal.h"
#include "bus-introspect.h"

int bus_process_object(sd_bus *bus, sd_bus_message *m);
void bus_node_gc(sd_bus *b, struct node *n);

int introspect_path(
                sd_bus *bus,
                const char *path,
                struct node *n,
                bool require_fallback,
                bool ignore_nodes_modified,
                bool *found_object,
                char **ret,
                sd_bus_error *error);
