/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "bus-internal.h"

int bus_process_object(sd_bus *bus, sd_bus_message *m);
void bus_node_gc(sd_bus *b, struct node *n);
