/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "portabled-forward.h"
#include "runtime-scope.h"

typedef struct Manager {
        sd_event *event;
        sd_bus *bus;

        Hashmap *polkit_registry;

        Hashmap *image_cache;
        sd_event_source *image_cache_defer_event;

        LIST_HEAD(Operation, operations);
        unsigned n_operations;

        RuntimeScope runtime_scope; /* for now always RUNTIME_SCOPE_SYSTEM */
} Manager;

extern const BusObjectImplementation manager_object;
