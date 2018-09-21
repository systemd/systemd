/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"
#include "sd-event.h"

#include "hashmap.h"
#include "list.h"

typedef struct Manager Manager;

#include "portabled-operation.h"

struct Manager {
        sd_event *event;
        sd_bus *bus;

        Hashmap *polkit_registry;

        Hashmap *image_cache;
        sd_event_source *image_cache_defer_event;

        LIST_HEAD(Operation, operations);
        unsigned n_operations;
};
