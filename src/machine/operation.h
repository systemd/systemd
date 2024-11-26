/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "list.h"

typedef struct Operation Operation;

#include "machined.h"

#define OPERATIONS_MAX 64

struct Operation {
        Manager *manager;
        Machine *machine;
        pid_t pid;

        /* only one of these two fields should be set */
        sd_varlink *link;
        sd_bus_message *message;

        int errno_fd;
        int extra_fd;
        sd_event_source *event_source;
        int (*done)(Operation *o, int ret, sd_bus_error *error);
        LIST_FIELDS(Operation, operations);
        LIST_FIELDS(Operation, operations_by_machine);
};

int operation_new(Manager *manager, Machine *machine, pid_t child, sd_bus_message *message, sd_varlink *link, int errno_fd, Operation **ret);
Operation *operation_free(Operation *o);
static inline int operation_new_with_bus_reply(Manager *manager, Machine *machine, pid_t child, sd_bus_message *message, int errno_fd, Operation **ret) {
        return operation_new(manager, machine, child, message, /* link = */ NULL, errno_fd, ret);
}
static inline int operation_new_with_varlink_reply(Manager *manager, Machine *machine, pid_t child, sd_varlink *link, int errno_fd, Operation **ret) {
        return operation_new(manager, machine, child, /* message = */ NULL, link, errno_fd, ret);
}
