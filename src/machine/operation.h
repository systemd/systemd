/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "machine-forward.h"

#define OPERATIONS_MAX 64

typedef struct Operation {
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
} Operation;

int operation_new(Manager *manager, Machine *machine, pid_t child, int errno_fd, Operation **ret);
Operation *operation_free(Operation *o);

void operation_attach_bus_reply(Operation *op, sd_bus_message *message);
void operation_attach_varlink_reply(Operation *op, sd_varlink *link);

static inline int operation_new_with_bus_reply(
                Manager *manager,
                Machine *machine,
                pid_t child,
                sd_bus_message *message,
                int errno_fd,
                Operation **ret) {

        Operation *op;
        int r;

        r = operation_new(manager, machine, child, errno_fd, &op);
        if (r < 0)
                return r;

        operation_attach_bus_reply(op, message);

        if (ret)
                *ret = op;

        return 0;
}

static inline int operation_new_with_varlink_reply(
                Manager *manager,
                Machine *machine,
                pid_t child,
                sd_varlink *link,
                int errno_fd,
                Operation **ret) {

        Operation *op;
        int r;

        r = operation_new(manager, machine, child, errno_fd, &op);
        if (r < 0)
                return r;

        operation_attach_varlink_reply(op, link);

        if (ret)
                *ret = op;

        return 0;
}
