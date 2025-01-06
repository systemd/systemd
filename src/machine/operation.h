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

int operation_new(Manager *manager, Machine *machine, pid_t child, int errno_fd, Operation **ret);
Operation *operation_free(Operation *o);

static inline void operation_attach_bus_reply(Operation *op, sd_bus_message *message) {
        assert(op);
        assert(!op->message);
        assert(!op->link);
        assert(message);

        op->message = sd_bus_message_ref(message);
}

static inline void operation_attach_varlink_reply(Operation *op, sd_varlink *link) {
        assert(op);
        assert(!op->message);
        assert(!op->link);
        assert(link);

        op->link = sd_varlink_ref(link);
}

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
