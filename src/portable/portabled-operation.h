/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "portabled-forward.h"

#define OPERATIONS_MAX 64

typedef struct Operation {
        Manager *manager;
        pid_t pid;
        sd_bus_message *message;
        int errno_fd;
        int extra_fd;
        sd_event_source *event_source;
        int (*done)(Operation *o, int ret, sd_bus_error *error);
        LIST_FIELDS(Operation, operations);
} Operation;

int operation_new(Manager *manager, pid_t child, sd_bus_message *message, int errno_fd, Operation **ret);
Operation *operation_free(Operation *o);
