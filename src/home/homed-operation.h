/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "user-record.h"

typedef enum OperationType {
        OPERATION_ACQUIRE,           /* enqueued on AcquireHome() */
        OPERATION_RELEASE,           /* enqueued on ReleaseHome() */
        OPERATION_LOCK_ALL,          /* enqueued on LockAllHomes() */
        OPERATION_DEACTIVATE_ALL,    /* enqueued on DeactivateAllHomes() */
        OPERATION_PIPE_EOF,          /* enqueued when we see EOF on the per-home reference pipes */
        OPERATION_DEACTIVATE_FORCE,  /* enqueued on hard $HOME unplug */
        OPERATION_IMMEDIATE,         /* this is never enqueued, it's just a marker we immediately started executing an operation without enqueuing anything first. */
        _OPERATION_MAX,
        _OPERATION_INVALID = -EINVAL,
} OperationType;

/* Encapsulates an operation on one or more home directories. This has two uses:
 *
 *     1) For queuing an operation when we need to execute one for some reason but there's already one being
 *        executed.
 *
 *     2) When executing an operation without enqueuing it first (OPERATION_IMMEDIATE)
 *
 * Note that a single operation object can encapsulate operations on multiple home directories. This is used
 * for the LockAllHomes() operation, which is one operation but applies to all homes at once. In case the
 * operation applies to multiple homes the reference counter is increased once for each, and thus the
 * operation is fully completed only after it reached zero again.
 *
 * The object (optionally) contains a reference of the D-Bus message triggering the operation, which is
 * replied to when the operation is fully completed, i.e. when n_ref reaches zero.
 */

typedef struct Operation {
        unsigned n_ref;
        OperationType type;
        sd_bus_message *message;

        UserRecord *secret;
        uint64_t call_flags; /* flags passed into UpdateEx() or CreateHomeEx() */
        int send_fd;   /* pipe fd for AcquireHome() which is taken already when we start the operation */

        int result;    /* < 0 if not completed yet, == 0 on failure, > 0 on success */
        sd_bus_error error;
        int ret;
} Operation;

Operation *operation_new(OperationType type, sd_bus_message *m);
Operation *operation_ref(Operation *operation);
Operation *operation_unref(Operation *operation);

DEFINE_TRIVIAL_CLEANUP_FUNC(Operation*, operation_unref);

void operation_result(Operation *o, int ret, const sd_bus_error *error);

static inline Operation* operation_result_unref(Operation *o, int ret, const sd_bus_error *error) {
        if (!o)
                return NULL;

        operation_result(o, ret, error);
        return operation_unref(o);
}
