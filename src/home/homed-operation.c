/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "fd-util.h"
#include "homed-operation.h"

Operation *operation_new(OperationType type, sd_bus_message *m) {
        Operation *o;

        assert(type >= 0);
        assert(type < _OPERATION_MAX);

        o = new(Operation, 1);
        if (!o)
                return NULL;

        *o = (Operation) {
                .type = type,
                .n_ref = 1,
                .message = sd_bus_message_ref(m),
                .send_fd = -EBADF,
                .result = -1,
        };

        return o;
}

Operation *operation_new_varlink(OperationType type, Varlink *v) {
        Operation *o;

        assert(type >= 0);
        assert(type <= _OPERATION_MAX);

        o = new(Operation, 1);
        if (!o)
                return NULL;

        *o = (Operation) {
                .type = type,
                .n_ref = 1,
                .varlink = varlink_ref(v),
                .send_fd = -EBADF,
                .result = -1,
        };

        return o;
}


static void operation_propagate_result(Operation *o) {
        int r;

        if (o->message) {
                if (o->result) {
                        /* Success */
                        if (o->send_fd < 0)
                                r = sd_bus_reply_method_return(o->message, NULL);
                        else
                                r = sd_bus_reply_method_return(o->message, "h", o->send_fd);
                } else {
                        /* Failure */
                        if (sd_bus_error_is_set(&o->error))
                                r = sd_bus_reply_method_error(o->message, &o->error);
                        else
                                r = sd_bus_reply_method_errnof(o->message, o->ret, "Failed to execute operation: %m");
                }
                if (r < 0)
                        log_warning_errno(r, "Failed to reply to %s method call, ignoring: %m", sd_bus_message_get_member(o->message));
        }

        if (o->varlink) {
                if (o->result) {
                        /* Success */
                        assert(o->send_fd == -EBADF); /* We don't support this via Varlink */
                        r = varlink_reply(o->varlink, NULL);
                } else {
                        /* Failure */
                        if (sd_bus_error_is_set(&o->error))
                                /* We can't pass an arbitrary message through Varlink, so let's at least log */
                                log_warning_errno(o->ret,
                                                  "Failed to execute operation for %s: %s",
                                                  varlink_get_current_method(o->varlink),
                                                  bus_error_message(&o->error, o->ret));
                        r = varlink_error_errno(o->varlink, o->ret);
                }
                if (r < 0)
                        log_warning_errno(r,
                                          "Failed to reply to %s varlink call, ignoring: %m",
                                          varlink_get_current_method(o->varlink));
        }
}

static Operation *operation_free(Operation *o) {
        if (!o)
                return NULL;

        if (o->result >= 0)
                operation_propagate_result(o);

        sd_bus_message_unref(o->message);
        varlink_unref(o->varlink);
        user_record_unref(o->secret);
        safe_close(o->send_fd);
        sd_bus_error_free(&o->error);

        return mfree(o);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Operation, operation, operation_free);

void operation_result(Operation *o, int ret, const sd_bus_error *error) {
        assert(o);

        if (ret >= 0)
                o->result = true;
        else {
                o->ret = ret;

                sd_bus_error_free(&o->error);
                sd_bus_error_copy(&o->error, error);

                o->result = false;
        }
}
