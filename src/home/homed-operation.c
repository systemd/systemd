/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
                .send_fd = -1,
                .result = -1,
        };

        return o;
}

static Operation *operation_free(Operation *o) {
        int r;

        if (!o)
                return NULL;

        if (o->message && o->result >= 0) {

                if (o->result) {
                        /* Propagate success */
                        if (o->send_fd < 0)
                                r = sd_bus_reply_method_return(o->message, NULL);
                        else
                                r = sd_bus_reply_method_return(o->message, "h", o->send_fd);

                } else {
                        /* Propagate failure */
                        if (sd_bus_error_is_set(&o->error))
                                r = sd_bus_reply_method_error(o->message, &o->error);
                        else
                                r = sd_bus_reply_method_errnof(o->message, o->ret, "Failed to execute operation: %m");
                }
                if (r < 0)
                        log_warning_errno(r, "Failed to reply to %s method call, ignoring: %m", sd_bus_message_get_member(o->message));
        }

        sd_bus_message_unref(o->message);
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
