/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/wait.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "portabled.h"
#include "portabled-operation.h"
#include "process-util.h"

static int operation_done(sd_event_source *s, const siginfo_t *si, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Operation *o = ASSERT_PTR(userdata);
        int r;

        assert(si);

        log_debug("Operation " PID_FMT " is now complete with code=%s status=%i",
                  o->pid,
                  sigchld_code_to_string(si->si_code), si->si_status);

        o->pid = 0;

        if (si->si_code != CLD_EXITED) {
                r = sd_bus_error_set(&error, SD_BUS_ERROR_FAILED, "Child died abnormally.");
                goto fail;
        }

        if (si->si_status == EXIT_SUCCESS)
                r = 0;
        else if (read(o->errno_fd, &r, sizeof(r)) != sizeof(r)) { /* Try to acquire error code for failed operation */
                r = sd_bus_error_set(&error, SD_BUS_ERROR_FAILED, "Child failed.");
                goto fail;
        }

        if (o->done) {
                /* A completion routine is set for this operation, call it. */
                r = o->done(o, r, &error);
                if (r < 0) {
                        if (!sd_bus_error_is_set(&error))
                                sd_bus_error_set_errno(&error, r);

                        goto fail;
                }

        } else {
                /* The default operation when done is to simply return an error on failure or an empty success
                 * message on success. */
                if (r < 0) {
                        sd_bus_error_set_errno(&error, r);
                        goto fail;
                }

                r = sd_bus_reply_method_return(o->message, NULL);
                if (r < 0)
                        log_error_errno(r, "Failed to reply to message: %m");
        }

        operation_free(o);
        return 0;

fail:
        r = sd_bus_reply_method_error(o->message, &error);
        if (r < 0)
                log_error_errno(r, "Failed to reply to message: %m");

        operation_free(o);
        return 0;
}

int operation_new(Manager *manager, pid_t child, sd_bus_message *message, int errno_fd, Operation **ret) {
        Operation *o;
        int r;

        assert(manager);
        assert(child > 1);
        assert(message);
        assert(errno_fd >= 0);

        o = new0(Operation, 1);
        if (!o)
                return -ENOMEM;

        o->extra_fd = -EBADF;

        r = sd_event_add_child(manager->event, &o->event_source, child, WEXITED, operation_done, o);
        if (r < 0) {
                free(o);
                return r;
        }

        o->pid = child;
        o->message = sd_bus_message_ref(message);
        o->errno_fd = errno_fd;

        LIST_PREPEND(operations, manager->operations, o);
        manager->n_operations++;
        o->manager = manager;

        log_debug("Started new operation " PID_FMT ".", child);

        /* At this point we took ownership of both the child and the errno file descriptor! */

        if (ret)
                *ret = o;

        return 0;
}

Operation *operation_free(Operation *o) {
        if (!o)
                return NULL;

        sd_event_source_unref(o->event_source);

        safe_close(o->errno_fd);
        safe_close(o->extra_fd);

        if (o->pid > 1)
                (void) sigkill_wait(o->pid);

        sd_bus_message_unref(o->message);

        if (o->manager) {
                LIST_REMOVE(operations, o->manager->operations, o);
                o->manager->n_operations--;
        }

        return mfree(o);
}
