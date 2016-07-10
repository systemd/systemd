/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "alloc-util.h"
#include "fd-util.h"
#include "operation.h"
#include "process-util.h"

static int operation_done(sd_event_source *s, const siginfo_t *si, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        Operation *o = userdata;
        int r;

        assert(o);
        assert(si);

        log_debug("Operating " PID_FMT " is now complete with code=%s status=%i",
                  o->pid,
                  sigchld_code_to_string(si->si_code), si->si_status);

        o->pid = 0;

        if (si->si_code != CLD_EXITED) {
                r = sd_bus_error_setf(&error, SD_BUS_ERROR_FAILED, "Child died abnormally.");
                goto fail;
        }

        if (si->si_status == EXIT_SUCCESS)
                r = 0;
        else if (read(o->errno_fd, &r, sizeof(r)) != sizeof(r)) { /* Try to acquire error code for failed operation */
                r = sd_bus_error_setf(&error, SD_BUS_ERROR_FAILED, "Child failed.");
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
                if (r < 0)
                        goto fail;

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

int operation_new(Manager *manager, Machine *machine, pid_t child, sd_bus_message *message, int errno_fd, Operation **ret) {
        Operation *o;
        int r;

        assert(manager);
        assert(child > 1);
        assert(message);
        assert(errno_fd >= 0);

        o = new0(Operation, 1);
        if (!o)
                return -ENOMEM;

        o->extra_fd = -1;

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

        if (machine) {
                LIST_PREPEND(operations_by_machine, machine->operations, o);
                o->machine = machine;
        }

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

        if (o->machine)
                LIST_REMOVE(operations_by_machine, o->machine->operations, o);

        free(o);
        return NULL;
}
