/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* The bus must have an attached event loop; otherwise return -ENOPKG. */
int bus_call_future(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_future **ret);
/* future_get_bus_reply() returns the future's result if that is negative, and copies the name and
 * message of an error reply into reterr_error. Otherwise it returns 1 with the reply. If the reply
 * carries fds that the bus does not accept, it returns -EBADMSG instead. As with sd_future_result(),
 * the future has to be resolved. */
int future_get_bus_reply(sd_future *f, sd_bus_error *reterr_error, sd_bus_message **ret_reply);

int bus_call_suspend(
                sd_bus *bus,
                sd_bus_message *m,
                uint64_t usec,
                sd_bus_error *reterr_error,
                sd_bus_message **ret_reply);
