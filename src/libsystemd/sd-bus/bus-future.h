/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* The bus must have an attached event loop; otherwise return -ENOPKG. */
int bus_call_future(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_future **ret);
/* -EAGAIN while the call is pending, the future's result if it is negative (with the error reply's
 * detail in reterr_error where there is one), and 1 with the reply otherwise. */
int future_get_bus_reply(sd_future *f, sd_bus_error *reterr_error, sd_bus_message **ret_reply);

int bus_call_suspend(
                sd_bus *bus,
                sd_bus_message *m,
                uint64_t usec,
                sd_bus_error *reterr_error,
                sd_bus_message **ret_reply);
