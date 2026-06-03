/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

int bus_call_future(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_future **ret);
int future_get_bus_reply(sd_future *f, sd_bus_error *reterr_error, sd_bus_message **ret_reply);

int bus_call_suspend(
                sd_bus *bus,
                sd_bus_message *m,
                uint64_t usec,
                sd_bus_error *reterr_error,
                sd_bus_message **ret_reply);

/* Subscribe to a bus signal and feed every match into a freshly-allocated channel as
 * sd_bus_message refs. The channel owns the bus match slot via sd_channel_set_slot, so
 * sd_channel_close (or the final unref) tears down the subscription automatically.
 * capacity bounds the buffer; overflow signals are logged and dropped. If the async
 * AddMatch fails, the channel is closed so consumers see -EPIPE. */
int bus_signal_channel_new(
                sd_bus *bus,
                const char *sender,
                const char *path,
                const char *interface,
                const char *member,
                size_t capacity,
                sd_channel **ret);
