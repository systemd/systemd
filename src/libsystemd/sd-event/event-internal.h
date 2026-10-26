/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "forward.h"

bool event_io_uring_available(sd_event *e);
int event_get_wait_fd(sd_event *e);

/* Submits a copy of the SQE and resolves f with the res of its CQE. Internal only: handing out io_uring
 * SQEs comes with contracts (the buffers that the SQE references stay valid until the CQE arrives, and the
 * SQE posts exactly one CQE, so no multishot operations) that we can't support as a stable API across
 * kernels and opcodes. */
int event_add_io_uring_sqe(sd_event *e, const struct io_uring_sqe *sqe, sd_future *f);
int event_cancel_io_uring_sqe(sd_event *e, sd_future *f);
