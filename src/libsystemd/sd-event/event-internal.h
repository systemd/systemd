/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "forward.h"

/* io_uring runs an operation that has to block, for example on a regular file, in a worker thread of the
 * process. While a worker thread exists, unshare(CLONE_NEWUSER) and setns() into a user or mount namespace
 * fail with EINVAL, and every worker thread counts against the task limit of the process. An event loop
 * therefore only uses io_uring after the program enabled it with event_set_use_io_uring(). */
void event_set_use_io_uring(sd_event *e, bool b);
bool event_io_uring_available(sd_event *e);
int event_get_wait_fd(sd_event *e);

/* Submits a copy of the SQE and resolves f with the res of its CQE. Internal only: handing out io_uring
 * SQEs comes with contracts (the buffers that the SQE references stay valid until the CQE arrives, and the
 * SQE posts exactly one CQE, so no multishot operations) that we can't support as a stable API across
 * kernels and opcodes. */
int event_add_io_uring_sqe(sd_event *e, const union io_uring_sqe128 *sqe, sd_future *f);
int event_cancel_io_uring_sqe(sd_event *e, sd_future *f);
