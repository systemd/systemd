/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "basic-forward.h"

int dlopen_io_uring(int log_level);

#if HAVE_LIBURING
#include <liburing.h> /* IWYU pragma: export */

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(io_uring_queue_init_params);
extern DLSYM_PROTOTYPE(io_uring_queue_exit);
extern DLSYM_PROTOTYPE(io_uring_submit);
extern DLSYM_PROTOTYPE(io_uring_submit_and_wait_timeout);
extern DLSYM_PROTOTYPE(io_uring_get_probe_ring);
extern DLSYM_PROTOTYPE(io_uring_free_probe);
#endif
