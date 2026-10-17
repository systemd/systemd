/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "dlopen-note.h"
#include "forward.h"

int dlopen_io_uring(int log_level) _dlopen_loader_;

#if HAVE_LIBURING
#ifndef SYSTEMD_CFLAGS_MARKER_LIBURING
#  error "missing liburing_cflags in meson dependency."
#endif

#include <liburing.h> /* IWYU pragma: export */

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(io_uring_queue_init_params);
extern DLSYM_PROTOTYPE(io_uring_queue_exit);
extern DLSYM_PROTOTYPE(io_uring_submit);
#endif
