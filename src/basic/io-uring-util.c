/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-dlopen.h"

#include "io-uring-util.h"
#include "log.h" /* IWYU pragma: keep */

#if HAVE_LIBURING
DLSYM_PROTOTYPE(io_uring_queue_init_params) = NULL;
DLSYM_PROTOTYPE(io_uring_queue_exit) = NULL;
DLSYM_PROTOTYPE(io_uring_submit) = NULL;
DLSYM_PROTOTYPE(io_uring_submit_and_wait_timeout) = NULL;
DLSYM_PROTOTYPE(io_uring_get_probe_ring) = NULL;
DLSYM_PROTOTYPE(io_uring_free_probe) = NULL;
#endif

int dlopen_io_uring(int log_level) {
#if HAVE_LIBURING
        static void *io_uring_dl = NULL;

        SD_ELF_NOTE_DLOPEN(
                        "liburing",
                        "Support for the io_uring sd-event backend",
                        SD_ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "liburing.so.2");

        return dlopen_many_sym_or_warn(
                        &io_uring_dl,
                        "liburing.so.2", log_level,
                        DLSYM_ARG(io_uring_queue_init_params),
                        DLSYM_ARG(io_uring_queue_exit),
                        DLSYM_ARG(io_uring_submit),
                        DLSYM_ARG(io_uring_submit_and_wait_timeout),
                        DLSYM_ARG(io_uring_get_probe_ring),
                        DLSYM_ARG(io_uring_free_probe));
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "liburing support is not compiled in.");
#endif
}
