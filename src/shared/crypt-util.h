/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#if HAVE_LIBCRYPTSETUP
#include <libcryptsetup.h>

#include "macro.h"

/* These next two are defined in libcryptsetup.h from cryptsetup version 2.3.4 forwards. */
#ifndef CRYPT_ACTIVATE_NO_READ_WORKQUEUE
#define CRYPT_ACTIVATE_NO_READ_WORKQUEUE (1 << 24)
#endif
#ifndef CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE
#define CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE (1 << 25)
#endif

DEFINE_TRIVIAL_CLEANUP_FUNC(struct crypt_device *, crypt_free);

void cryptsetup_log_glue(int level, const char *msg, void *usrptr);
#endif
