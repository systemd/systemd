/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#if HAVE_LIBCRYPTSETUP
#include <libcryptsetup.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(struct crypt_device *, crypt_free);

void cryptsetup_log_glue(int level, const char *msg, void *usrptr);
#endif
