/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "macro.h"
#include "mp.h"

static inline void umaskp(mode_t *u) {
        umask(*u);
}

#define _cleanup_umask_ _cleanup_(umaskp)

#define RUN_WITH_UMASK(mask)                                            \
        MPP_DECLARE(1, _cleanup_umask_ mode_t _saved_umask_ = umask(mask))
