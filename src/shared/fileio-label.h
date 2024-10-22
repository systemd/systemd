/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

/* These functions are split out of fileio.h (and not for example just flags to the functions they wrap) in order to
 * optimize linking: This way, -lselinux is needed only for the callers of these functions that need selinux, but not
 * for all */

#include "fileio.h"

int create_shutdown_run_nologin_or_warn(void);
