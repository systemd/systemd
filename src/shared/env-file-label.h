/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* These functions are split out of fileio.h (and not for example just flags to the functions they wrap) in order to
 * optimize linking: This way, -lselinux is needed only for the callers of these functions that need selinux, but not
 * for all */

int write_env_file_label(const char *fname, char **l);
