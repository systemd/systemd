/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

/* wall_utmp and wall_logind are implementation details and should not be used directly.
 * We expose them so that the compiler doesn't give us "unused function" warnings. We
 * want both to be compiled if enabled even when we only use one of them in wall(),
 * in order to prevent things from bitrotting. */

#if ENABLE_UTMP
int wall_utmp(
        const char *message,
        bool (*match_tty)(const char *tty, bool is_local, void *userdata),
        void *userdata);
#endif

#if ENABLE_LOGIND
int wall_logind(
        const char *message,
        bool (*match_tty)(const char *tty, bool is_local, void *userdata),
        void *userdata);
#endif

int wall(
        const char *message,
        const char *username,
        const char *origin_tty,
        bool (*match_tty)(const char *tty, bool is_local, void *userdata),
        void *userdata);
