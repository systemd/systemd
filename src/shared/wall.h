/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

#if ENABLE_UTMP || ENABLE_LOGIND

/* Strips escape sequences and control characters from a message that is about to be broadcast to
 * other users' terminals. Returns NULL on allocation failure. */
char *wall_sanitize_message(const char *message);

int wall(
        const char *message,
        const char *username,
        const char *origin_tty,
        bool (*match_tty)(const char *tty, bool is_local, void *userdata),
        void *userdata);

#else

static inline int wall(
        const char *message,
        const char *username,
        const char *origin_tty,
        bool (*match_tty)(const char *tty, bool is_local, void *userdata),
        void *userdata) {

        return 0;
}

#endif
