/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

int _nss_systemd_block(bool b);
bool _nss_systemd_is_blocked(void);

/* For use with the _cleanup_() macro */
static inline void _nss_systemd_unblockp(bool *b) {
        if (*b)
                assert_se(_nss_systemd_block(false) >= 0);
}
