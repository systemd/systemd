/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

#if HAVE_SELINUX
int mac_selinux_setup(bool *loaded_policy);
#else
static inline int mac_selinux_setup(bool *loaded_policy) {
        return 0;
}
#endif
