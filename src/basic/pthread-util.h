/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <pthread.h>

#include "macro.h"

static inline pthread_mutex_t* pthread_mutex_lock_assert(pthread_mutex_t *mutex) {
        assert_se(pthread_mutex_lock(mutex) == 0);
        return mutex;
}

static inline void pthread_mutex_unlock_assertp(pthread_mutex_t **mutexp) {
        if (*mutexp)
                assert_se(pthread_mutex_unlock(*mutexp) == 0);
}
