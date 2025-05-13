/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

pthread_mutex_t* pthread_mutex_lock_assert(pthread_mutex_t *mutex);

void pthread_mutex_unlock_assertp(pthread_mutex_t **mutexp);
