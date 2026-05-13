/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sched.h>              /* IWYU pragma: export */

#include "basic-forward.h"

pid_t raw_clone(unsigned long flags);
