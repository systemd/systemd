/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

bool future_has_waiter(sd_future *f, sd_future *waiter);
