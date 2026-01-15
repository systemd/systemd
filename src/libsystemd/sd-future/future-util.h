/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

int future_new_child_pidref(sd_event *e, PidRef *pidref, int options, sd_future **ret);
