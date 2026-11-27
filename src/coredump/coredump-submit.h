/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "coredump-forward.h"

bool coredump_submit_can_use_records(const CoredumpConfig *config);
int coredump_submit(const CoredumpConfig *config, CoredumpContext *context);
