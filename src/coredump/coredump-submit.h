/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "coredump-forward.h"

int coredump_submit(const CoredumpConfig *config, CoredumpContext *context);
