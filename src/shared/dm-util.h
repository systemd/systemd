/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int dm_deferred_remove_cancel(const char *name);

int dm_create_linear(
                const char *name,
                const char *uuid,
                dev_t devnum,
                uint64_t offset,
                uint64_t size);
int dm_remove_device(const char *name);
