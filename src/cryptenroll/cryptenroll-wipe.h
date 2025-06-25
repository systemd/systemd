/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum WipeScope WipeScope;

int wipe_slots(struct crypt_device *cd,
               const int explicit_slots[],
               size_t n_explicit_slots,
               WipeScope by_scope,
               unsigned by_mask,
               int except_slot);
