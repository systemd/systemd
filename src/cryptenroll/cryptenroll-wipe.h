/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cryptenroll.h"
#include "cryptsetup-util.h"
#include "varlink.h"

int wipe_slots(struct crypt_device *cd,
               const int explicit_slots[],
               size_t n_explicit_slots,
               WipeScope by_scope,
               unsigned by_mask,
               int except_slot);

int vl_wipe_slots(Varlink *link,
                  JsonVariant *params,
                  struct crypt_device *cd,
                  int except_slot);

int vl_method_wipe(Varlink *link,
                   JsonVariant *params,
                   VarlinkMethodFlags flags,
                   void *userdata);

/* A set of JsonDispatch initializers that ignore fields used by vl_wipe_slots, to
 * avoid complaints about unexpected fields */
#define VARLINK_DISPATCH_WIPE_FIELDS                            \
        { .name = "wipeAll",   .type = JSON_VARIANT_BOOLEAN },  \
        { .name = "wipeEmpty", .type = JSON_VARIANT_BOOLEAN },  \
        { .name = "wipeType",  .type = JSON_VARIANT_STRING  },  \
        { .name = "wipeSlots", .type = JSON_VARIANT_ARRAY   }
