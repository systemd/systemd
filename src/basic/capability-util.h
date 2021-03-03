/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/capability.h>
#include <sys/types.h>

#include "macro.h"
#include "missing_capability.h"
#include "util.h"

#define CAP_ALL UINT64_MAX

unsigned cap_last_cap(void);
int have_effective_cap(int value);
int capability_gain_cap_setpcap(cap_t *return_caps);
int capability_bounding_set_drop(uint64_t keep, bool right_now);
int capability_bounding_set_drop_usermode(uint64_t keep);

int capability_ambient_set_apply(uint64_t set, bool also_inherit);
int capability_update_inherited_set(cap_t caps, uint64_t ambient_set);

int drop_privileges(uid_t uid, gid_t gid, uint64_t keep_capabilities);

int drop_capability(cap_value_t cv);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(cap_t, cap_free, NULL);
#define _cleanup_cap_free_ _cleanup_(cap_freep)

static inline void cap_free_charpp(char **p) {
        if (*p)
                cap_free(*p);
}
#define _cleanup_cap_free_charp_ _cleanup_(cap_free_charpp)

static inline uint64_t all_capabilities(void) {
        return UINT64_MAX >> (63 - cap_last_cap());
}

static inline bool cap_test_all(uint64_t caps) {
        return FLAGS_SET(caps, all_capabilities());
}

bool ambient_capabilities_supported(void);

/* Identical to linux/capability.h's CAP_TO_MASK(), but uses an unsigned 1U instead of a signed 1 for shifting left, in
 * order to avoid complaints about shifting a signed int left by 31 bits, which would make it negative. */
#define CAP_TO_MASK_CORRECTED(x) (1U << ((x) & 31U))

typedef struct CapabilityQuintet {
        /* Stores all five types of capabilities in one go. Note that we use UINT64_MAX for unset here. This hence
         * needs to be updated as soon as Linux learns more than 63 caps. */
        uint64_t effective;
        uint64_t bounding;
        uint64_t inheritable;
        uint64_t permitted;
        uint64_t ambient;
} CapabilityQuintet;

assert_cc(CAP_LAST_CAP < 64);

#define CAPABILITY_QUINTET_NULL { UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX }

static inline bool capability_quintet_is_set(const CapabilityQuintet *q) {
        return q->effective != UINT64_MAX ||
                q->bounding != UINT64_MAX ||
                q->inheritable != UINT64_MAX ||
                q->permitted != UINT64_MAX ||
                q->ambient != UINT64_MAX;
}

/* Mangles the specified caps quintet taking the current bounding set into account:
 * drops all caps from all five sets if our bounding set doesn't allow them.
 * Returns true if the quintet was modified. */
bool capability_quintet_mangle(CapabilityQuintet *q);

int capability_quintet_enforce(const CapabilityQuintet *q);
