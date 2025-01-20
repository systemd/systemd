/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/capability.h>
#include <sys/types.h>

#include "macro.h"
#include "missing_capability.h"
#include "pidref.h"

/* Special marker used when storing a capabilities mask as "unset". This would need to be updated as soon as
 * Linux learns more than 63 caps. */
#define CAP_MASK_UNSET UINT64_MAX
assert_cc(CAP_LAST_CAP < 64);

/* All possible capabilities bits on */
#define CAP_MASK_ALL UINT64_C(0x7fffffffffffffff)

/* The largest capability we can deal with, given we want to be able to store cap masks in uint64_t but still
 * be able to use UINT64_MAX as indicator for "not set". The latter makes capability 63 unavailable. */
#define CAP_LIMIT 62

static inline bool capability_is_set(uint64_t v) {
        return v != CAP_MASK_UNSET;
}

unsigned cap_last_cap(void);
int have_effective_cap(int value);
int capability_gain_cap_setpcap(cap_t *ret_before_caps);
int capability_bounding_set_drop(uint64_t keep, bool right_now);
int capability_bounding_set_drop_usermode(uint64_t keep);

int capability_ambient_set_apply(uint64_t set, bool also_inherit);
int capability_update_inherited_set(cap_t caps, uint64_t ambient_set);

int drop_privileges(uid_t uid, gid_t gid, uint64_t keep_capabilities);

int drop_capability(cap_value_t cv);
int keep_capability(cap_value_t cv);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(cap_t, cap_free, NULL);
#define _cleanup_cap_free_ _cleanup_(cap_freep)

static inline uint64_t all_capabilities(void) {
        return UINT64_MAX >> (63 - cap_last_cap());
}

static inline bool cap_test_all(uint64_t caps) {
        return FLAGS_SET(caps, all_capabilities());
}

/* Identical to linux/capability.h's CAP_TO_MASK(), but uses an unsigned 1U instead of a signed 1 for shifting left, in
 * order to avoid complaints about shifting a signed int left by 31 bits, which would make it negative. */
#define CAP_TO_MASK_CORRECTED(x) (1U << ((x) & 31U))

typedef struct CapabilityQuintet {
        /* Stores all five types of capabilities in one go. */
        uint64_t effective;
        uint64_t bounding;
        uint64_t inheritable;
        uint64_t permitted;
        uint64_t ambient;
} CapabilityQuintet;

#define CAPABILITY_QUINTET_NULL (const CapabilityQuintet) { CAP_MASK_UNSET, CAP_MASK_UNSET, CAP_MASK_UNSET, CAP_MASK_UNSET, CAP_MASK_UNSET }

static inline bool capability_quintet_is_set(const CapabilityQuintet *q) {
        return capability_is_set(q->effective) ||
                capability_is_set(q->bounding) ||
                capability_is_set(q->inheritable) ||
                capability_is_set(q->permitted) ||
                capability_is_set(q->ambient);
}

static inline bool capability_quintet_is_fully_set(const CapabilityQuintet *q) {
        return capability_is_set(q->effective) &&
                capability_is_set(q->bounding) &&
                capability_is_set(q->inheritable) &&
                capability_is_set(q->permitted) &&
                capability_is_set(q->ambient);
}

/* Mangles the specified caps quintet taking the current bounding set into account:
 * drops all caps from all five sets if our bounding set doesn't allow them.
 * Returns true if the quintet was modified. */
bool capability_quintet_mangle(CapabilityQuintet *q);

int capability_quintet_enforce(const CapabilityQuintet *q);

int capability_get_ambient(uint64_t *ret);

int pidref_get_capability(const PidRef *pidref, CapabilityQuintet *ret);
