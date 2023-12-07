/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct ImagePolicy ImagePolicy;

#include "conf-parser.h"
#include "dissect-image.h"
#include "errno-list.h"

typedef enum PartitionPolicyFlags {
        /* Not all policy flags really make sense on all partition types, see comments. But even if they
         * don't make sense we'll parse them anyway, because maybe one day we'll add them for more partition
         * types, too. Moreover, we allow configuring a "default" policy for all partition types for which no
         * explicit policy is specified. It's useful if we can use policy flags in there and apply this
         * default policy gracefully even to partition types where they don't really make too much sense
         * on. Example: a default policy of "verity+encrypted" certainly makes sense, but for /home/
         * partitions this gracefully degrades to "encrypted" (as we do not have a concept of verity for
         * /home/), and so on. */
        PARTITION_POLICY_VERITY               = 1 << 0, /* must exist, activate with verity                 (only applies to root/usr partitions) */
        PARTITION_POLICY_SIGNED               = 1 << 1, /* must exist, activate with signed verity          (only applies to root/usr partitions) */
        PARTITION_POLICY_ENCRYPTED            = 1 << 2, /* must exist, activate with LUKS encryption        (applies to any data partition, but not to verity/signature partitions */
        PARTITION_POLICY_UNPROTECTED          = 1 << 3, /* must exist, activate without encryption/verity */
        PARTITION_POLICY_UNUSED               = 1 << 4, /* must exist, don't use */
        PARTITION_POLICY_ABSENT               = 1 << 5, /* must not exist */
        PARTITION_POLICY_OPEN                 = PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED|
                                                PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_UNUSED|PARTITION_POLICY_ABSENT,
        PARTITION_POLICY_IGNORE               = PARTITION_POLICY_UNUSED|PARTITION_POLICY_ABSENT,
        _PARTITION_POLICY_USE_MASK            = PARTITION_POLICY_OPEN,

        PARTITION_POLICY_READ_ONLY_OFF        = 1 << 6, /* State of GPT partition flag "read-only" must be on */
        PARTITION_POLICY_READ_ONLY_ON         = 1 << 7,
        _PARTITION_POLICY_READ_ONLY_MASK      = PARTITION_POLICY_READ_ONLY_OFF|PARTITION_POLICY_READ_ONLY_ON,
        PARTITION_POLICY_GROWFS_OFF           = 1 << 8, /* State of GPT partition flag "growfs" must be on */
        PARTITION_POLICY_GROWFS_ON            = 1 << 9,
        _PARTITION_POLICY_GROWFS_MASK         = PARTITION_POLICY_GROWFS_OFF|PARTITION_POLICY_GROWFS_ON,
        _PARTITION_POLICY_PFLAGS_MASK         = _PARTITION_POLICY_READ_ONLY_MASK|_PARTITION_POLICY_GROWFS_MASK,

        _PARTITION_POLICY_MASK                = _PARTITION_POLICY_USE_MASK|_PARTITION_POLICY_READ_ONLY_MASK|_PARTITION_POLICY_GROWFS_MASK,

        _PARTITION_POLICY_FLAGS_INVALID       = -EINVAL,
        _PARTITION_POLICY_FLAGS_ERRNO_MAX     = -ERRNO_MAX, /* Ensure the whole errno range fits into this enum */
} PartitionPolicyFlags;

assert_cc((_PARTITION_POLICY_USE_MASK | _PARTITION_POLICY_PFLAGS_MASK) >= 0); /* ensure flags don't collide with errno range */

typedef struct PartitionPolicy {
        PartitionDesignator designator;
        PartitionPolicyFlags flags;
} PartitionPolicy;

struct ImagePolicy {
        PartitionPolicyFlags default_flags;  /* for any designator not listed in the list below */
        size_t n_policies;
        PartitionPolicy policies[];          /* sorted by designator, hence suitable for binary search */
};

/* Default policies for various use cases */
extern const ImagePolicy image_policy_allow;
extern const ImagePolicy image_policy_deny;
extern const ImagePolicy image_policy_ignore;
extern const ImagePolicy image_policy_sysext;        /* No verity required */
extern const ImagePolicy image_policy_sysext_strict; /* Signed verity required */
extern const ImagePolicy image_policy_confext;       /* No verity required */
extern const ImagePolicy image_policy_container;
extern const ImagePolicy image_policy_service;
extern const ImagePolicy image_policy_host;

PartitionPolicyFlags image_policy_get(const ImagePolicy *policy, PartitionDesignator designator);
PartitionPolicyFlags image_policy_get_exhaustively(const ImagePolicy *policy, PartitionDesignator designator);

/* We want that the NULL image policy means "everything" allowed, hence use these simple accessors to make
 * NULL policies work reasonably */
static inline PartitionPolicyFlags image_policy_default(const ImagePolicy *policy) {
        return policy ? policy->default_flags : PARTITION_POLICY_OPEN;
}

static inline size_t image_policy_n_entries(const ImagePolicy *policy) {
        return policy ? policy->n_policies : 0;
}

PartitionPolicyFlags partition_policy_flags_extend(PartitionPolicyFlags flags);
PartitionPolicyFlags partition_policy_flags_reduce(PartitionPolicyFlags flags);

PartitionPolicyFlags partition_policy_flags_from_string(const char *s);
int partition_policy_flags_to_string(PartitionPolicyFlags flags, bool simplify, char **ret);

int image_policy_from_string(const char *s, ImagePolicy **ret);
int image_policy_to_string(const ImagePolicy *policy, bool simplify, char **ret);

/* Recognizes three special policies by equivalence */
bool image_policy_equiv_ignore(const ImagePolicy *policy);
bool image_policy_equiv_allow(const ImagePolicy *policy);
bool image_policy_equiv_deny(const ImagePolicy *policy);

bool image_policy_equal(const ImagePolicy *a, const ImagePolicy *b);       /* checks if defined the same way, i.e. has literally the same ruleset */
int image_policy_equivalent(const ImagePolicy *a, const ImagePolicy *b);   /* checks if the outcome is the same, i.e. for all partitions results in the same decisions. */

int image_policy_intersect(const ImagePolicy *a, const ImagePolicy *b, ImagePolicy **ret);

static inline ImagePolicy* image_policy_free(ImagePolicy *p) {
        return mfree(p);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(ImagePolicy*, image_policy_free);

CONFIG_PARSER_PROTOTYPE(config_parse_image_policy);
int parse_image_policy_argument(const char *s, ImagePolicy **policy);
