/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "extract-word.h"
#include "image-policy.h"
#include "logarithm.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"

/* Rationale for the chosen syntax:
 *
 * → one line, so that it can be reasonably added to a shell command line, for example via `systemd-dissect
 *   --image-policy=…` or to the kernel command line via `systemd.image_policy=`.
 *
 * → no use of "," or ";" as separators, so that it can be included in mount/fstab-style option strings and
 *   doesn't require escaping. Instead, separators are ":", "=", "+" which should be fine both in shell
 *   command lines and in mount/fstab style option strings.
 */

static int partition_policy_compare(const PartitionPolicy *a, const PartitionPolicy *b) {
        return CMP(ASSERT_PTR(a)->designator, ASSERT_PTR(b)->designator);
}

static const PartitionPolicy* image_policy_bsearch(const ImagePolicy *policy, PartitionDesignator designator) {
        if (!policy)
                return NULL;

        return typesafe_bsearch(
                        &(const PartitionPolicy) { .designator = designator },
                        ASSERT_PTR(policy)->policies,
                        ASSERT_PTR(policy)->n_policies,
                        partition_policy_compare);
}

PartitionPolicyFlags partition_policy_flags_extend(PartitionPolicyFlags flags) {
        /* If some parts of a flags field are left unspecified, let's fill in all options. */

        /* If no protection flag is set, then this means all are set */
        if ((flags & _PARTITION_POLICY_USE_MASK) == 0)
                flags |= PARTITION_POLICY_OPEN;

        /* If the gpt flags bits are not specified, set both options for each */
        if ((flags & _PARTITION_POLICY_READ_ONLY_MASK) == 0)
                flags |= PARTITION_POLICY_READ_ONLY_ON|PARTITION_POLICY_READ_ONLY_OFF;

        if ((flags & _PARTITION_POLICY_GROWFS_MASK) == 0)
                flags |= PARTITION_POLICY_GROWFS_ON|PARTITION_POLICY_GROWFS_OFF;

        return flags;
}

PartitionPolicyFlags partition_policy_flags_reduce(PartitionPolicyFlags flags) {
        /* The reverse of partition_policy_flags_extend(): if some parts of the flags field allow all
         * possible options, let's remove it from the flags to make them shorter */

        if (FLAGS_SET(flags, _PARTITION_POLICY_USE_MASK))
                flags &= ~_PARTITION_POLICY_USE_MASK;
        if (FLAGS_SET(flags, _PARTITION_POLICY_READ_ONLY_MASK))
                flags &= ~_PARTITION_POLICY_READ_ONLY_MASK;
        if (FLAGS_SET(flags, _PARTITION_POLICY_GROWFS_MASK))
                flags &= ~_PARTITION_POLICY_GROWFS_MASK;

        return flags;
}

static PartitionPolicyFlags partition_policy_normalized_flags(const PartitionPolicy *policy) {
        PartitionPolicyFlags flags = ASSERT_PTR(policy)->flags;

        /* This normalizes the per-partition policy flags. This means if the user left some things
         * unspecified, we'll fill in the appropriate "dontcare" policy instead. We'll also mask out bits
         * that do not make any sense for specific partition types. */

        flags = partition_policy_flags_extend(flags);

        /* If this is a verity or verity signature designator, then mask off all protection bits, this after
         * all needs no protection, because it *is* the protection */
        if (partition_verity_to_data(policy->designator) >= 0 ||
            partition_verity_sig_to_data(policy->designator) >= 0)
                flags &= ~(PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED);

        /* if this designator has no verity concept, then mask off verity protection flags */
        if (partition_verity_of(policy->designator) < 0)
                flags &= ~(PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED);

        /* If the partition must be absent, then the gpt flags don't matter */
        if ((flags & _PARTITION_POLICY_USE_MASK) == PARTITION_POLICY_ABSENT)
                flags &= ~(_PARTITION_POLICY_READ_ONLY_MASK|_PARTITION_POLICY_GROWFS_MASK);

        return flags;
}

PartitionPolicyFlags image_policy_get(const ImagePolicy *policy, PartitionDesignator designator) {
        PartitionDesignator data_designator = _PARTITION_DESIGNATOR_INVALID;
        const PartitionPolicy *pp;

        /* No policy means: everything may be used in any mode */
        if (!policy)
                return partition_policy_normalized_flags(
                                &(const PartitionPolicy) {
                                        .flags = PARTITION_POLICY_OPEN,
                                        .designator = designator,
                                });

        pp = image_policy_bsearch(policy, designator);
        if (pp)
                return partition_policy_normalized_flags(pp);

        /* Hmm, so this didn't work, then let's see if we can derive some policy from the underlying data
         * partition in case of verity/signature partitions */

        data_designator = partition_verity_to_data(designator);
        if (data_designator >= 0) {
                PartitionPolicyFlags data_flags;

                /* So we are asked for the policy for a verity partition, and there's no explicit policy for
                 * that case. Let's synthesize a policy from the protection setting for the underlying data
                 * partition. */

                data_flags = image_policy_get(policy, data_designator);
                if (data_flags < 0)
                        return data_flags;

                /* We need verity if verity or verity with sig is requested */
                if (!(data_flags & (PARTITION_POLICY_SIGNED|PARTITION_POLICY_VERITY)))
                        return _PARTITION_POLICY_FLAGS_INVALID;

                /* If the data partition may be unused or absent, then the verity partition may too. Also, inherit the partition flags policy */
                return partition_policy_normalized_flags(
                                &(const PartitionPolicy) {
                                        .flags = PARTITION_POLICY_UNPROTECTED | (data_flags & (PARTITION_POLICY_UNUSED|PARTITION_POLICY_ABSENT)) |
                                                 (data_flags & _PARTITION_POLICY_PFLAGS_MASK),
                                        .designator = designator,
                                });
        }

        data_designator = partition_verity_sig_to_data(designator);
        if (data_designator >= 0) {
                PartitionPolicyFlags data_flags;

                /* Similar case as for verity partitions, but slightly more strict rules */

                data_flags = image_policy_get(policy, data_designator);
                if (data_flags < 0)
                        return data_flags;

                if (!(data_flags & PARTITION_POLICY_SIGNED))
                        return _PARTITION_POLICY_FLAGS_INVALID;

                return partition_policy_normalized_flags(
                                &(const PartitionPolicy) {
                                        .flags = PARTITION_POLICY_UNPROTECTED | (data_flags & (PARTITION_POLICY_UNUSED|PARTITION_POLICY_ABSENT)) |
                                                 (data_flags & _PARTITION_POLICY_PFLAGS_MASK),
                                        .designator = designator,
                                });
        }

        return _PARTITION_POLICY_FLAGS_INVALID; /* got nothing */
}

PartitionPolicyFlags image_policy_get_exhaustively(const ImagePolicy *policy, PartitionDesignator designator) {
        PartitionPolicyFlags flags;

        /* This is just like image_policy_get() but whenever there is no policy for a specific designator, we
         * return the default policy. */

        flags = image_policy_get(policy, designator);
        if (flags < 0)
                return partition_policy_normalized_flags(
                                &(const PartitionPolicy) {
                                        .flags = image_policy_default(policy),
                                        .designator = designator,
                                });

        return flags;
}

static PartitionPolicyFlags policy_flag_from_string_one(const char *s) {
        assert(s);

        /* This is a bitmask (i.e. not dense), hence we don't use the "string-table.h" stuff here. */

        if (streq(s, "verity"))
                return PARTITION_POLICY_VERITY;
        if (streq(s, "signed"))
                return PARTITION_POLICY_SIGNED;
        if (streq(s, "encrypted"))
                return PARTITION_POLICY_ENCRYPTED;
        if (streq(s, "unprotected"))
                return PARTITION_POLICY_UNPROTECTED;
        if (streq(s, "unused"))
                return PARTITION_POLICY_UNUSED;
        if (streq(s, "absent"))
                return PARTITION_POLICY_ABSENT;
        if (streq(s, "open")) /* shortcut alias */
                return PARTITION_POLICY_OPEN;
        if (streq(s, "ignore")) /* ditto */
                return PARTITION_POLICY_IGNORE;
        if (streq(s, "read-only-on"))
                return PARTITION_POLICY_READ_ONLY_ON;
        if (streq(s, "read-only-off"))
                return PARTITION_POLICY_READ_ONLY_OFF;
        if (streq(s, "growfs-on"))
                return PARTITION_POLICY_GROWFS_ON;
        if (streq(s, "growfs-off"))
                return PARTITION_POLICY_GROWFS_OFF;

        return _PARTITION_POLICY_FLAGS_INVALID;
}

PartitionPolicyFlags partition_policy_flags_from_string(const char *s) {
        PartitionPolicyFlags flags = 0;
        int r;

        assert(s);

        if (empty_or_dash(s))
                return 0;

        for (;;) {
                _cleanup_free_ char *f = NULL;
                PartitionPolicyFlags ff;

                r = extract_first_word(&s, &f, "+", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                ff = policy_flag_from_string_one(strstrip(f));
                if (ff < 0)
                        return -EBADRQC; /* recognizable error */

                flags |= ff;
        }

        return flags;
}

static ImagePolicy* image_policy_new(size_t n_policies) {
        ImagePolicy *p;

        if (n_policies > (SIZE_MAX - offsetof(ImagePolicy, policies)) / sizeof(PartitionPolicy)) /* overflow check */
                return NULL;

        p = malloc(offsetof(ImagePolicy, policies) + sizeof(PartitionPolicy) * n_policies);
        if (!p)
                return NULL;

        *p = (ImagePolicy) {
                .default_flags = PARTITION_POLICY_IGNORE,
        };
        return p;
}

int image_policy_from_string(const char *s, ImagePolicy **ret) {
        _cleanup_free_ ImagePolicy *p = NULL;
        uint64_t dmask = 0;
        ImagePolicy *t;
        PartitionPolicyFlags symbolic_policy;
        int r;

        assert(s);
        assert_cc(sizeof(dmask) * 8 >= _PARTITION_DESIGNATOR_MAX);

        /* Recognizable errors:
         *
         *     ENOTUNIQ → Two or more rules for the same partition
         *     EBADSLT  → Unknown partition designator
         *     EBADRQC  → Unknown policy flags
         */

        /* First, let's handle "symbolic" policies, i.e. "-", "*", "~" */
        if (empty_or_dash(s))
                /* ignore policy: everything may exist, but nothing used */
                symbolic_policy = PARTITION_POLICY_IGNORE;
        else if (streq(s, "*"))
                /* allow policy: everything is allowed */
                symbolic_policy = PARTITION_POLICY_OPEN;
        else if (streq(s, "~"))
                /* deny policy: nothing may exist */
                symbolic_policy = PARTITION_POLICY_ABSENT;
        else
                symbolic_policy = _PARTITION_POLICY_FLAGS_INVALID;

        if (symbolic_policy >= 0) {
                if (!ret)
                        return 0;

                p = image_policy_new(0);
                if (!p)
                        return -ENOMEM;

                p->default_flags = symbolic_policy;
                *ret = TAKE_PTR(p);
                return 0;
        }

        /* Allocate the policy at maximum size, i.e. for all designators. We might overshoot a bit, but the
         * items are cheap, and we can return unused space to libc once we know we don't need it */
        p = image_policy_new(_PARTITION_DESIGNATOR_MAX);
        if (!p)
                return -ENOMEM;

        const char *q = s;
        bool default_specified = false;
        for (;;) {
                _cleanup_free_ char *e = NULL, *d = NULL;
                PartitionDesignator designator;
                PartitionPolicyFlags flags;
                char *f, *ds, *fs;

                r = extract_first_word(&q, &e, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                f = e;
                r = extract_first_word((const char**) &f, &d, "=", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Expected designator name followed by '='; got instead: %s", e);
                if (!f) /* no separator? */
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Missing '=' in policy expression: %s", e);

                ds = strstrip(d);
                if (isempty(ds)) {
                        /* Not partition name? then it's the default policy */
                        if (default_specified)
                                return log_debug_errno(SYNTHETIC_ERRNO(ENOTUNIQ), "Default partition policy flags specified more than once.");

                        designator = _PARTITION_DESIGNATOR_INVALID;
                        default_specified = true;
                } else {
                        designator = partition_designator_from_string(ds);
                        if (designator < 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADSLT), "Unknown partition designator: %s", ds); /* recognizable error */
                        if (dmask & (UINT64_C(1) << designator))
                                return log_debug_errno(SYNTHETIC_ERRNO(ENOTUNIQ), "Partition designator specified more than once: %s", ds);
                        dmask |= UINT64_C(1) << designator;
                }

                fs = strstrip(f);
                flags = partition_policy_flags_from_string(fs);
                if (flags == -EBADRQC)
                        return log_debug_errno(flags, "Unknown partition policy flag: %s", fs);
                if (flags < 0)
                        return log_debug_errno(flags, "Failed to parse partition policy flags '%s': %m", fs);

                if (designator < 0)
                        p->default_flags = flags;
                else {
                        p->policies[p->n_policies++] = (PartitionPolicy) {
                                .designator = designator,
                                .flags = flags,
                        };
                }
        };

        assert(p->n_policies <= _PARTITION_DESIGNATOR_MAX);

        /* Return unused space to libc */
        t = realloc(p, offsetof(ImagePolicy, policies) + sizeof(PartitionPolicy) * p->n_policies);
        if (t)
                p = t;

        typesafe_qsort(p->policies, p->n_policies, partition_policy_compare);

        if (ret)
                *ret = TAKE_PTR(p);

        return 0;
}

int partition_policy_flags_to_string(PartitionPolicyFlags flags, bool simplify, char **ret) {
        _cleanup_free_ char *buf = NULL;
        const char *l[CONST_LOG2U(_PARTITION_POLICY_MASK + 1) + 1]; /* one string per known flag at most */
        size_t m = 0;

        assert(ret);

        if (flags < 0)
                return -EINVAL;

        /* If 'simplify' is false we'll output the precise value of every single flag.
         *
         * If 'simplify' is true we'll try to make the output shorter, by doing the following:
         *
         *     → we'll spell the long form "verity+signed+encrypted+unprotected+unused+absent" via its
         *       equivalent shortcut form "open" (which we happily parse btw, see above)
         *
         *     → we'll spell the long form "unused+absent" via its shortcut "ignore" (which we are also happy
         *       to parse)
         *
         *     → if the read-only/growfs policy flags are both set, we suppress them. this thus removes the
         *       distinction between "user explicitly declared don't care" and "we implied don't care because
         *       user didn't say anything".
         *
         * net result: the resulting string is shorter, but the effective policy declared that way will have
         * the same results as the long form. */

        if (simplify && (flags & _PARTITION_POLICY_USE_MASK) == PARTITION_POLICY_OPEN)
                l[m++] = "open";
        else if (simplify && (flags & _PARTITION_POLICY_USE_MASK) == PARTITION_POLICY_IGNORE)
                l[m++] = "ignore";
        else {
                if (flags & PARTITION_POLICY_VERITY)
                        l[m++] = "verity";
                if (flags & PARTITION_POLICY_SIGNED)
                        l[m++] = "signed";
                if (flags & PARTITION_POLICY_ENCRYPTED)
                        l[m++] = "encrypted";
                if (flags & PARTITION_POLICY_UNPROTECTED)
                        l[m++] = "unprotected";
                if (flags & PARTITION_POLICY_UNUSED)
                        l[m++] = "unused";
                if (flags & PARTITION_POLICY_ABSENT)
                        l[m++] = "absent";
        }

        if (!simplify || (!(flags & PARTITION_POLICY_READ_ONLY_ON) != !(flags & PARTITION_POLICY_READ_ONLY_OFF))) {
                if (flags & PARTITION_POLICY_READ_ONLY_ON)
                        l[m++] = "read-only-on";
                if (flags & PARTITION_POLICY_READ_ONLY_OFF)
                        l[m++] = "read-only-off";
        }

        if (!simplify || (!(flags & PARTITION_POLICY_GROWFS_ON) != !(flags & PARTITION_POLICY_GROWFS_OFF))) {
                if (flags & PARTITION_POLICY_GROWFS_OFF)
                        l[m++] = "growfs-off";
                if (flags & PARTITION_POLICY_GROWFS_ON)
                        l[m++] = "growfs-on";
        }

        if (m == 0)
                buf = strdup("-");
        else {
                assert(m < ELEMENTSOF(l));
                l[m] = NULL;

                buf = strv_join((char**) l, "+");
        }
        if (!buf)
                return -ENOMEM;

        *ret = TAKE_PTR(buf);
        return 0;
}

static bool partition_policy_flags_extended_equal(PartitionPolicyFlags a, PartitionPolicyFlags b) {
        return partition_policy_flags_extend(a) == partition_policy_flags_extend(b);
}

static int image_policy_flags_all_match(const ImagePolicy *policy, PartitionPolicyFlags expected) {

        if (expected < 0)
                return -EINVAL;

        if (!partition_policy_flags_extended_equal(image_policy_default(policy), expected))
                return false;

        for (PartitionDesignator d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                PartitionPolicyFlags f, w;

                f = image_policy_get_exhaustively(policy, d);
                if (f < 0)
                        return f;

                w = partition_policy_normalized_flags(
                                &(const PartitionPolicy) {
                                        .flags = expected,
                                        .designator = d,
                                });
                if (w < 0)
                        return w;
                if (f != w)
                        return false;
        }

        return true;
}

bool image_policy_equiv_ignore(const ImagePolicy *policy) {
        /* Checks if this is the ignore policy (or equivalent to it), i.e. everything is ignored, aka '-', aka '' */
        return image_policy_flags_all_match(policy, PARTITION_POLICY_IGNORE);
}

bool image_policy_equiv_allow(const ImagePolicy *policy) {
        /* Checks if this is the allow policy (or equivalent to it), i.e. everything is allowed, aka '*' */
        return image_policy_flags_all_match(policy, PARTITION_POLICY_OPEN);
}

bool image_policy_equiv_deny(const ImagePolicy *policy) {
        /* Checks if this is the deny policy (or equivalent to it), i.e. everything must be absent, aka '~' */
        return image_policy_flags_all_match(policy, PARTITION_POLICY_ABSENT);
}

int image_policy_to_string(const ImagePolicy *policy, bool simplify, char **ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert(ret);

        if (simplify) {
                const char *fixed;

                if (image_policy_equiv_allow(policy))
                        fixed = "*";
                else if (image_policy_equiv_ignore(policy))
                        fixed = "-";
                else if (image_policy_equiv_deny(policy))
                        fixed = "~";
                else
                        fixed = NULL;

                if (fixed) {
                        s = strdup(fixed);
                        if (!s)
                                return -ENOMEM;

                        *ret = TAKE_PTR(s);
                        return 0;
                }
        }

        for (size_t i = 0; i < image_policy_n_entries(policy); i++) {
                const PartitionPolicy *p = policy->policies + i;
                _cleanup_free_ char *f = NULL;
                const char *t;

                assert(i == 0 || p->designator > policy->policies[i-1].designator); /* Validate perfect ordering */

                assert_se(t = partition_designator_to_string(p->designator));

                if (simplify) {
                        /* Skip policy entries that match the default anyway */
                        PartitionPolicyFlags df;

                        df = partition_policy_normalized_flags(
                                        &(const PartitionPolicy) {
                                                .flags = image_policy_default(policy),
                                                .designator = p->designator,
                                        });
                        if (df < 0)
                                return df;

                        if (df == p->flags)
                                continue;
                }

                r = partition_policy_flags_to_string(p->flags, simplify, &f);
                if (r < 0)
                        return r;

                if (!strextend(&s, isempty(s) ? "" : ":", t, "=", f))
                        return -ENOMEM;
        }

        if (!simplify || !partition_policy_flags_extended_equal(image_policy_default(policy), PARTITION_POLICY_IGNORE)) {
                _cleanup_free_ char *df = NULL;

                r = partition_policy_flags_to_string(image_policy_default(policy), simplify, &df);
                if (r < 0)
                        return r;

                if (!strextend(&s, isempty(s) ? "" : ":", "=", df))
                        return -ENOMEM;
        }

        if (isempty(s)) { /* no rule and default policy? then let's return "-" */
                s = strdup("-");
                if (!s)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(s);
        return 0;
}

bool image_policy_equal(const ImagePolicy *a, const ImagePolicy *b) {
        if (a == b)
                return true;
        if (image_policy_n_entries(a) != image_policy_n_entries(b))
                return false;
        if (image_policy_default(a) != image_policy_default(b))
                return false;
        for (size_t i = 0; i < image_policy_n_entries(a); i++) {
                if (a->policies[i].designator != b->policies[i].designator)
                        return false;
                if (a->policies[i].flags != b->policies[i].flags)
                        return false;
        }

        return true;
}

int image_policy_equivalent(const ImagePolicy *a, const ImagePolicy *b) {

        /* The image_policy_equal() function checks if the policy is defined the exact same way. This
         * function here instead looks at the outcome of the two policies instead. Where does this come to
         * different results you ask? We imply some logic regarding Verity/Encryption: when no rule is
         * defined for a verity partition we can synthesize it from the protection level of the data
         * partition it protects. Or: any per-partition rule that is identical to the default rule is
         * redundant, and will be recognized as such by image_policy_equivalent() but not by
         * image_policy_equal()- */

        if (!partition_policy_flags_extended_equal(image_policy_default(a), image_policy_default(b)))
                return false;

        for (PartitionDesignator d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                PartitionPolicyFlags f, w;

                f = image_policy_get_exhaustively(a, d);
                if (f < 0)
                        return f;

                w = image_policy_get_exhaustively(b, d);
                if (w < 0)
                        return w;

                if (f != w)
                        return false;
        }

        return true;
}

int config_parse_image_policy(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(image_policy_freep) ImagePolicy *np = NULL;
        ImagePolicy **p = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        if (isempty(rvalue)) {
                *p = image_policy_free(*p);
                return 0;
        }

        r = image_policy_from_string(rvalue, &np);
        if (r == -ENOTUNIQ)
                return log_syntax(unit, LOG_ERR, filename, line, r, "Duplicate rule in image policy, refusing: %s", rvalue);
        if (r == -EBADSLT)
                return log_syntax(unit, LOG_ERR, filename, line, r, "Unknown partition type in image policy, refusing: %s", rvalue);
        if (r == -EBADRQC)
                return log_syntax(unit, LOG_ERR, filename, line, r, "Unknown partition policy flag in image policy, refusing: %s", rvalue);
        if (r < 0)
                return log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse image policy, refusing: %s", rvalue);

        return free_and_replace_full(*p, np, image_policy_free);
}

int parse_image_policy_argument(const char *s, ImagePolicy **policy) {
        _cleanup_(image_policy_freep) ImagePolicy *np = NULL;
        int r;

        assert(s);
        assert(policy);

        /*
         * This function is intended to be used in command line parsers.
         *
         * NOTE THAT THIS WILL FREE THE PREVIOUS ARGUMENT POINTER ON SUCCESS!
         * Hence, do not pass in uninitialized pointers.
         */

        r = image_policy_from_string(s, &np);
        if (r == -ENOTUNIQ)
                return log_error_errno(r, "Duplicate rule in image policy: %s", s);
        if (r == -EBADSLT)
                return log_error_errno(r, "Unknown partition type in image policy: %s", s);
        if (r == -EBADRQC)
                return log_error_errno(r, "Unknown partition policy flag in image policy: %s", s);
        if (r < 0)
                return log_error_errno(r, "Failed to parse image policy: %s", s);

        return free_and_replace_full(*policy, np, image_policy_free);
}

static bool partition_policy_flags_has_unspecified(PartitionPolicyFlags flags) {

        if ((flags & _PARTITION_POLICY_USE_MASK) == 0)
                return true;
        if ((flags & _PARTITION_POLICY_READ_ONLY_MASK) == 0)
                return true;
        if ((flags & _PARTITION_POLICY_GROWFS_MASK) == 0)
                return true;

        return false;
}

int image_policy_intersect(const ImagePolicy *a, const ImagePolicy *b, ImagePolicy **ret) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;

        /* Calculates the intersection of the specified policies, i.e. only what is permitted in both. This
         * might fail with -ENAVAIL if the intersection is an "impossible policy". For example, if a root
         * partition my neither be used, nor be absent, nor be unused then this is considered
         * "impossible".  */

        p = image_policy_new(_PARTITION_DESIGNATOR_MAX);
        if (!p)
                return -ENOMEM;

        p->default_flags =
                partition_policy_flags_extend(image_policy_default(a)) &
                partition_policy_flags_extend(image_policy_default(b));

        if (partition_policy_flags_has_unspecified(p->default_flags)) /* Intersection empty? */
                return -ENAVAIL;

        p->default_flags = partition_policy_flags_reduce(p->default_flags);

        for (PartitionDesignator d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                PartitionPolicyFlags x, y, z, df;

                /* If this designator has no entry in either policy we don't need to include it in the intersection either. */
                if (!image_policy_bsearch(a, d) && !image_policy_bsearch(b, d))
                        continue;

                /* Expand this policy flags field to the "long" form, i.e. for each part of the flags that
                 * are left unspcified add in all possible options */
                x = image_policy_get_exhaustively(a, d);
                if (x < 0)
                        return x;

                y = image_policy_get_exhaustively(b, d);
                if (y < 0)
                        return y;

                /* Mask it */
                z = x & y;

                /* Check if the intersection is empty for this partition. If so, generate a clear error */
                if (partition_policy_flags_has_unspecified(z))
                        return -ENAVAIL;

                df = partition_policy_normalized_flags(
                                &(const PartitionPolicy) {
                                        .flags = image_policy_default(p),
                                        .designator = d,
                                });
                if (df < 0)
                        return df;
                if (df == z) /* Same as default? then let's skip this */
                        continue;

                /* image_policy_get_exhaustively() may have extended the flags mask to include all
                 * read-only/growfs flags if not set. Let's remove them again, if they are both set to
                 * minimize the policy again. */
                z = partition_policy_flags_reduce(z);

                p->policies[p->n_policies++] = (struct PartitionPolicy) {
                        .designator = d,
                        .flags = z,
                };
        }

        if (ret)
                *ret = TAKE_PTR(p);

        return 0;
}

const ImagePolicy image_policy_allow = {
        /* Allow policy */
        .n_policies = 0,
        .default_flags = PARTITION_POLICY_OPEN,
};

const ImagePolicy image_policy_deny = {
        /* Deny policy */
        .n_policies = 0,
        .default_flags = PARTITION_POLICY_ABSENT,
};

const ImagePolicy image_policy_ignore = {
        /* Ignore policy */
        .n_policies = 0,
        .default_flags = PARTITION_POLICY_IGNORE,
};

const ImagePolicy image_policy_sysext = {
        /* For system extensions, honour root file system, and /usr/ and ignore everything else. After all,
         * we are only interested in /usr/ + /opt/ trees anyway, and that's really the only place they can
         * be. */
        .n_policies = 2,
        .policies = {
                { PARTITION_ROOT,     PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_USR,      PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
        },
        .default_flags = PARTITION_POLICY_IGNORE,
};

const ImagePolicy image_policy_sysext_strict = {
        /* For system extensions, requiring signing */
        .n_policies = 2,
        .policies = {
                { PARTITION_ROOT,     PARTITION_POLICY_SIGNED|PARTITION_POLICY_ABSENT },
                { PARTITION_USR,      PARTITION_POLICY_SIGNED|PARTITION_POLICY_ABSENT },
        },
        .default_flags = PARTITION_POLICY_IGNORE,
};

const ImagePolicy image_policy_confext = {
        /* For configuration extensions, honour root file system, and ignore everything else. After all, we
         * are only interested in the /etc/ tree anyway, and that's really the only place it can be. */
        .n_policies = 1,
        .policies = {
                { PARTITION_ROOT,     PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
        },
        .default_flags = PARTITION_POLICY_IGNORE,
};

const ImagePolicy image_policy_confext_strict = {
        .n_policies = 1,
        .policies = {
                { PARTITION_ROOT,     PARTITION_POLICY_SIGNED|PARTITION_POLICY_ABSENT },
        },
        .default_flags = PARTITION_POLICY_IGNORE,
};

const ImagePolicy image_policy_container = {
        /* For systemd-nspawn containers we use all partitions, with the exception of swap */
        .n_policies = 8,
        .policies = {
                { PARTITION_ROOT,     PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_USR,      PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_HOME,     PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_SRV,      PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_ESP,      PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_XBOOTLDR, PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_TMP,      PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_VAR,      PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
        },
        .default_flags = PARTITION_POLICY_IGNORE,
};

const ImagePolicy image_policy_host = {
        /* For the host policy we basically use everything */
        .n_policies = 9,
        .policies = {
                { PARTITION_ROOT,     PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_USR,      PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_HOME,     PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_SRV,      PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_ESP,      PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_XBOOTLDR, PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_SWAP,     PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_TMP,      PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_VAR,      PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
        },
        .default_flags = PARTITION_POLICY_IGNORE,
};

const ImagePolicy image_policy_service = {
        /* For RootImage= in services we skip ESP/XBOOTLDR and swap */
        .n_policies = 6,
        .policies = {
                { PARTITION_ROOT,     PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_USR,      PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_HOME,     PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_SRV,      PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_TMP,      PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_VAR,      PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
        },
        .default_flags = PARTITION_POLICY_IGNORE,
};
