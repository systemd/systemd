/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "extract-word.h"
#include "image-policy.h"
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

static PartitionPolicy* image_policy_bsearch(const ImagePolicy *policy, PartitionDesignator designator) {
        if (!policy)
                return NULL;

        return typesafe_bsearch(
                        &(PartitionPolicy) { .designator = designator },
                        ASSERT_PTR(policy)->policies,
                        ASSERT_PTR(policy)->n_policies,
                        partition_policy_compare);
}

static PartitionPolicyFlags partition_policy_normalized_flags(const PartitionPolicy *policy) {
        PartitionPolicyFlags flags;

        assert(policy);

        flags = policy->flags;

        if (partition_verity_to_data(policy->designator) >= 0 ||
            partition_verity_sig_to_data(policy->designator) >= 0)
                /* If this is a verity or verity signature designator, then mask off all protection bits,
                 * this after all needs no protection, because it *is* the protection */
                flags &= ~(PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED);
        else if ((flags & _PARTITION_POLICY_USE_MASK) == 0)
                /* For data partitions: if no protection flag is set, then this means all are set */
                flags |= PARTITION_POLICY_OPEN;

        if ((flags & _PARTITION_POLICY_USE_MASK) == PARTITION_POLICY_ABSENT)
                /* If the partition must be absent, then the gpt flags don't matter */
                flags &= ~(_PARTITION_POLICY_READ_ONLY_MASK|_PARTITION_POLICY_GROWFS_MASK);
        else {
                /* If the gpt flags bits are not specified, set both options for each */
                if ((flags & _PARTITION_POLICY_READ_ONLY_MASK) == 0)
                        flags |= PARTITION_POLICY_READ_ONLY_ON|PARTITION_POLICY_READ_ONLY_OFF;
                if ((flags & _PARTITION_POLICY_GROWFS_MASK) == 0)
                        flags |= PARTITION_POLICY_GROWFS_ON|PARTITION_POLICY_GROWFS_OFF;
        }

        return flags;
}

PartitionPolicyFlags image_policy_get(const ImagePolicy *policy, PartitionDesignator designator) {
        PartitionDesignator data_designator = _PARTITION_DESIGNATOR_INVALID;
        PartitionPolicy *pp;

        /* No policy means: everything may be used in any mode */
        if (!policy)
                return PARTITION_POLICY_OPEN;

        pp = image_policy_bsearch(policy, designator);
        if (pp)
                return partition_policy_normalized_flags(pp);

        /* Hmm, so this didn't work, then let's see if we can derive some policy from the underlying data
         * partition in case of verity/signature partitions */

        data_designator = partition_verity_to_data(designator);
        if (data_designator >= 0) {
                PartitionPolicyFlags data_flags;

                /* So we are asked for the policy for a verity partition, and there's no explicit policy for
                 * that case. Let's synthesize policy from the protection setting for the underlying data
                 * partition. */

                data_flags = image_policy_get(policy, data_designator);
                if (data_flags < 0)
                        return data_flags;

                /* We need verity if verity or verity with sig is requested */
                if (!(data_flags & (PARTITION_POLICY_SIGNED|PARTITION_POLICY_VERITY)))
                        return _PARTITION_POLICY_FLAGS_INVALID;

                /* If the data partition may be unused or absent, then the verity partition may too. Also, inherit the partition flags policy */
                return PARTITION_POLICY_UNPROTECTED | (data_flags & (PARTITION_POLICY_UNUSED|PARTITION_POLICY_ABSENT)) |
                        (data_flags & _PARTITION_POLICY_PFLAGS_MASK);
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

                return PARTITION_POLICY_UNPROTECTED | (data_flags & (PARTITION_POLICY_UNUSED|PARTITION_POLICY_ABSENT)) |
                        (data_flags & _PARTITION_POLICY_PFLAGS_MASK);
        }

        return _PARTITION_POLICY_FLAGS_INVALID; /* got nothing */
}

PartitionPolicyFlags image_policy_get_exhaustively(const ImagePolicy *policy, PartitionDesignator designator) {
        PartitionPolicyFlags flags;

        /* This is just like image_policy_get() but whenever there is no policy for a specific designator, we
         * say "unused+absent", i.e. we won't care about the partition */

        flags = image_policy_get(policy, designator);
        if (flags < 0)
                return PARTITION_POLICY_UNUSED|PARTITION_POLICY_ABSENT; /* If no policy then allow it to exist not be missing, but certainly don't use it */

        return flags;
}

static PartitionPolicyFlags policy_flag_from_string_one(const char *s) {
        if (!s)
                return _PARTITION_POLICY_FLAGS_INVALID;

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

        if (!s)
                return _PARTITION_POLICY_FLAGS_INVALID;

        if (streq(s, "-"))
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

        if (n_policies > (SIZE_MAX - offsetof(ImagePolicy, policies) / sizeof(PartitionPolicy)))
                return NULL;

        p = malloc(offsetof(ImagePolicy, policies) + sizeof(PartitionPolicy) * n_policies);
        if (!p)
                return NULL;

        p->n_policies = 0;
        return p;
}

int image_policy_from_string(const char *s, ImagePolicy **ret) {
        _cleanup_free_ ImagePolicy *p = NULL;
        ImagePolicy *t;
        uint64_t dmask = 0;
        int r;

        assert(ret);
        assert_cc(sizeof(dmask) * 8 >= _PARTITION_DESIGNATOR_MAX);

        if (isempty(s) || streq(s, "-")) {
                /* empty policy: everything may exist, but nothing used */
                p = image_policy_new(0);
                if (!p)
                        return -ENOMEM;

                *ret = TAKE_PTR(p);
                return 0;
        }

        if (streq(s, "~")) {
                /* deny policy: nothing may exist */
                p = image_policy_new(_PARTITION_DESIGNATOR_MAX);
                if (!p)
                        return -ENOMEM;

                for (PartitionDesignator d = 0; d < _PARTITION_DESIGNATOR_MAX; d++)
                        p->policies[d] = (PartitionPolicy) {
                                .designator = d,
                                .flags = PARTITION_POLICY_ABSENT,
                        };

                p->n_policies = _PARTITION_DESIGNATOR_MAX;
                *ret = TAKE_PTR(p);
                return 0;
        }

        if (streq(s, "*")) {
                /* no policy: everything is allowed */
                *ret = NULL;
                return 0;
        }

        /* Allocate the policy at maximum size, i.e. for all designators. We might overshoot a bit, but the
         * items are cheap, and we can return unused space to libc once we know we don't need it */
        p = image_policy_new(_PARTITION_DESIGNATOR_MAX);
        if (!p)
                return -ENOMEM;
        p->n_policies = 0;

        const char *q = s;
        for (;;) {
                _cleanup_free_ char *e = NULL, *d = NULL;
                PartitionDesignator designator;
                PartitionPolicyFlags flags;
                char *qq;

                r = extract_first_word(&q, &e, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                qq = e;
                r = extract_first_word((const char**) &qq, &d, "=", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Expected designator name, followed by '=' got instead: %s", e);

                designator = partition_designator_from_string(strstrip(d));
                if (designator < 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENXIO), "Unknown partition designator: %s", d); /* recognizable error */
                if (dmask & (UINT64_C(1) << designator))
                        return log_debug_errno(SYNTHETIC_ERRNO(ENXIO), "Partition designator specified more than once: %s", d);
                dmask |= UINT64_C(1) << designator;

                flags = partition_policy_flags_from_string(strstrip(qq));
                if (flags == -EBADRQC)
                        return log_debug_errno(flags, "Unknown partition policy flag: %s", qq);
                if (flags < 0)
                        return log_debug_errno(flags, "Failed to parse partition policy flags '%s': %m", qq);

                if ((flags & _PARTITION_POLICY_USE_MASK) == 0) /* if the use mask is unspecified, then dont use, but allow it to exist */
                        flags |= PARTITION_POLICY_UNUSED|PARTITION_POLICY_ABSENT;

                p->policies[p->n_policies++] = (PartitionPolicy) {
                        .designator = designator,
                        .flags = flags,
                };
        };

        assert(p->n_policies <= _PARTITION_DESIGNATOR_MAX);

        /* Return unused space to libc */
        t = realloc(p, offsetof(ImagePolicy, policies) + sizeof(PartitionPolicy) * p->n_policies);
        if (t)
                p = t;

        typesafe_qsort(p->policies, p->n_policies, partition_policy_compare);

        *ret = TAKE_PTR(p);
        return 0;
}

int partition_policy_flags_to_string(PartitionPolicyFlags flags, char **ret) {
        _cleanup_free_ char *buf = NULL;
        const char *l[11];
        size_t m = 0;

        if (FLAGS_SET(flags, PARTITION_POLICY_OPEN))
                l[m++] = "open";
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

        if (flags & PARTITION_POLICY_READ_ONLY_ON)
                l[m++] = "read-only-on";
        if (flags & PARTITION_POLICY_READ_ONLY_OFF)
                l[m++] = "read-only-off";

        if (flags & PARTITION_POLICY_GROWFS_OFF)
                l[m++] = "growfs-off";
        if (flags & PARTITION_POLICY_GROWFS_ON)
                l[m++] = "growfs-on";

        if (m == 0)
                buf = strdup("-");
        else {
                assert(m+1 < ELEMENTSOF(l));
                l[m] = NULL;

                buf = strv_join((char**) l, "+");
        }
        if (!buf)
                return -ENOMEM;

        *ret = TAKE_PTR(buf);
        return 0;
}

int image_policy_to_string(const ImagePolicy *policy, char **ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert(ret);

        if (!policy) {
                s = strdup("*"); /* everything allowed */
                if (!s)
                        return -ENOMEM;

                *ret = TAKE_PTR(s);
                return 0;
        }

        for (size_t i = 0; i < policy->n_policies; i++) {
                const PartitionPolicy *p = policy->policies + i;
                _cleanup_free_ char *f = NULL;
                const char *t;

                assert(i == 0 || p->designator > policy->policies[i-1].designator); /* Validate perfect ordering */

                assert_se(t = partition_designator_to_string(p->designator));

                r = partition_policy_flags_to_string(p->flags, &f);
                if (r < 0)
                        return r;

                if (!strextend(&s, isempty(s) ? "" : ":", t, "=", f))
                        return -ENOMEM;
        }

        if (!s) {
                s = strdup("-"); /* nothing is allowed */
                if (!s)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(s);
        return 0;
}

bool image_policy_equal(const ImagePolicy *a, const ImagePolicy *b) {
        if (a == b)
                return true;
        if (!a || !b)
                return false;
        if (a->n_policies != b->n_policies)
                return false;
        for (size_t i = 0; i < a->n_policies; i++) {
                if (a->policies[i].designator != b->policies[i].designator)
                        return false;
                if (a->policies[i].flags != b->policies[i].flags)
                        return false;
        }

        return true;
}

const ImagePolicy image_policy_sysext = {
        /* For system extensions, honour root file system, and /usr/ and ignore everything else. After all,
         * we are only interested in /usr/ + /opt/ trees anyway, and that's really the only place they can
         * be. */
        .n_policies = 2,
        .policies = {
                { PARTITION_ROOT,     PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_USR,      PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_ENCRYPTED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
        },
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
};
