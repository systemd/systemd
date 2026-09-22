/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hashmap.h"
#include "machine-tags.h"
#include "string-util.h"
#include "strv.h"

bool machine_tag_is_valid(const char *s) {
        size_t n = strlen_ptr(s);
        if (n <= 0 || n >= 256)
                return false;

        /* Don't allow "-" and "." as first char. (This is load-bearing, we want that "+"/"-" can be used as
         * prefix for adding/removing tags from the list). */
        if (strchr("-.=", s[0]))
                return false;

        /* We allow parameterization of tags, with a "=" as separator */
        const char *eq = strchr(s, '=');
        if (eq) {
                assert(eq > s);

                /* If there is an '=', then make the same restrictions as for the first char on the last char before it */
                if (strchr("-.", eq[-1]))
                        return false;
        } else {
                /* If there's no '=', then make the restriction on the very last character */
                if (strchr("-.", s[n-1]))
                        return false;
        }

        return in_charset(s, ALPHANUMERICAL "-.=");
}

int machine_tag_list_is_valid(char **l) {
        int r;

        r = machine_tags_from_strv(l, /* graceful= */ false, /* ret= */ NULL);
        switch (r) {
        case -EINVAL:
        case -E2BIG:
                return false;
        case 0:
                return true;
        default:
                return r;
        }
}

int machine_tags_from_string(const char *s, bool graceful, char ***ret) {
        assert(ret);

        /* Parse the colon-separated TAGS= machine-info field into a sorted, deduplicated strv. */

        if (isempty(s)) {
                *ret = NULL;
                return 0;
        }

        _cleanup_strv_free_ char **l = strv_split(s, ":");
        if (!l)
                return -ENOMEM;

        return machine_tags_from_strv(l, graceful, ret);
}

int machine_tags_from_strv(char **l, bool graceful, char ***ret) {
        int r;

        /* Go through a list of tags and verify each tag. If 'graceful' is true invalid tags are silently
         * dropped, otherwise an invalid tag makes us fail with -EINVAL. If the same tag or key is specified
         * more than once, the one specified last wins if 'graceful' is true, otherwise this makes us fail
         * with -EINVAL, too. At most MACHINE_TAGS_MAX valid tags are accepted. The result is sorted only
         * after deduplication, and is NULL if no (valid) tags remain. */

        /* Maps the key of each tag, i.e. everything up to and including the first '=', or the whole tag if it
         * has no '=', to the tag itself (borrowed from 'l'). A bare tag and an assignment of the same name
         * hence get distinct keys and may coexist. */
        _cleanup_hashmap_free_ Hashmap *h = NULL;
        STRV_FOREACH(i, l) {
                if (!machine_tag_is_valid(*i)) {
                        if (graceful)
                                continue;

                        return -EINVAL;
                }

                if (hashmap_size(h) >= MACHINE_TAGS_MAX)
                        return -E2BIG;

                const char *eq = strchrnul(*i, '=');
                _cleanup_free_ char *k = strndup(*i, (eq - *i) + (*eq == '='));
                if (!k)
                        return -ENOMEM;

                r = hashmap_ensure_put(&h, &string_hash_ops_free, k, *i);
                if (IN_SET(r, 0, -EEXIST)) {  /* same key and value or same key but different value */
                        if (!graceful)
                                return -EINVAL;

                        if (r == -EEXIST)
                                /* not the same value pointer, update to the later value */
                                assert_se(hashmap_update(h, k, *i) >= 0);
                        continue;
                }
                if (r < 0)
                        return r;
                TAKE_PTR(k);
        }

        if (ret) {
                _cleanup_strv_free_ char **cleaned = NULL;
                char *v;
                HASHMAP_FOREACH(v, h) {
                        r = strv_extend(&cleaned, v);
                        if (r < 0)
                                return r;
                }

                strv_sort(cleaned);
                *ret = TAKE_PTR(cleaned);
        }

        return 0;
}
