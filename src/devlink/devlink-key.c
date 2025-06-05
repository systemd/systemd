/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "macro.h"
#include "siphash24.h"

#include "devlink-key.h"
#include "devlink-match.h"

void devlink_key_hash_func(const DevlinkKey *key, struct siphash *state) {
        siphash24_compress_typesafe(key->kind, state);
        siphash24_compress_typesafe(key->matchset, state);
        devlink_match_hash(&key->match, key->matchset, state);
}

int devlink_key_compare_func(const DevlinkKey *x, const DevlinkKey *y) {
        int d;

        assert(x);
        assert(y);

        d = CMP(x->kind, y->kind);
        if (d)
                return d;

        d = CMP(x->matchset, y->matchset);
        if (d)
                return d;

        return devlink_match_compare(&x->match, &y->match, x->matchset);
}

void devlink_key_copy_from_match(DevlinkKey *dst, const DevlinkMatch *src, DevlinkMatchSet matchset) {
        assert(dst);
        assert(src);

        devlink_match_copy(&dst->match, src, matchset);
        dst->matchset |= matchset;
}

void devlink_key_copy_subkey(DevlinkKey *dst, const DevlinkKey *src, DevlinkMatchSet matchset) {
        assert(dst);
        assert(src);

        assert((src->matchset & matchset) == matchset);
        devlink_key_copy_from_match(dst, &src->match, matchset);
}

int devlink_key_duplicate_from_match(DevlinkKey *dst, const DevlinkMatch *src, DevlinkMatchSet matchset) {
        int r;

        assert(dst);
        assert(src);

        r = devlink_match_duplicate(&dst->match, src, matchset);
        if (r)
                return r;

        dst->matchset = matchset;

        return 0;
}

int devlink_key_duplicate(DevlinkKey *dst, const DevlinkKey *src) {
        assert(dst);
        assert(src);

        return devlink_key_duplicate_from_match(dst, &src->match, src->matchset);
}

void devlink_key_init(DevlinkKey *key, DevlinkKind kind) {
        key->kind = kind;
        key->matchset = 0;
}

void devlink_key_fini(DevlinkKey *key) {
        devlink_match_fini(&key->match);
}

void devlink_key_matchset_set(DevlinkKey *key, DevlinkMatchSet matchset) {
        key->matchset = matchset;
}

int devlink_key_genl_append(sd_netlink_message *message, const DevlinkKey *key) {
        return devlink_match_genl_append(message, &key->match, key->matchset);
}
