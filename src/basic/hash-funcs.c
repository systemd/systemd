/* SPDX-License-Identifier: LGPL-2.1+ */

#include <string.h>

#include "hash-funcs.h"
#include "path-util.h"

void string_hash_func(const char *p, struct siphash *state) {
        siphash24_compress(p, strlen(p) + 1, state);
}

DEFINE_HASH_OPS(string_hash_ops, char, string_hash_func, string_compare_func);
DEFINE_HASH_OPS_FULL(string_hash_ops_free_free,
                     char, string_hash_func, string_compare_func, free,
                     char, free);

void path_hash_func(const char *q, struct siphash *state) {
        size_t n;

        assert(q);
        assert(state);

        /* Calculates a hash for a path in a way this duplicate inner slashes don't make a differences, and also
         * whether there's a trailing slash or not. This fits well with the semantics of path_compare(), which does
         * similar checks and also doesn't care for trailing slashes. Note that relative and absolute paths (i.e. those
         * which begin in a slash or not) will hash differently though. */

        n = strspn(q, "/");
        if (n > 0) { /* Eat up initial slashes, and add one "/" to the hash for all of them */
                siphash24_compress(q, 1, state);
                q += n;
        }

        for (;;) {
                /* Determine length of next component */
                n = strcspn(q, "/");
                if (n == 0) /* Reached the end? */
                        break;

                /* Add this component to the hash and skip over it */
                siphash24_compress(q, n, state);
                q += n;

                /* How many slashes follow this component? */
                n = strspn(q, "/");
                if (q[n] == 0) /* Is this a trailing slash? If so, we are at the end, and don't care about the slashes anymore */
                        break;

                /* We are not add the end yet. Hash exactly one slash for all of the ones we just encountered. */
                siphash24_compress(q, 1, state);
                q += n;
        }
}

int path_compare_func(const char *a, const char *b) {
        return path_compare(a, b);
}

DEFINE_HASH_OPS(path_hash_ops, char, path_hash_func, path_compare_func);

void trivial_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(&p, sizeof(p), state);
}

int trivial_compare_func(const void *a, const void *b) {
        return CMP(a, b);
}

const struct hash_ops trivial_hash_ops = {
        .hash = trivial_hash_func,
        .compare = trivial_compare_func,
};

void uint64_hash_func(const uint64_t *p, struct siphash *state) {
        siphash24_compress(p, sizeof(uint64_t), state);
}

int uint64_compare_func(const uint64_t *a, const uint64_t *b) {
        return CMP(*a, *b);
}

DEFINE_HASH_OPS(uint64_hash_ops, uint64_t, uint64_hash_func, uint64_compare_func);

#if SIZEOF_DEV_T != 8
void devt_hash_func(const dev_t *p, struct siphash *state) {
        siphash24_compress(p, sizeof(dev_t), state);
}

int devt_compare_func(const dev_t *a, const dev_t *b) {
        return CMP(*a, *b);
}

DEFINE_HASH_OPS(devt_hash_ops, dev_t, devt_hash_func, devt_compare_func);
#endif
