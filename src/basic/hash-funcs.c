/* SPDX-License-Identifier: LGPL-2.1+ */

#include <string.h>

#include "hash-funcs.h"
#include "path-util.h"

void string_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(p, strlen(p) + 1, state);
}

int string_compare_func(const void *a, const void *b) {
        return strcmp(a, b);
}

const struct hash_ops string_hash_ops = {
        .hash = string_hash_func,
        .compare = string_compare_func
};

void path_hash_func(const void *p, struct siphash *state) {
        const char *q = p;
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

int path_compare_func(const void *a, const void *b) {
        return path_compare(a, b);
}

const struct hash_ops path_hash_ops = {
        .hash = path_hash_func,
        .compare = path_compare_func
};

void trivial_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(&p, sizeof(p), state);
}

int trivial_compare_func(const void *a, const void *b) {
        return CMP(a, b);
}

const struct hash_ops trivial_hash_ops = {
        .hash = trivial_hash_func,
        .compare = trivial_compare_func
};

void uint64_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(p, sizeof(uint64_t), state);
}

int uint64_compare_func(const void *_a, const void *_b) {
        uint64_t a, b;
        a = *(const uint64_t*) _a;
        b = *(const uint64_t*) _b;
        return CMP(a, b);
}

const struct hash_ops uint64_hash_ops = {
        .hash = uint64_hash_func,
        .compare = uint64_compare_func
};

#if SIZEOF_DEV_T != 8
void devt_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(p, sizeof(dev_t), state);
}

int devt_compare_func(const void *_a, const void *_b) {
        dev_t a, b;
        a = *(const dev_t*) _a;
        b = *(const dev_t*) _b;
        return CMP(a, b);
}

const struct hash_ops devt_hash_ops = {
        .hash = devt_hash_func,
        .compare = devt_compare_func
};
#endif
