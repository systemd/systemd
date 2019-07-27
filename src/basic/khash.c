/* SPDX-License-Identifier: LGPL-2.1+ */

#include <linux/if_alg.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "khash.h"
#include "macro.h"
#include "missing.h"
#include "string-util.h"
#include "util.h"

/* On current kernels the maximum digest (according to "grep digestsize /proc/crypto | sort -u") is actually 32, but
 * let's add some extra room, the few wasted bytes don't really matter... */
#define LONGEST_DIGEST 128

struct khash {
        int fd;
        char *algorithm;
        uint8_t digest[LONGEST_DIGEST+1];
        size_t digest_size;
        bool digest_valid;
};

int khash_supported(void) {
        static const union {
                struct sockaddr sa;
                struct sockaddr_alg alg;
        } sa = {
                .alg.salg_family = AF_ALG,
                .alg.salg_type = "hash",
                .alg.salg_name = "sha256", /* a very common algorithm */
        };

        static int cached = -1;

        if (cached < 0) {
                _cleanup_close_ int fd1 = -1, fd2 = -1;
                uint8_t buf[LONGEST_DIGEST+1];

                fd1 = socket(AF_ALG, SOCK_SEQPACKET|SOCK_CLOEXEC, 0);
                if (fd1 < 0) {
                        /* The kernel returns EAFNOSUPPORT if AF_ALG is not supported at all */
                        if (IN_SET(errno, EAFNOSUPPORT, EOPNOTSUPP))
                                return (cached = false);

                        return -errno;
                }

                if (bind(fd1, &sa.sa, sizeof(sa)) < 0) {
                        /* The kernel returns ENOENT if the selected algorithm is not supported at all. We use a check
                         * for SHA256 as a proxy for whether the whole API is supported at all. After all it's one of
                         * the most common hash functions, and if it isn't supported, that's ample indication that
                         * something is really off. */

                        if (IN_SET(errno, ENOENT, EOPNOTSUPP))
                                return (cached = false);

                        return -errno;
                }

                fd2 = accept4(fd1, NULL, 0, SOCK_CLOEXEC);
                if (fd2 < 0) {
                        if (errno == EOPNOTSUPP)
                                return (cached = false);

                        return -errno;
                }

                if (recv(fd2, buf, sizeof(buf), 0) < 0) {
                        /* On some kernels we get ENOKEY for non-keyed hash functions (such as sha256), let's refuse
                         * using the API in those cases, since the kernel is
                         * broken. https://github.com/systemd/systemd/issues/8278 */

                        if (IN_SET(errno, ENOKEY, EOPNOTSUPP))
                                return (cached = false);
                }

                cached = true;
        }

        return cached;
}

int khash_new_with_key(khash **ret, const char *algorithm, const void *key, size_t key_size) {
        union {
                struct sockaddr sa;
                struct sockaddr_alg alg;
        } sa = {
                .alg.salg_family = AF_ALG,
                .alg.salg_type = "hash",
        };

        _cleanup_(khash_unrefp) khash *h = NULL;
        _cleanup_close_ int fd = -1;
        int supported;
        ssize_t n;

        assert(ret);
        assert(key || key_size == 0);

        /* Filter out an empty algorithm early, as we do not support an algorithm by that name. */
        if (isempty(algorithm))
                return -EINVAL;

        /* Overly long hash algorithm names we definitely do not support */
        if (strlen(algorithm) >= sizeof(sa.alg.salg_name))
                return -EOPNOTSUPP;

        supported = khash_supported();
        if (supported < 0)
                return supported;
        if (supported == 0)
                return -EOPNOTSUPP;

        fd = socket(AF_ALG, SOCK_SEQPACKET|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        strcpy((char*) sa.alg.salg_name, algorithm);
        if (bind(fd, &sa.sa, sizeof(sa)) < 0) {
                if (errno == ENOENT)
                        return -EOPNOTSUPP;
                return -errno;
        }

        if (key) {
                if (setsockopt(fd, SOL_ALG, ALG_SET_KEY, key, key_size) < 0)
                        return -errno;
        }

        h = new0(khash, 1);
        if (!h)
                return -ENOMEM;

        h->fd = accept4(fd, NULL, 0, SOCK_CLOEXEC);
        if (h->fd < 0)
                return -errno;

        h->algorithm = strdup(algorithm);
        if (!h->algorithm)
                return -ENOMEM;

        /* Temporary fix for rc kernel bug: https://bugzilla.redhat.com/show_bug.cgi?id=1395896 */
        (void) send(h->fd, NULL, 0, 0);

        /* Figure out the digest size */
        n = recv(h->fd, h->digest, sizeof(h->digest), 0);
        if (n < 0)
                return -errno;
        if (n >= LONGEST_DIGEST) /* longer than what we expected? If so, we don't support this */
                return -EOPNOTSUPP;

        h->digest_size = (size_t) n;
        h->digest_valid = true;

        /* Temporary fix for rc kernel bug: https://bugzilla.redhat.com/show_bug.cgi?id=1395896 */
        (void) send(h->fd, NULL, 0, 0);

        *ret = h;
        h = NULL;

        return 0;
}

int khash_new(khash **ret, const char *algorithm) {
        return khash_new_with_key(ret, algorithm, NULL, 0);
}

khash* khash_unref(khash *h) {
        if (!h)
                return NULL;

        safe_close(h->fd);
        free(h->algorithm);
        return mfree(h);
}

int khash_dup(khash *h, khash **ret) {
        _cleanup_(khash_unrefp) khash *copy = NULL;

        assert(h);
        assert(ret);

        copy = newdup(khash, h, 1);
        if (!copy)
                return -ENOMEM;

        copy->fd = -1;
        copy->algorithm = strdup(h->algorithm);
        if (!copy->algorithm)
                return -ENOMEM;

        copy->fd = accept4(h->fd, NULL, 0, SOCK_CLOEXEC);
        if (copy->fd < 0)
                return -errno;

        *ret = TAKE_PTR(copy);

        return 0;
}

const char *khash_get_algorithm(khash *h) {
        assert(h);

        return h->algorithm;
}

size_t khash_get_size(khash *h) {
        assert(h);

        return h->digest_size;
}

int khash_reset(khash *h) {
        ssize_t n;

        assert(h);

        n = send(h->fd, NULL, 0, 0);
        if (n < 0)
                return -errno;

        h->digest_valid = false;

        return 0;
}

int khash_put(khash *h, const void *buffer, size_t size) {
        ssize_t n;

        assert(h);
        assert(buffer || size == 0);

        if (size <= 0)
                return 0;

        n = send(h->fd, buffer, size, MSG_MORE);
        if (n < 0)
                return -errno;

        h->digest_valid = false;

        return 0;
}

int khash_put_iovec(khash *h, const struct iovec *iovec, size_t n) {
        struct msghdr mh = {
                mh.msg_iov = (struct iovec*) iovec,
                mh.msg_iovlen = n,
        };
        ssize_t k;

        assert(h);
        assert(iovec || n == 0);

        if (n <= 0)
                return 0;

        k = sendmsg(h->fd, &mh, MSG_MORE);
        if (k < 0)
                return -errno;

        h->digest_valid = false;

        return 0;
}

static int retrieve_digest(khash *h) {
        ssize_t n;

        assert(h);

        if (h->digest_valid)
                return 0;

        n = recv(h->fd, h->digest, h->digest_size, 0);
        if (n < 0)
                return n;
        if ((size_t) n != h->digest_size) /* digest size changed? */
                return -EIO;

        h->digest_valid = true;

        return 0;
}

int khash_digest_data(khash *h, const void **ret) {
        int r;

        assert(h);
        assert(ret);

        r = retrieve_digest(h);
        if (r < 0)
                return r;

        *ret = h->digest;
        return 0;
}

int khash_digest_string(khash *h, char **ret) {
        int r;
        char *p;

        assert(h);
        assert(ret);

        r = retrieve_digest(h);
        if (r < 0)
                return r;

        p = hexmem(h->digest, h->digest_size);
        if (!p)
                return -ENOMEM;

        *ret = p;
        return 0;
}
