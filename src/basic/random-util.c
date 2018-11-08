/* SPDX-License-Identifier: LGPL-2.1+ */

#ifdef __x86_64__
#include <cpuid.h>
#endif

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#if HAVE_SYS_AUXV_H
#  include <sys/auxv.h>
#endif

#if USE_SYS_RANDOM_H
#  include <sys/random.h>
#else
#  include <linux/random.h>
#endif

#include "fd-util.h"
#include "io-util.h"
#include "missing.h"
#include "random-util.h"
#include "time-util.h"


int rdrand64(uint64_t *ret) {

#ifdef __x86_64__
        static int have_rdrand = -1;
        unsigned char err;

        if (have_rdrand < 0) {
                uint32_t eax, ebx, ecx, edx;

                /* Check if RDRAND is supported by the CPU */
                if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0) {
                        have_rdrand = false;
                        return -EOPNOTSUPP;
                }

                have_rdrand = !!(ecx & (1U << 30));
        }

        if (have_rdrand == 0)
                return -EOPNOTSUPP;

        asm volatile("rdrand %0;"
                     "setc %1"
                     : "=r" (*ret),
                       "=qm" (err));
        if (!err)
                return -EAGAIN;

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int genuine_random_bytes(void *p, size_t n, RandomFlags flags) {
        static int have_syscall = -1;
        _cleanup_close_ int fd = -1;
        bool got_some = false;
        int r;

        /* Gathers some randomness from the kernel (or the CPU if the RANDOM_ALLOW_RDRAND flag is set). This call won't
         * block, unless the RANDOM_BLOCK flag is set. If RANDOM_DONT_DRAIN is set, an error is returned if the random
         * pool is not initialized. Otherwise it will always return some data from the kernel, regardless of whether
         * the random pool is fully initialized or not. */

        if (n == 0)
                return 0;

        if (FLAGS_SET(flags, RANDOM_ALLOW_RDRAND))
                /* Try x86-64' RDRAND intrinsic if we have it. We only use it if high quality randomness is not
                 * required, as we don't trust it (who does?). Note that we only do a single iteration of RDRAND here,
                 * even though the Intel docs suggest calling this in a tight loop of 10 invocations or so. That's
                 * because we don't really care about the quality here. We generally prefer using RDRAND if the caller
                 * allows us too, since this way we won't drain the kernel randomness pool if we don't need it, as the
                 * pool's entropy is scarce. */
                for (;;) {
                        uint64_t u;
                        size_t m;

                        if (rdrand64(&u) < 0) {
                                if (got_some && FLAGS_SET(flags, RANDOM_EXTEND_WITH_PSEUDO)) {
                                        /* Fill in the remaining bytes using pseudo-random values */
                                        pseudo_random_bytes(p, n);
                                        return 0;
                                }

                                /* OK, this didn't work, let's go to getrandom() + /dev/urandom instead */
                                break;
                        }

                        m = MIN(sizeof(u), n);
                        memcpy(p, &u, m);

                        p = (uint8_t*) p + m;
                        n -= m;

                        if (n == 0)
                                return 0; /* Yay, success! */

                        got_some = true;
                }

        /* Use the getrandom() syscall unless we know we don't have it. */
        if (have_syscall != 0 && !HAS_FEATURE_MEMORY_SANITIZER) {

                for (;;) {
                        r = getrandom(p, n, FLAGS_SET(flags, RANDOM_BLOCK) ? 0 : GRND_NONBLOCK);
                        if (r > 0) {
                                have_syscall = true;

                                if ((size_t) r == n)
                                        return 0; /* Yay, success! */

                                assert((size_t) r < n);
                                p = (uint8_t*) p + r;
                                n -= r;

                                if (FLAGS_SET(flags, RANDOM_EXTEND_WITH_PSEUDO)) {
                                        /* Fill in the remaining bytes using pseudo-random values */
                                        pseudo_random_bytes(p, n);
                                        return 0;
                                }

                                got_some = true;

                                /* Hmm, we didn't get enough good data but the caller insists on good data? Then try again */
                                if (FLAGS_SET(flags, RANDOM_BLOCK))
                                        continue;

                                /* Fill in the rest with /dev/urandom */
                                break;

                        } else if (r == 0) {
                                have_syscall = true;
                                return -EIO;

                        } else if (errno == ENOSYS) {
                                /* We lack the syscall, continue with reading from /dev/urandom. */
                                have_syscall = false;
                                break;

                        } else if (errno == EAGAIN) {
                                /* The kernel has no entropy whatsoever. Let's remember to use the syscall the next
                                 * time again though.
                                 *
                                 * If RANDOM_DONT_DRAIN is set, return an error so that random_bytes() can produce some
                                 * pseudo-random bytes instead. Otherwise, fall back to /dev/urandom, which we know is empty,
                                 * but the kernel will produce some bytes for us on a best-effort basis. */
                                have_syscall = true;

                                if (got_some && FLAGS_SET(flags, RANDOM_EXTEND_WITH_PSEUDO)) {
                                        /* Fill in the remaining bytes using pseudorandom values */
                                        pseudo_random_bytes(p, n);
                                        return 0;
                                }

                                if (FLAGS_SET(flags, RANDOM_DONT_DRAIN))
                                        return -ENODATA;

                                /* Use /dev/urandom instead */
                                break;
                        } else
                                return -errno;
                }
        }

        fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return errno == ENOENT ? -ENOSYS : -errno;

        return loop_read_exact(fd, p, n, true);
}

void initialize_srand(void) {
        static bool srand_called = false;
        unsigned x;
#if HAVE_SYS_AUXV_H
        const void *auxv;
#endif
        uint64_t k;

        if (srand_called)
                return;

#if HAVE_SYS_AUXV_H
        /* The kernel provides us with 16 bytes of entropy in auxv, so let's
         * try to make use of that to seed the pseudo-random generator. It's
         * better than nothing... */

        auxv = (const void*) getauxval(AT_RANDOM);
        if (auxv) {
                assert_cc(sizeof(x) <= 16);
                memcpy(&x, auxv, sizeof(x));
        } else
#endif
                x = 0;

        x ^= (unsigned) now(CLOCK_REALTIME);
        x ^= (unsigned) gettid();

        if (rdrand64(&k) >= 0)
                x ^= (unsigned) k;

        srand(x);
        srand_called = true;
}

/* INT_MAX gives us only 31 bits, so use 24 out of that. */
#if RAND_MAX >= INT_MAX
#  define RAND_STEP 3
#else
/* SHORT_INT_MAX or lower gives at most 15 bits, we just just 8 out of that. */
#  define RAND_STEP 1
#endif

void pseudo_random_bytes(void *p, size_t n) {
        uint8_t *q;

        initialize_srand();

        for (q = p; q < (uint8_t*) p + n; q += RAND_STEP) {
                unsigned rr;

                rr = (unsigned) rand();

#if RAND_STEP >= 3
                if ((size_t) (q - (uint8_t*) p + 2) < n)
                        q[2] = rr >> 16;
#endif
#if RAND_STEP >= 2
                if ((size_t) (q - (uint8_t*) p + 1) < n)
                        q[1] = rr >> 8;
#endif
                q[0] = rr;
        }
}

void random_bytes(void *p, size_t n) {

        if (genuine_random_bytes(p, n, RANDOM_EXTEND_WITH_PSEUDO|RANDOM_DONT_DRAIN|RANDOM_ALLOW_RDRAND) >= 0)
                return;

        /* If for some reason some user made /dev/urandom unavailable to us, or the kernel has no entropy, use a PRNG instead. */
        pseudo_random_bytes(p, n);
}
