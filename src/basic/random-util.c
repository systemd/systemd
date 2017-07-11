/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>
#include <linux/random.h>
#include <stdint.h>

#ifdef HAVE_SYS_AUXV_H
#  include <sys/auxv.h>
#endif

#ifdef USE_SYS_RANDOM_H
#  include <sys/random.h>
#else
#  include <linux/random.h>
#endif

#include "fd-util.h"
#include "io-util.h"
#include "missing.h"
#include "random-util.h"
#include "time-util.h"

int acquire_random_bytes(void *p, size_t n, bool high_quality_required) {
        static int have_syscall = -1;

        _cleanup_close_ int fd = -1;
        unsigned already_done = 0;
        int r;

        /* Gathers some randomness from the kernel. This call will never block. If
         * high_quality_required, it will always return some data from the kernel,
         * regardless of whether the random pool is fully initialized or not.
         * Otherwise, it will return success if at least some random bytes were
         * successfully acquired, and an error if the kernel has no entropy whatsover
         * for us. */

        /* Use the getrandom() syscall unless we know we don't have it. */
        if (have_syscall != 0) {
                r = getrandom(p, n, GRND_NONBLOCK);
                if (r > 0) {
                        have_syscall = true;
                        if ((size_t) r == n)
                                return 0;
                        if (!high_quality_required) {
                                /* Fill in the remaing bytes using pseudorandom values */
                                pseudorandom_bytes((uint8_t*) p + r, n - r);
                                return 0;
                        }

                        already_done = r;
                } else if (errno == ENOSYS)
                          /* We lack the syscall, continue with reading from /dev/urandom. */
                          have_syscall = false;
                else if (errno == EAGAIN) {
                        /* The kernel has no entropy whatsoever. Let's remember to
                         * use the syscall the next time again though.
                         *
                         * If high_quality_required is false, return an error so that
                         * random_bytes() can produce some pseudorandom
                         * bytes. Otherwise, fall back to /dev/urandom, which we know
                         * is empty, but the kernel will produce some bytes for us on
                         * a best-effort basis. */
                        have_syscall = true;

                        if (!high_quality_required)
                                return -ENODATA;
                } else
                        return -errno;
        }

        fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return errno == ENOENT ? -ENOSYS : -errno;

        return loop_read_exact(fd, (uint8_t*) p + already_done, n - already_done, true);
}

void initialize_srand(void) {
        static bool srand_called = false;
        unsigned x;
#ifdef HAVE_SYS_AUXV_H
        void *auxv;
#endif

        if (srand_called)
                return;

#ifdef HAVE_SYS_AUXV_H
        /* The kernel provides us with 16 bytes of entropy in auxv, so let's
         * try to make use of that to seed the pseudo-random generator. It's
         * better than nothing... */

        auxv = (void*) getauxval(AT_RANDOM);
        if (auxv) {
                assert_cc(sizeof(x) <= 16);
                memcpy(&x, auxv, sizeof(x));
        } else
#endif
                x = 0;


        x ^= (unsigned) now(CLOCK_REALTIME);
        x ^= (unsigned) gettid();

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

void pseudorandom_bytes(void *p, size_t n) {
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
        int r;

        r = acquire_random_bytes(p, n, false);
        if (r >= 0)
                return;

        /* If some idiot made /dev/urandom unavailable to us, or the
         * kernel has no entropy, use a PRNG instead. */
        return pseudorandom_bytes(p, n);
}
