/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#endif

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#if HAVE_SYS_AUXV_H
#  include <sys/auxv.h>
#endif

#include "alloc-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "missing_random.h"
#include "missing_syscall.h"
#include "parse-util.h"
#include "random-util.h"
#include "siphash24.h"
#include "time-util.h"

static bool srand_called = false;

int genuine_random_bytes(void *p, size_t n, RandomFlags flags) {
        static int have_syscall = -1;
        _cleanup_close_ int fd = -1;

        /* Gathers some high-quality randomness from the kernel. This call won't block, unless the RANDOM_BLOCK
         * flag is set. If it doesn't block, it will still always return some data from the kernel, regardless
         * of whether the random pool is fully initialized or not. When creating cryptographic key material you
         * should always use RANDOM_BLOCK. */

        if (n == 0)
                return 0;

        /* Use the getrandom() syscall unless we know we don't have it. */
        if (have_syscall != 0 && !HAS_FEATURE_MEMORY_SANITIZER) {
                for (;;) {
                        ssize_t l = getrandom(p, n, FLAGS_SET(flags, RANDOM_BLOCK) ? 0 : GRND_INSECURE);

                        if (l > 0) {
                                have_syscall = true;

                                if ((size_t) l == n)
                                        return 0; /* Yay, success! */

                                /* We didn't get enough data, so try again */
                                assert((size_t) l < n);
                                p = (uint8_t*) p + l;
                                n -= l;
                                continue;

                        } else if (l == 0) {
                                have_syscall = true;
                                return -EIO;

                        } else if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                                /* We lack the syscall, continue with reading from /dev/urandom. */
                                have_syscall = false;
                                break;

                        } else if (errno == EINVAL) {
                                /* If we previously passed GRND_INSECURE, and this flag isn't known, then
                                 * we're likely running an old kernel which has getrandom() but not
                                 * GRND_INSECURE. In this case, fall back to /dev/urandom. */
                                if (!FLAGS_SET(flags, RANDOM_BLOCK))
                                        break;

                                return -errno;
                        } else
                                return -errno;
                }
        }

        fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return errno == ENOENT ? -ENOSYS : -errno;

        return loop_read_exact(fd, p, n, true);
}

static void clear_srand_initialization(void) {
        srand_called = false;
}

void initialize_srand(void) {
        static bool pthread_atfork_registered = false;
        unsigned x;

        if (srand_called)
                return;

#if HAVE_SYS_AUXV_H
        /* The kernel provides us with 16 bytes of entropy in auxv, so let's try to make use of that to seed
         * the pseudo-random generator. It's better than nothing... But let's first hash it to make it harder
         * to recover the original value by watching any pseudo-random bits we generate. After all the
         * AT_RANDOM data might be used by other stuff too (in particular: ASLR), and we probably shouldn't
         * leak the seed for that. */

        const void *auxv = ULONG_TO_PTR(getauxval(AT_RANDOM));
        if (auxv) {
                static const uint8_t auxval_hash_key[16] = {
                        0x92, 0x6e, 0xfe, 0x1b, 0xcf, 0x00, 0x52, 0x9c, 0xcc, 0x42, 0xcf, 0xdc, 0x94, 0x1f, 0x81, 0x0f
                };

                x = (unsigned) siphash24(auxv, 16, auxval_hash_key);
        } else
#endif
                x = 0;

        x ^= (unsigned) now(CLOCK_REALTIME);
        x ^= (unsigned) gettid();

        srand(x);
        srand_called = true;

        if (!pthread_atfork_registered) {
                (void) pthread_atfork(NULL, NULL, clear_srand_initialization);
                pthread_atfork_registered = true;
        }
}

/* INT_MAX gives us only 31 bits, so use 24 out of that. */
#if RAND_MAX >= INT_MAX
assert_cc(RAND_MAX >= 16777215);
#  define RAND_STEP 3
#else
/* SHORT_INT_MAX or lower gives at most 15 bits, we just use 8 out of that. */
assert_cc(RAND_MAX >= 255);
#  define RAND_STEP 1
#endif

void pseudo_random_bytes(void *p, size_t n) {
        uint8_t *q;

        /* This returns pseudo-random data using libc's rand() function. You probably never want to call this
         * directly, because why would you use this if you can get better stuff cheaply? Use random_bytes()
         * instead, see below: it will fall back to this function if there's nothing better to get, but only
         * then. */

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

        /* This returns high quality randomness if we can get it cheaply. If we can't because for some reason
         * it is not available we'll try some crappy fallbacks.
         *
         * What this function will do:
         *
         *         • Use getrandom(GRND_INSECURE) or /dev/urandom, to return high-quality random values if
         *           they are cheaply available, or less high-quality random values if they are not.
         *
         *         • This function will return pseudo-random data, generated via libc rand() if nothing
         *           better is available.
         *
         *         • This function will work fine in early boot
         *
         *         • This function will always succeed
         *
         * What this function won't do:
         *
         *         • This function will never fail: it will give you randomness no matter what. It might not
         *           be high quality, but it will return some, possibly generated via libc's rand() call.
         *
         *         • This function will never block: if the only way to get good randomness is a blocking,
         *           synchronous getrandom() we'll instead provide you with pseudo-random data.
         *
         * This function is hence great for things like seeding hash tables, generating random numeric UNIX
         * user IDs (that are checked for collisions before use) and such.
         *
         * This function is hence not useful for generating UUIDs or cryptographic key material.
         */

        if (genuine_random_bytes(p, n, 0) >= 0)
                return;

        /* If for some reason some user made /dev/urandom unavailable to us, or the kernel has no entropy, use a PRNG instead. */
        pseudo_random_bytes(p, n);
}

size_t random_pool_size(void) {
        _cleanup_free_ char *s = NULL;
        int r;

        /* Read pool size, if possible */
        r = read_one_line_file("/proc/sys/kernel/random/poolsize", &s);
        if (r < 0)
                log_debug_errno(r, "Failed to read pool size from kernel: %m");
        else {
                unsigned sz;

                r = safe_atou(s, &sz);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse pool size: %s", s);
                else
                        /* poolsize is in bits on 2.6, but we want bytes */
                        return CLAMP(sz / 8, RANDOM_POOL_SIZE_MIN, RANDOM_POOL_SIZE_MAX);
        }

        /* Use the minimum as default, if we can't retrieve the correct value */
        return RANDOM_POOL_SIZE_MIN;
}

int random_write_entropy(int fd, const void *seed, size_t size, bool credit) {
        _cleanup_close_ int opened_fd = -1;
        int r;

        assert(seed || size == 0);

        if (size == 0)
                return 0;

        if (fd < 0) {
                opened_fd = open("/dev/urandom", O_WRONLY|O_CLOEXEC|O_NOCTTY);
                if (opened_fd < 0)
                        return -errno;

                fd = opened_fd;
        }

        if (credit) {
                _cleanup_free_ struct rand_pool_info *info = NULL;

                /* The kernel API only accepts "int" as entropy count (which is in bits), let's avoid any
                 * chance for confusion here. */
                if (size > INT_MAX / 8)
                        return -EOVERFLOW;

                info = malloc(offsetof(struct rand_pool_info, buf) + size);
                if (!info)
                        return -ENOMEM;

                info->entropy_count = size * 8;
                info->buf_size = size;
                memcpy(info->buf, seed, size);

                if (ioctl(fd, RNDADDENTROPY, info) < 0)
                        return -errno;
        } else {
                r = loop_write(fd, seed, size, false);
                if (r < 0)
                        return r;
        }

        return 1;
}

uint64_t random_u64_range(uint64_t m) {
        uint64_t x, remainder;

        /* Generates a random number in the range 0…m-1, unbiased. (Java's algorithm) */

        if (m == 0) /* Let's take m == 0 as special case to return an integer from the full range */
                return random_u64();
        if (m == 1)
                return 0;

        remainder = UINT64_MAX % m;

        do {
                x = random_u64();
        } while (x >= UINT64_MAX - remainder);

        return x % m;
}
