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

int rdrand(unsigned long *ret) {

        /* So, you are a "security researcher", and you wonder why we bother with using raw RDRAND here,
         * instead of sticking to /dev/urandom or getrandom()?
         *
         * Here's why: early boot. On Linux, during early boot the random pool that backs /dev/urandom and
         * getrandom() is generally not initialized yet. It is very common that initialization of the random
         * pool takes a longer time (up to many minutes), in particular on embedded devices that have no
         * explicit hardware random generator, as well as in virtualized environments such as major cloud
         * installations that do not provide virtio-rng or a similar mechanism.
         *
         * In such an environment using getrandom() synchronously means we'd block the entire system boot-up
         * until the pool is initialized, i.e. *very* long. Using getrandom() asynchronously (GRND_NONBLOCK)
         * would mean acquiring randomness during early boot would simply fail. Using /dev/urandom would mean
         * generating many kmsg log messages about our use of it before the random pool is properly
         * initialized. Neither of these outcomes is desirable.
         *
         * Thus, for very specific purposes we use RDRAND instead of either of these three options. RDRAND
         * provides us quickly and relatively reliably with random values, without having to delay boot,
         * without triggering warning messages in kmsg.
         *
         * Note that we use RDRAND only under very specific circumstances, when the requirements on the
         * quality of the returned entropy permit it. Specifically, here are some cases where we *do* use
         * RDRAND:
         *
         *         • UUID generation: UUIDs are supposed to be universally unique but are not cryptographic
         *           key material. The quality and trust level of RDRAND should hence be OK: UUIDs should be
         *           generated in a way that is reliably unique, but they do not require ultimate trust into
         *           the entropy generator. systemd generates a number of UUIDs during early boot, including
         *           'invocation IDs' for every unit spawned that identify the specific invocation of the
         *           service globally, and a number of others. Other alternatives for generating these UUIDs
         *           have been considered, but don't really work: for example, hashing uuids from a local
         *           system identifier combined with a counter falls flat because during early boot disk
         *           storage is not yet available (think: initrd) and thus a system-specific ID cannot be
         *           stored or retrieved yet.
         *
         *         • Hash table seed generation: systemd uses many hash tables internally. Hash tables are
         *           generally assumed to have O(1) access complexity, but can deteriorate to prohibitive
         *           O(n) access complexity if an attacker manages to trigger a large number of hash
         *           collisions. Thus, systemd (as any software employing hash tables should) uses seeded
         *           hash functions for its hash tables, with a seed generated randomly. The hash tables
         *           systemd employs watch the fill level closely and reseed if necessary. This allows use of
         *           a low quality RNG initially, as long as it improves should a hash table be under attack:
         *           the attacker after all needs to trigger many collisions to exploit it for the purpose
         *           of DoS, but if doing so improves the seed the attack surface is reduced as the attack
         *           takes place.
         *
         * Some cases where we do NOT use RDRAND are:
         *
         *         • Generation of cryptographic key material 🔑
         *
         *         • Generation of cryptographic salt values 🧂
         *
         * This function returns:
         *
         *         -EOPNOTSUPP → RDRAND is not available on this system 😔
         *         -EAGAIN     → The operation failed this time, but is likely to work if you try again a few
         *                       times ♻
         *         -EUCLEAN    → We got some random value, but it looked strange, so we refused using it.
         *                       This failure might or might not be temporary. 😕
         */

#if defined(__i386__) || defined(__x86_64__)
        static int have_rdrand = -1;
        unsigned long v;
        uint8_t success;

        if (have_rdrand < 0) {
                uint32_t eax, ebx, ecx, edx;

                /* Check if RDRAND is supported by the CPU */
                if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0) {
                        have_rdrand = false;
                        return -EOPNOTSUPP;
                }

/* Compat with old gcc where bit_RDRND didn't exist yet */
#ifndef bit_RDRND
#define bit_RDRND (1U << 30)
#endif

                have_rdrand = !!(ecx & bit_RDRND);

                if (have_rdrand > 0) {
                        /* Allow disabling use of RDRAND with SYSTEMD_RDRAND=0
                           If it is unset getenv_bool_secure will return a negative value. */
                        if (getenv_bool_secure("SYSTEMD_RDRAND") == 0) {
                                have_rdrand = false;
                                return -EOPNOTSUPP;
                        }
                }
        }

        if (have_rdrand == 0)
                return -EOPNOTSUPP;

        asm volatile("rdrand %0;"
                     "setc %1"
                     : "=r" (v),
                       "=qm" (success));
        msan_unpoison(&success, sizeof(success));
        if (!success)
                return -EAGAIN;

        /* Apparently on some AMD CPUs RDRAND will sometimes (after a suspend/resume cycle?) report success
         * via the carry flag but nonetheless return the same fixed value -1 in all cases. This appears to be
         * a bad bug in the CPU or firmware. Let's deal with that and work-around this by explicitly checking
         * for this special value (and also 0, just to be sure) and filtering it out. This is a work-around
         * only however and something AMD really should fix properly. The Linux kernel should probably work
         * around this issue by turning off RDRAND altogether on those CPUs. See:
         * https://github.com/systemd/systemd/issues/11810 */
        if (v == 0 || v == ULONG_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                       "RDRAND returned suspicious value %lx, assuming bad hardware RNG, not using value.", v);

        *ret = v;
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

        /* Gathers some high-quality randomness from the kernel (or potentially mid-quality randomness from
         * the CPU if the RANDOM_ALLOW_RDRAND flag is set). This call won't block, unless the RANDOM_BLOCK
         * flag is set. If RANDOM_MAY_FAIL is set, an error is returned if the random pool is not
         * initialized. Otherwise it will always return some data from the kernel, regardless of whether the
         * random pool is fully initialized or not. If RANDOM_EXTEND_WITH_PSEUDO is set, and some but not
         * enough better quality randomness could be acquired, the rest is filled up with low quality
         * randomness.
         *
         * Of course, when creating cryptographic key material you really shouldn't use RANDOM_ALLOW_DRDRAND
         * or even RANDOM_EXTEND_WITH_PSEUDO.
         *
         * When generating UUIDs it's fine to use RANDOM_ALLOW_RDRAND but not OK to use
         * RANDOM_EXTEND_WITH_PSEUDO. In fact RANDOM_EXTEND_WITH_PSEUDO is only really fine when invoked via
         * an "all bets are off" wrapper, such as random_bytes(), see below. */

        if (n == 0)
                return 0;

        if (FLAGS_SET(flags, RANDOM_ALLOW_RDRAND))
                /* Try x86-64' RDRAND intrinsic if we have it. We only use it if high quality randomness is
                 * not required, as we don't trust it (who does?). Note that we only do a single iteration of
                 * RDRAND here, even though the Intel docs suggest calling this in a tight loop of 10
                 * invocations or so. That's because we don't really care about the quality here. We
                 * generally prefer using RDRAND if the caller allows us to, since this way we won't upset
                 * the kernel's random subsystem by accessing it before the pool is initialized (after all it
                 * will kmsg log about every attempt to do so)..*/
                for (;;) {
                        unsigned long u;
                        size_t m;

                        if (rdrand(&u) < 0) {
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
                        r = getrandom(p, n,
                                      (FLAGS_SET(flags, RANDOM_BLOCK) ? 0 : GRND_NONBLOCK) |
                                      (FLAGS_SET(flags, RANDOM_ALLOW_INSECURE) ? GRND_INSECURE : 0));
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

                        } else if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                                /* We lack the syscall, continue with reading from /dev/urandom. */
                                have_syscall = false;
                                break;

                        } else if (errno == EAGAIN) {
                                /* The kernel has no entropy whatsoever. Let's remember to use the syscall
                                 * the next time again though.
                                 *
                                 * If RANDOM_MAY_FAIL is set, return an error so that random_bytes() can
                                 * produce some pseudo-random bytes instead. Otherwise, fall back to
                                 * /dev/urandom, which we know is empty, but the kernel will produce some
                                 * bytes for us on a best-effort basis. */
                                have_syscall = true;

                                if (got_some && FLAGS_SET(flags, RANDOM_EXTEND_WITH_PSEUDO)) {
                                        /* Fill in the remaining bytes using pseudorandom values */
                                        pseudo_random_bytes(p, n);
                                        return 0;
                                }

                                if (FLAGS_SET(flags, RANDOM_MAY_FAIL))
                                        return -ENODATA;

                                /* Use /dev/urandom instead */
                                break;

                        } else if (errno == EINVAL) {

                                /* Most likely: unknown flag. We know that GRND_INSECURE might cause this,
                                 * hence try without. */

                                if (FLAGS_SET(flags, RANDOM_ALLOW_INSECURE)) {
                                        flags = flags &~ RANDOM_ALLOW_INSECURE;
                                        continue;
                                }

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
#if HAVE_SYS_AUXV_H
        const void *auxv;
#endif
        unsigned long k;

        if (srand_called)
                return;

#if HAVE_SYS_AUXV_H
        /* The kernel provides us with 16 bytes of entropy in auxv, so let's try to make use of that to seed
         * the pseudo-random generator. It's better than nothing... But let's first hash it to make it harder
         * to recover the original value by watching any pseudo-random bits we generate. After all the
         * AT_RANDOM data might be used by other stuff too (in particular: ASLR), and we probably shouldn't
         * leak the seed for that. */

        auxv = ULONG_TO_PTR(getauxval(AT_RANDOM));
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

        if (rdrand(&k) >= 0)
                x ^= (unsigned) k;

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
         *         • This function will preferably use the CPU's RDRAND operation, if it is available, in
         *           order to return "mid-quality" random values cheaply.
         *
         *         • Use getrandom() with GRND_NONBLOCK, to return high-quality random values if they are
         *           cheaply available.
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

        if (genuine_random_bytes(p, n, RANDOM_EXTEND_WITH_PSEUDO|RANDOM_MAY_FAIL|RANDOM_ALLOW_RDRAND|RANDOM_ALLOW_INSECURE) >= 0)
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
