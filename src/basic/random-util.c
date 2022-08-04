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
#include "sha256.h"
#include "time-util.h"

/* This is a "best effort" kind of thing, but has no real security value.
 * So, this should only be used by random_bytes(), which is not meant for
 * crypto. This could be made better, but we're *not* trying to roll a
 * userspace prng here, or even have forward secrecy, but rather just do
 * the shortest thing that is at least better than libc rand(). */
static void fallback_random_bytes(void *p, size_t n) {
        static thread_local uint64_t fallback_counter = 0;
        struct {
                char label[32];
                uint64_t call_id, block_id;
                usec_t stamp_mono, stamp_real;
                pid_t pid, tid;
                uint8_t auxval[16];
        } state = {
                /* Arbitrary domain separation to prevent other usage of AT_RANDOM from clashing. */
                .label = "systemd fallback random bytes v1",
                .call_id = fallback_counter++,
                .stamp_mono = now(CLOCK_MONOTONIC),
                .stamp_real = now(CLOCK_REALTIME),
                .pid = getpid(),
                .tid = gettid()
        };

#if HAVE_SYS_AUXV_H
        memcpy(state.auxval, ULONG_TO_PTR(getauxval(AT_RANDOM)), sizeof(state.auxval));
#endif

        while (n > 0) {
                struct sha256_ctx ctx;

                sha256_init_ctx(&ctx);
                sha256_process_bytes(&state, sizeof(state), &ctx);
                if (n < SHA256_DIGEST_SIZE) {
                        uint8_t partial[SHA256_DIGEST_SIZE];
                        sha256_finish_ctx(&ctx, partial);
                        memcpy(p, partial, n);
                        break;
                }
                sha256_finish_ctx(&ctx, p);
                p = (uint8_t *) p + SHA256_DIGEST_SIZE;
                n -= SHA256_DIGEST_SIZE;
                ++state.block_id;
        }
}

void random_bytes(void *p, size_t n) {
        static bool have_getrandom = true, have_grndinsecure = true;
        _cleanup_close_ int fd = -1;

        if (n == 0)
                return;

        for (;;) {
                ssize_t l;

                if (!have_getrandom)
                        break;

                l = getrandom(p, n, have_grndinsecure ? GRND_INSECURE : GRND_NONBLOCK);
                if (l > 0) {
                        if ((size_t) l == n)
                                return; /* Done reading, success. */
                        p = (uint8_t *) p + l;
                        n -= l;
                        continue; /* Interrupted by a signal; keep going. */
                } else if (l == 0)
                        break; /* Weird, so fallback to /dev/urandom. */
                else if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                        have_getrandom = false;
                        break; /* No syscall, so fallback to /dev/urandom. */
                } else if (errno == EINVAL && have_grndinsecure) {
                        have_grndinsecure = false;
                        continue; /* No GRND_INSECURE; fallback to GRND_NONBLOCK. */
                } else if (errno == EAGAIN && !have_grndinsecure)
                        break; /* Will block, but no GRND_INSECURE, so fallback to /dev/urandom. */

                break; /* Unexpected, so just give up and fallback to /dev/urandom. */
        }

        fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd >= 0 && loop_read_exact(fd, p, n, false) == 0)
                return;

        /* This is a terrible fallback. Oh well. */
        fallback_random_bytes(p, n);
}

int crypto_random_bytes(void *p, size_t n) {
        static bool have_getrandom = true, seen_initialized = false;
        _cleanup_close_ int fd = -1;

        if (n == 0)
                return 0;

        for (;;) {
                ssize_t l;

                if (!have_getrandom)
                        break;

                l = getrandom(p, n, 0);
                if (l > 0) {
                        if ((size_t) l == n)
                                return 0; /* Done reading, success. */
                        p = (uint8_t *) p + l;
                        n -= l;
                        continue; /* Interrupted by a signal; keep going. */
                } else if (l == 0)
                        return -EIO; /* Weird, should never happen. */
                else if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                        have_getrandom = false;
                        break; /* No syscall, so fallback to /dev/urandom. */
                }
                return -errno;
        }

        if (!seen_initialized) {
                _cleanup_close_ int ready_fd = -1;
                int r;

                ready_fd = open("/dev/random", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (ready_fd < 0)
                        return -errno;
                r = fd_wait_for_event(ready_fd, POLLIN, USEC_INFINITY);
                if (r < 0)
                        return r;
                seen_initialized = true;
        }

        fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return -errno;
        return loop_read_exact(fd, p, n, false);
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
