/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if SD_BOOT
/* struct iovec is a POSIX userspace construct. Let's introduce it also in EFI mode, it's just so useful */
struct iovec {
        void *iov_base;
        size_t iov_len;
};

static inline void free(void *p);
#endif

/* This accepts both const and non-const pointers */
#define IOVEC_MAKE(base, len)                                           \
        (struct iovec) {                                                \
                .iov_base = (void*) (base),                             \
                .iov_len = (len),                                       \
        }

static inline void iovec_done(struct iovec *iovec) {
        /* A _cleanup_() helper that frees the iov_base in the iovec */
        assert(iovec);

        iovec->iov_base = mfree(iovec->iov_base);
        iovec->iov_len = 0;
}

static inline bool iovec_is_set(const struct iovec *iovec) {
        /* Checks if the iovec points to a non-empty chunk of memory */
        return iovec && iovec->iov_len > 0 && iovec->iov_base;
}

static inline bool iovec_is_valid(const struct iovec *iovec) {
        /* Checks if the iovec is either NULL, empty or points to a valid bit of memory */
        return !iovec || (iovec->iov_base || iovec->iov_len == 0);
}
