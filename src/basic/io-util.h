/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "macro.h"
#include "time-util.h"

int flush_fd(int fd);

ssize_t loop_read(int fd, void *buf, size_t nbytes, bool do_poll);
int loop_read_exact(int fd, void *buf, size_t nbytes, bool do_poll);
int loop_write(int fd, const void *buf, size_t nbytes, bool do_poll);

int pipe_eof(int fd);

int fd_wait_for_event(int fd, int event, usec_t timeout);

ssize_t sparse_write(int fd, const void *p, size_t sz, size_t run_length);

static inline size_t IOVEC_TOTAL_SIZE(const struct iovec *i, size_t n) {
        size_t j, r = 0;

        for (j = 0; j < n; j++)
                r += i[j].iov_len;

        return r;
}

static inline size_t IOVEC_INCREMENT(struct iovec *i, size_t n, size_t k) {
        size_t j;

        for (j = 0; j < n; j++) {
                size_t sub;

                if (_unlikely_(k <= 0))
                        break;

                sub = MIN(i[j].iov_len, k);
                i[j].iov_len -= sub;
                i[j].iov_base = (uint8_t*) i[j].iov_base + sub;
                k -= sub;
        }

        return k;
}

static inline bool FILE_SIZE_VALID(uint64_t l) {
        /* ftruncate() and friends take an unsigned file size, but actually cannot deal with file sizes larger than
         * 2^63 since the kernel internally handles it as signed value. This call allows checking for this early. */

        return (l >> 63) == 0;
}

static inline bool FILE_SIZE_VALID_OR_INFINITY(uint64_t l) {

        /* Same as above, but allows one extra value: -1 as indication for infinity. */

        if (l == (uint64_t) -1)
                return true;

        return FILE_SIZE_VALID(l);

}

#define IOVEC_INIT(base, len) { .iov_base = (base), .iov_len = (len) }
#define IOVEC_MAKE(base, len) (struct iovec) IOVEC_INIT(base, len)
#define IOVEC_INIT_STRING(string) IOVEC_INIT((char*) string, strlen(string))
#define IOVEC_MAKE_STRING(string) (struct iovec) IOVEC_INIT_STRING(string)

char* set_iovec_string_field(struct iovec *iovec, size_t *n_iovec, const char *field, const char *value);
char* set_iovec_string_field_free(struct iovec *iovec, size_t *n_iovec, const char *field, char *value);

struct iovec_wrapper {
        struct iovec *iovec;
        size_t count;
        size_t size_bytes;
};

struct iovec_wrapper *iovw_new(void);
struct iovec_wrapper *iovw_free(struct iovec_wrapper *iovw);
struct iovec_wrapper *iovw_free_free(struct iovec_wrapper *iovw);
void iovw_free_contents(struct iovec_wrapper *iovw, bool free_vectors);
int iovw_put(struct iovec_wrapper *iovw, void *data, size_t len);
int iovw_put_string_field(struct iovec_wrapper *iovw, const char *field, const char *value);
int iovw_put_string_field_free(struct iovec_wrapper *iovw, const char *field, char *value);
void iovw_rebase(struct iovec_wrapper *iovw, char *old, char *new);
size_t iovw_size(struct iovec_wrapper *iovw);
