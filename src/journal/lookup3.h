/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

#include <inttypes.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "macro.h"

uint32_t jenkins_hashword(const uint32_t *k, size_t length, uint32_t initval) _pure_;
void jenkins_hashword2(const uint32_t *k, size_t length, uint32_t *pc, uint32_t *pb);

uint32_t jenkins_hashlittle(const void *key, size_t length, uint32_t initval) _pure_;
void jenkins_hashlittle2(const void *key, size_t length, uint32_t *pc, uint32_t *pb);

uint32_t jenkins_hashbig(const void *key, size_t length, uint32_t initval) _pure_;

static inline uint64_t hash64(const void *data, size_t length) {
        uint32_t a = 0, b = 0;

        jenkins_hashlittle2(data, length, &a, &b);

        return ((uint64_t) a << 32ULL) | (uint64_t) b;
}

static inline uint64_t hash64v(const struct iovec *iovec, unsigned n_iovec, uint64_t size) {
        uint32_t a = 0, b = 0;

        while (size && n_iovec--) {
                uint64_t hash = MIN(size, iovec->iov_len);

                jenkins_hashlittle2(iovec->iov_base, hash, &a, &b);

                iovec++;
                size -= hash;
        }

        return ((uint64_t) a << 32ULL) | (uint64_t) b;
}
