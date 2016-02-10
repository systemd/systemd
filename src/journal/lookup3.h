#pragma once

#include <inttypes.h>
#include <sys/types.h>

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
