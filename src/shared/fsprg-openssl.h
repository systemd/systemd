/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

#define FSPRG_RECOMMENDED_SECPAR 1536
#define FSPRG_RECOMMENDED_SEEDLEN (96/8)

bool fsprg_secpar_is_valid(uint16_t secpar);
size_t fsprg_state_size(uint16_t secpar);
int fsprg_generate_state(
                uint16_t secpar,
                uint64_t epoch,
                const struct iovec *seed,
                struct iovec *state);
int fsprg_evolve(struct iovec *state);
int fsprg_get_epoch(const struct iovec *state, uint64_t *ret);
int fsprg_get_key(const struct iovec *state, struct iovec *key);
