/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/*
 * fsprg v0.1  -  (seekable) forward-secure pseudorandom generator
 * Copyright © 2012 B. Poettering
 * Contact: fsprg@point-at-infinity.org
 */

#include <inttypes.h>
#include <sys/types.h>

#include "macro.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FSPRG_RECOMMENDED_SECPAR 1536
#define FSPRG_RECOMMENDED_SEEDLEN (96/8)

size_t FSPRG_mskinbytes(unsigned secpar) _const_;
size_t FSPRG_mpkinbytes(unsigned secpar) _const_;
size_t FSPRG_stateinbytes(unsigned secpar) _const_;

/* Setup msk and mpk. Providing seed != NULL makes this algorithm deterministic. */
int FSPRG_GenMK(void *msk, void *mpk, const void *seed, size_t seedlen, unsigned secpar);

/* Initialize state deterministically in dependence on seed. */
/* Note: in case one wants to run only one GenState0 per GenMK it is safe to use
   the same seed for both GenMK and GenState0.
*/
int FSPRG_GenState0(void *state, const void *mpk, const void *seed, size_t seedlen);

int FSPRG_Evolve(void *state);

uint64_t FSPRG_GetEpoch(const void *state) _pure_;

/* Seek to any arbitrary state (by providing msk together with seed from GenState0). */
int FSPRG_Seek(void *state, uint64_t epoch, const void *msk, const void *seed, size_t seedlen);

int FSPRG_GetKey(const void *state, void *key, size_t keylen, uint32_t idx);

#ifdef __cplusplus
}
#endif
