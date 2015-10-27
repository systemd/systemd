/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef __fsprgh__
#define __fsprgh__

/*
 * fsprg v0.1  -  (seekable) forward-secure pseudorandom generator
 * Copyright (C) 2012 B. Poettering
 * Contact: fsprg@point-at-infinity.org
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 *
 */

#include <sys/types.h>
#include <inttypes.h>

#include "macro.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FSPRG_RECOMMENDED_SECPAR 1536
#define FSPRG_RECOMMENDED_SEEDLEN (96/8)

size_t FSPRG_mskinbytes(unsigned secpar) _const_;
size_t FSPRG_mpkinbytes(unsigned secpar) _const_;
size_t FSPRG_stateinbytes(unsigned secpar) _const_;

/* Setup msk and mpk. Providing seed != NULL makes this algorithm deterministic. */
void FSPRG_GenMK(void *msk, void *mpk, const void *seed, size_t seedlen, unsigned secpar);

/* Initialize state deterministically in dependence on seed. */
/* Note: in case one wants to run only one GenState0 per GenMK it is safe to use
   the same seed for both GenMK and GenState0.
*/
void FSPRG_GenState0(void *state, const void *mpk, const void *seed, size_t seedlen);

void FSPRG_Evolve(void *state);

uint64_t FSPRG_GetEpoch(const void *state) _pure_;

/* Seek to any arbitrary state (by providing msk together with seed from GenState0). */
void FSPRG_Seek(void *state, uint64_t epoch, const void *msk, const void *seed, size_t seedlen);

void FSPRG_GetKey(const void *state, void *key, size_t keylen, uint32_t idx);

#ifdef __cplusplus
}
#endif

#endif
