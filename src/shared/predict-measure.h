/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "crypto-util.h"
#include "forward.h"
#include "uki.h"

#if HAVE_OPENSSL

/* The state of PCR 11 in one bank. */
typedef struct PcrState {
        char *bank;
        const EVP_MD *md;
        void *value;
        size_t value_size;
        void *saved_value;
} PcrState;

void pcr_state_free_all(PcrState **pcr_state);

int measure_normalize_banks(char * const *banks, char ***ret);
int measure_normalize_phases(char * const *phases, char ***ret);

int pcr_states_allocate(char * const *banks, PcrState **ret);
int pcr_states_measure_uki(PcrState *pcr_states, size_t n, const int section_fds[static _UNIFIED_SECTION_MAX]);

int measure_calculate(PcrState *pcr_states, size_t n, char * const *phases, sd_json_variant **ret);
void measure_calculate_print(sd_json_variant *v);

int measure_build_policy(
                PcrState *pcr_states,
                size_t n,
                char * const *phases,
                EVP_PKEY *private_key,
                EVP_PKEY *public_key,
                const char *policyref,
                bool include_tbs,
                sd_json_variant **v);

#endif
