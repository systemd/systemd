/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "json-util.h"
#include "log.h"
#include "predict-measure.h"
#include "string-util.h"
#include "strv.h"
#include "tpm2-pcr.h"
#include "tpm2-util.h"

#if HAVE_OPENSSL

void pcr_state_free_all(PcrState **pcr_state) {
        assert(pcr_state);

        if (!*pcr_state)
                return;

        for (size_t i = 0; (*pcr_state)[i].value; i++) {
                free((*pcr_state)[i].bank);
                free((*pcr_state)[i].value);
                free((*pcr_state)[i].saved_value);
        }

        *pcr_state = mfree(*pcr_state);
}

int measure_normalize_banks(char * const *banks, char ***ret) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(ret);

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        STRV_FOREACH(bank, banks) {
                const EVP_MD *implementation = sym_EVP_get_digestbyname(*bank);
                if (!implementation)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown bank '%s'.", *bank);

                if (strv_extend(&l, sym_EVP_MD_get0_name(implementation)) < 0)
                        return log_oom_debug();
        }

        if (strv_isempty(l)) {
                l = strv_free(l);
                l = strv_new("SHA1", "SHA256", "SHA384", "SHA512");
                if (!l)
                        return log_oom_debug();
        }

        strv_sort_uniq(l);

        *ret = TAKE_PTR(l);
        return 0;
}

static char* normalize_phase(const char *s) {
        _cleanup_strv_free_ char **l = NULL;

        /* Removes duplicate, leading and trailing ":" from a phase expression. */

        l = strv_split(s, ":");
        if (!l)
                return NULL;

        return strv_join(strv_remove(l, ""), ":");
}

int measure_normalize_phases(char * const *phases, char ***ret) {
        _cleanup_strv_free_ char **l = NULL;

        assert(ret);

        STRV_FOREACH(phase, phases) {
                char *n = normalize_phase(*phase);
                if (!n)
                        return log_oom_debug();

                if (strv_consume(&l, n) < 0)
                        return log_oom_debug();
        }

        if (strv_isempty(l)) {
                /* Without explicit phases, measure everything from the beginning of the initrd to the
                 * beginning of shutdown. */
                l = strv_free(l);
                l = strv_new("enter-initrd",
                             "enter-initrd:leave-initrd",
                             "enter-initrd:leave-initrd:sysinit",
                             "enter-initrd:leave-initrd:sysinit:ready");
                if (!l)
                        return log_oom_debug();
        } else
                strv_sort_uniq(l);

        *ret = TAKE_PTR(l);
        return 0;
}

int pcr_states_allocate(char * const *banks, PcrState **ret) {
        _cleanup_(pcr_state_free_all) PcrState *pcr_states = NULL;
        size_t n = 0;
        int r;

        assert(ret);

        r = dlopen_libcrypto(LOG_DEBUG);
        if (r < 0)
                return r;

        pcr_states = new0(PcrState, strv_length(banks) + 1);
        if (!pcr_states)
                return log_oom_debug();

        STRV_FOREACH(d, banks) {
                const EVP_MD *implementation = sym_EVP_get_digestbyname(*d);
                if (!implementation)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown bank '%s'.", *d);

                _cleanup_free_ char *b = strdup(sym_EVP_MD_get0_name(implementation));
                if (!b)
                        return log_oom_debug();

                int sz = sym_EVP_MD_get_size(implementation);
                if (sz <= 0 || sz >= INT_MAX)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected digest size: %i", sz);

                /* The initial PCR value is all zeroes. */
                _cleanup_free_ void *v = malloc0(sz);
                if (!v)
                        return log_oom_debug();

                pcr_states[n++] = (struct PcrState) {
                        .bank = ascii_strlower(TAKE_PTR(b)),
                        .md = implementation,
                        .value = TAKE_PTR(v),
                        .value_size = sz,
                };
        }

        *ret = TAKE_PTR(pcr_states);
        return (int) n;
}

static int pcr_state_extend(PcrState *pcr_state, const void *data, size_t sz) {
        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *mc = NULL;
        unsigned value_size;

        assert(pcr_state);
        assert(data || sz == 0);
        assert(pcr_state->md);
        assert(pcr_state->value);
        assert(pcr_state->value_size > 0);

        mc = sym_EVP_MD_CTX_new();
        if (!mc)
                return log_oom_debug();

        if (sym_EVP_DigestInit_ex(mc, pcr_state->md, NULL) != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize %s context.", pcr_state->bank);

        if (sym_EVP_DigestUpdate(mc, pcr_state->value, pcr_state->value_size) != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to run digest.");

        if (sym_EVP_DigestUpdate(mc, data, sz) != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to run digest.");

        if (sym_EVP_DigestFinal_ex(mc, pcr_state->value, &value_size) != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to finalize hash context.");

        assert(value_size == pcr_state->value_size);
        return 0;
}

static void evp_md_ctx_free_all(EVP_MD_CTX **md[]) {
        assert(md);

        if (!*md)
                return;

        for (size_t i = 0; (*md)[i]; i++)
                sym_EVP_MD_CTX_free((*md)[i]);

        *md = mfree(*md);
}

#define BUFFER_SIZE (16U * 1024U)

int pcr_states_measure_uki(PcrState *pcr_states, size_t n, const int section_fds[static _UNIFIED_SECTION_MAX]) {
        _cleanup_free_ void *buffer = NULL;
        int r;

        assert(pcr_states);
        assert(n > 0);
        assert(section_fds);

        buffer = malloc(BUFFER_SIZE);
        if (!buffer)
                return log_oom_debug();

        for (UnifiedSection c = 0; c < _UNIFIED_SECTION_MAX; c++) {
                _cleanup_(evp_md_ctx_free_all) EVP_MD_CTX **mdctx = NULL;
                uint64_t m = 0;

                if (section_fds[c] < 0 || !unified_section_measure(c))
                        continue;

                /* Allocate one message digest context per bank (NULL terminated) */
                mdctx = new0(EVP_MD_CTX*, n + 1);
                if (!mdctx)
                        return log_oom_debug();

                for (size_t i = 0; i < n; i++) {
                        mdctx[i] = sym_EVP_MD_CTX_new();
                        if (!mdctx[i])
                                return log_oom_debug();

                        if (sym_EVP_DigestInit_ex(mdctx[i], pcr_states[i].md, NULL) != 1)
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to initialize data %s context.", pcr_states[i].bank);
                }

                for (;;) {
                        ssize_t sz = pread(section_fds[c], buffer, BUFFER_SIZE, m);
                        /* pread() fails with ESPIPE on pipes and sockets. read() consumes the data of a
                         * pipe or socket, so a pipe or socket section can only be measured once. */
                        if (sz < 0 && errno == ESPIPE)
                                sz = read(section_fds[c], buffer, BUFFER_SIZE);
                        if (sz < 0)
                                return log_debug_errno(errno, "Failed to read %s section: %m", unified_sections[c]);
                        if (sz == 0) /* EOF */
                                break;

                        for (size_t i = 0; i < n; i++)
                                if (sym_EVP_DigestUpdate(mdctx[i], buffer, sz) != 1)
                                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to run digest.");

                        m += sz;
                }

                /* systemd-stub skips empty sections. */
                if (m == 0)
                        continue;

                for (size_t i = 0; i < n; i++) {
                        _cleanup_free_ void *data_hash = NULL;
                        unsigned data_hash_size;

                        data_hash = malloc(pcr_states[i].value_size);
                        if (!data_hash)
                                return log_oom_debug();

                        /* Measure name of section */
                        if (sym_EVP_Digest(unified_sections[c], strlen(unified_sections[c]) + 1, data_hash, &data_hash_size, pcr_states[i].md, NULL) != 1)
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to hash section name with %s.", pcr_states[i].bank);

                        assert(data_hash_size == (unsigned) pcr_states[i].value_size);

                        r = pcr_state_extend(pcr_states + i, data_hash, data_hash_size);
                        if (r < 0)
                                return r;

                        /* Retrieve hash of data and measure it */
                        if (sym_EVP_DigestFinal_ex(mdctx[i], data_hash, &data_hash_size) != 1)
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to finalize hash context.");

                        assert(data_hash_size == (unsigned) pcr_states[i].value_size);

                        r = pcr_state_extend(pcr_states + i, data_hash, data_hash_size);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int pcr_states_measure_phase(PcrState *pcr_states, size_t n, const char *phase) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(pcr_states);
        assert(n > 0);

        /* During boot, each phase word is measured into PCR 11 separately. */

        l = strv_split(phase, ":");
        if (!l)
                return log_oom_debug();

        STRV_FOREACH(word, l) {
                if (isempty(*word))
                        continue;

                size_t wl = strlen(*word);

                for (size_t i = 0; i < n; i++) {
                        int bsz = sym_EVP_MD_get_size(pcr_states[i].md);
                        assert(bsz > 0);

                        _cleanup_free_ void *b = malloc(bsz);
                        if (!b)
                                return log_oom_debug();

                        if (sym_EVP_Digest(*word, wl, b, NULL, pcr_states[i].md, NULL) != 1)
                                return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to hash word '%s'.", *word);

                        r = pcr_state_extend(pcr_states + i, b, bsz);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int pcr_states_save(PcrState *pcr_states, size_t n) {
        assert(pcr_states);
        assert(n > 0);

        for (size_t i = 0; i < n; i++) {
                if (!pcr_states[i].value)
                        continue;

                _cleanup_free_ void *saved = memdup(pcr_states[i].value, pcr_states[i].value_size);
                if (!saved)
                        return log_oom_debug();

                free_and_replace(pcr_states[i].saved_value, saved);
        }

        return 0;
}

static void pcr_states_restore(PcrState *pcr_states, size_t n) {
        assert(pcr_states);
        assert(n > 0);

        for (size_t i = 0; i < n; i++) {
                assert(pcr_states[i].value);
                assert(pcr_states[i].saved_value);

                memcpy(pcr_states[i].value, pcr_states[i].saved_value, pcr_states[i].value_size);
        }
}

int measure_calculate(PcrState *pcr_states, size_t n, char * const *phases, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        int r;

        assert(pcr_states);
        assert(n > 0);
        assert(ret);

        /* The saved state allows calculating each phase starting from the same kernel measurement. */
        r = pcr_states_save(pcr_states, n);
        if (r < 0)
                return r;

        STRV_FOREACH(phase, phases) {
                r = pcr_states_measure_phase(pcr_states, n, *phase);
                if (r < 0)
                        return r;

                for (size_t i = 0; i < n; i++) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;

                        array = sd_json_variant_ref(sd_json_variant_by_key(w, pcr_states[i].bank));

                        r = sd_json_variant_append_arraybo(
                                        &array,
                                        SD_JSON_BUILD_PAIR_CONDITION(!isempty(*phase), "phase", SD_JSON_BUILD_STRING(*phase)),
                                        SD_JSON_BUILD_PAIR_INTEGER("pcr", TPM2_PCR_KERNEL_BOOT),
                                        SD_JSON_BUILD_PAIR_HEX("hash", pcr_states[i].value, pcr_states[i].value_size));
                        if (r < 0)
                                return log_debug_errno(r, "Failed to append JSON object to array: %m");

                        r = sd_json_variant_set_field(&w, pcr_states[i].bank, array);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to add bank info to object: %m");
                }

                pcr_states_restore(pcr_states, n);
        }

        *ret = TAKE_PTR(w);
        return 0;
}

void measure_calculate_print(sd_json_variant *v) {
        size_t n_entries = 0;

        if (sd_json_variant_elements(v) > 0)
                n_entries = sd_json_variant_elements(sd_json_variant_by_index(v, 1));

        for (size_t j = 0; j < n_entries; j++) {
                const char *bank;
                sd_json_variant *array;

                JSON_VARIANT_OBJECT_FOREACH(bank, array, v) {
                        sd_json_variant *e = sd_json_variant_by_index(array, j);
                        int64_t pcr = sd_json_variant_integer(sd_json_variant_by_key(e, "pcr"));

                        /* The description of each phase goes to stderr, the values to stdout. */
                        if (array == sd_json_variant_by_index(v, 1)) {
                                const char *phase = sd_json_variant_string(sd_json_variant_by_key(e, "phase"));

                                fflush(stdout);
                                fprintf(stderr, "%s# PCR[%" PRIi64 "] Phase <%s>%s\n",
                                        ansi_grey(),
                                        pcr,
                                        isempty(phase) ? ":" : phase,
                                        ansi_normal());
                                fflush(stderr);
                        }

                        printf("%" PRIi64 ":%s=%s\n", pcr, bank, sd_json_variant_string(sd_json_variant_by_key(e, "hash")));
                }
        }
}

int measure_build_policy(
                PcrState *pcr_states,
                size_t n,
                char * const *phases,
                EVP_PKEY *private_key,
                EVP_PKEY *public_key,
                const char *policyref,
                bool include_tbs,
                sd_json_variant **v) {

#if HAVE_TPM2
        int r;

        assert(pcr_states);
        assert(n > 0);
        assert(v);

        r = pcr_states_save(pcr_states, n);
        if (r < 0)
                return r;

        STRV_FOREACH(phase, phases) {
                r = pcr_states_measure_phase(pcr_states, n, *phase);
                if (r < 0)
                        return r;

                for (size_t i = 0; i < n; i++) {
                        PcrState *p = pcr_states + i;

                        int tpmalg = tpm2_hash_alg_from_string(sym_EVP_MD_get0_name(p->md));
                        if (tpmalg < 0)
                                return log_debug_errno(tpmalg, "Unsupported PCR bank");

                        Tpm2PCRValue pcr_value = TPM2_PCR_VALUE_MAKE(TPM2_PCR_KERNEL_BOOT,
                                                                     tpmalg,
                                                                     TPM2B_DIGEST_MAKE(p->value, p->value_size));

                        TPM2B_DIGEST pcr_policy_digest = TPM2B_DIGEST_MAKE(NULL, TPM2_SHA256_DIGEST_SIZE);

                        r = tpm2_calculate_policy_pcr(&pcr_value, 1, &pcr_policy_digest);
                        if (r < 0)
                                return log_debug_errno(r, "Could not calculate PolicyPCR digest: %m");

                        _cleanup_(iovec_done) struct iovec tbs_data = {};
                        r = tpm2_make_policy_authorize_tbs_data(&pcr_policy_digest, policyref, &tbs_data);
                        if (r < 0)
                                return r;

                        _cleanup_free_ void *sig = NULL;
                        size_t ss = 0;
                        if (private_key) {
                                /* The signature always uses SHA256, regardless of the bank. */
                                const EVP_MD *sha256 = ASSERT_PTR(sym_EVP_get_digestbyname("sha256"));

                                r = digest_and_sign(sha256, private_key, tbs_data.iov_base, tbs_data.iov_len, &sig, &ss);
                                if (r == -EADDRNOTAVAIL)
                                        return log_debug_errno(r, "Hash algorithm '%s' not available while signing. (Maybe OS security policy disables this algorithm?)", sym_EVP_MD_get0_name(sha256));
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to sign PCR policy with hash algorithm '%s': %m", sym_EVP_MD_get0_name(sha256));
                        }

                        _cleanup_free_ void *pubkey_fp = NULL;
                        size_t pubkey_fp_size = 0;
                        if (public_key) {
                                r = pubkey_fingerprint(public_key, sym_EVP_sha256(), &pubkey_fp, &pubkey_fp_size);
                                if (r < 0)
                                        return r;
                        }

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL;
                        r = tpm2_make_pcr_json_array(UINT64_C(1) << TPM2_PCR_KERNEL_BOOT, &a);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to build JSON PCR mask array: %m");

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *bv = NULL;
                        r = sd_json_buildo(&bv,
                                           SD_JSON_BUILD_PAIR_VARIANT("pcrs", a),                                                                     /* PCR mask */
                                           SD_JSON_BUILD_PAIR_CONDITION(pubkey_fp_size > 0, "pkfp", SD_JSON_BUILD_HEX(pubkey_fp, pubkey_fp_size)),    /* SHA256 fingerprint of public key (DER) used for the signature */
                                           SD_JSON_BUILD_PAIR_CONDITION(!isempty(policyref), "ref", SD_JSON_BUILD_STRING(policyref)),                 /* TPM2 policy reference */
                                           SD_JSON_BUILD_PAIR_HEX("pol", pcr_policy_digest.buffer, pcr_policy_digest.size),                           /* TPM2 PolicyPCR digest */
                                           SD_JSON_BUILD_PAIR_CONDITION(include_tbs, "tbs", SD_JSON_BUILD_HEX(tbs_data.iov_base, tbs_data.iov_len)),  /* data to sign offline */
                                           SD_JSON_BUILD_PAIR_CONDITION(ss > 0, "sig", SD_JSON_BUILD_BASE64(sig, ss)));                               /* signature data */
                        if (r < 0)
                                return log_debug_errno(r, "Failed to build JSON object: %m");

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *av = NULL;
                        av = sd_json_variant_ref(sd_json_variant_by_key(*v, p->bank));

                        r = sd_json_variant_append_array_nodup(&av, bv);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to append JSON object: %m");

                        r = sd_json_variant_set_field(v, p->bank, av);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to add JSON field: %m");
                }

                pcr_states_restore(pcr_states, n);
        }

        return 0;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "TPM2 support is not compiled in.");
#endif
}

#endif
