/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hexdecoct.h"
#include "json.h"
#include "luks2-tpm2.h"
#include "parse-util.h"
#include "random-util.h"
#include "tpm2-util.h"

int acquire_luks2_key(
                uint32_t pcr_mask,
                uint16_t pcr_bank,
                uint16_t primary_alg,
                const char *device,
                const void *key_data,
                size_t key_data_size,
                const void *policy_hash,
                size_t policy_hash_size,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        _cleanup_free_ char *auto_device = NULL;
        int r;

        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);

        if (!device) {
                r = tpm2_find_device_auto(LOG_DEBUG, &auto_device);
                if (r == -ENODEV)
                        return -EAGAIN; /* Tell the caller to wait for a TPM2 device to show up */
                if (r < 0)
                        return r;

                device = auto_device;
        }

        return tpm2_unseal(
                        device,
                        pcr_mask, pcr_bank,
                        primary_alg,
                        key_data, key_data_size,
                        policy_hash, policy_hash_size,
                        ret_decrypted_key, ret_decrypted_key_size);
}

/* this function expects valid "systemd-tpm2" in json */
int parse_luks2_tpm2_data(
                const char *json,
                uint32_t search_pcr_mask,
                uint32_t *ret_pcr_mask,
                uint16_t *ret_pcr_bank,
                uint16_t *ret_primary_alg,
                char **ret_base64_blob,
                char **ret_hex_policy_hash) {

        int r;
        JsonVariant *w, *e;
        uint32_t pcr_mask = 0;
        uint16_t pcr_bank = UINT16_MAX, primary_alg = TPM2_ALG_ECC;
        _cleanup_free_ char *base64_blob = NULL, *hex_policy_hash = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        assert(json);
        assert(ret_pcr_mask);
        assert(ret_pcr_bank);
        assert(ret_primary_alg);
        assert(ret_base64_blob);
        assert(ret_hex_policy_hash);

        r = json_parse(json, 0, &v, NULL, NULL);
        if (r < 0)
                return -EINVAL;

        w = json_variant_by_key(v, "tpm2-pcrs");
        if (!w || !json_variant_is_array(w))
                return -EINVAL;

        JSON_VARIANT_ARRAY_FOREACH(e, w) {
                uintmax_t u;

                if (!json_variant_is_number(e))
                        return -EINVAL;

                u = json_variant_unsigned(e);
                if (u >= TPM2_PCRS_MAX)
                        return -EINVAL;

                pcr_mask |= UINT32_C(1) << u;
        }

        if (search_pcr_mask != UINT32_MAX &&
            search_pcr_mask != pcr_mask)
                return -ENXIO;

        w = json_variant_by_key(v, "tpm2-pcr-bank");
        if (w) {
                /* The PCR bank field is optional */

                if (!json_variant_is_string(w))
                        return -EINVAL;

                r = tpm2_pcr_bank_from_string(json_variant_string(w));
                if (r < 0)
                        return r;

                pcr_bank = r;
        }

        w = json_variant_by_key(v, "tpm2-primary-alg");
        if (w) {
                /* The primary key algorithm is optional */

                if (!json_variant_is_string(w))
                        return -EINVAL;

                r = tpm2_primary_alg_from_string(json_variant_string(w));
                if (r < 0)
                        return r;

                primary_alg = r;
        }

        w = json_variant_by_key(v, "tpm2-blob");
        if (!w || !json_variant_is_string(w))
                return -EINVAL;

        base64_blob = strdup(json_variant_string(w));
        if (!base64_blob)
                return -ENOMEM;

        w = json_variant_by_key(v, "tpm2-policy-hash");
        if (!w || !json_variant_is_string(w))
                return -EINVAL;

        hex_policy_hash = strdup(json_variant_string(w));
        if (!hex_policy_hash)
                return -ENOMEM;

        *ret_pcr_mask = pcr_mask;
        *ret_pcr_bank = pcr_bank;
        *ret_primary_alg = primary_alg;
        *ret_base64_blob = TAKE_PTR(base64_blob);
        *ret_hex_policy_hash = TAKE_PTR(hex_policy_hash);

        return 0;
}
