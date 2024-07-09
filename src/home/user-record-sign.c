/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <openssl/pem.h>

#include "fd-util.h"
#include "fileio.h"
#include "json-util.h"
#include "memstream-util.h"
#include "openssl-util.h"
#include "user-record-sign.h"

static int user_record_signable_json(UserRecord *ur, char **ret) {
        _cleanup_(user_record_unrefp) UserRecord *reduced = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        int r;

        assert(ur);
        assert(ret);

        r = user_record_clone(ur, USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_PRIVILEGED|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_STRIP_SECRET|USER_RECORD_STRIP_BINDING|USER_RECORD_STRIP_STATUS|USER_RECORD_STRIP_SIGNATURE|USER_RECORD_PERMISSIVE, &reduced);
        if (r < 0)
                return r;

        j = sd_json_variant_ref(reduced->json);

        r = sd_json_variant_normalize(&j);
        if (r < 0)
                return r;

        return sd_json_variant_format(j, 0, ret);
}

int user_record_sign(UserRecord *ur, EVP_PKEY *private_key, UserRecord **ret) {
        _cleanup_(memstream_done) MemStream m = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *signed_ur = NULL;
        _cleanup_free_ char *text = NULL, *key = NULL;
        _cleanup_free_ void *signature = NULL;
        size_t signature_size = 0;
        FILE *f;
        int r;

        assert(ur);
        assert(private_key);
        assert(ret);

        r = user_record_signable_json(ur, &text);
        if (r < 0)
                return r;

        r = digest_and_sign(/* md= */ NULL, private_key, text, SIZE_MAX, &signature, &signature_size);
        if (r < 0)
                return r;

        f = memstream_init(&m);
        if (!f)
                return -ENOMEM;

        if (PEM_write_PUBKEY(f, private_key) <= 0)
                return -EIO;

        r = memstream_finalize(&m, &key, NULL);
        if (r < 0)
                return r;

        v = sd_json_variant_ref(ur->json);

        r = sd_json_variant_set_fieldb(
                        &v,
                        "signature",
                        SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("data", SD_JSON_BUILD_BASE64(signature, signature_size)),
                                                             SD_JSON_BUILD_PAIR("key", SD_JSON_BUILD_STRING(key)))));
        if (r < 0)
                return r;

        if (DEBUG_LOGGING)
                sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL);

        signed_ur = user_record_new();
        if (!signed_ur)
                return log_oom();

        r = user_record_load(signed_ur, v, USER_RECORD_LOAD_FULL|USER_RECORD_PERMISSIVE);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(signed_ur);
        return 0;
}

int user_record_verify(UserRecord *ur, EVP_PKEY *public_key) {
        _cleanup_free_ char *text = NULL;
        unsigned n_good = 0, n_bad = 0;
        sd_json_variant *array, *e;
        int r;

        assert(ur);
        assert(public_key);

        array = sd_json_variant_by_key(ur->json, "signature");
        if (!array)
                return USER_RECORD_UNSIGNED;

        if (!sd_json_variant_is_array(array))
                return -EINVAL;

        if (sd_json_variant_elements(array) == 0)
                return USER_RECORD_UNSIGNED;

        r = user_record_signable_json(ur, &text);
        if (r < 0)
                return r;

        JSON_VARIANT_ARRAY_FOREACH(e, array) {
                _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *md_ctx = NULL;
                _cleanup_free_ void *signature = NULL;
                size_t signature_size = 0;
                sd_json_variant *data;

                if (!sd_json_variant_is_object(e))
                        return -EINVAL;

                data = sd_json_variant_by_key(e, "data");
                if (!data)
                        return -EINVAL;

                r = sd_json_variant_unbase64(data, &signature, &signature_size);
                if (r < 0)
                        return r;

                md_ctx = EVP_MD_CTX_new();
                if (!md_ctx)
                        return -ENOMEM;

                if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, public_key) <= 0)
                        return -EIO;

                if (EVP_DigestVerify(md_ctx, signature, signature_size, (uint8_t*) text, strlen(text)) <= 0) {
                        n_bad++;
                        continue;
                }

                n_good++;
        }

        return n_good > 0 ? (n_bad == 0 ? USER_RECORD_SIGNED_EXCLUSIVE : USER_RECORD_SIGNED) :
                (n_bad == 0 ? USER_RECORD_UNSIGNED : USER_RECORD_FOREIGN);
}

int user_record_has_signature(UserRecord *ur) {
        sd_json_variant *array;

        array = sd_json_variant_by_key(ur->json, "signature");
        if (!array)
                return false;

        if (!sd_json_variant_is_array(array))
                return -EINVAL;

        return sd_json_variant_elements(array) > 0;
}
