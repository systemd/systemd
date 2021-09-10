/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "extract-word.h"
#include "parse-util.h"
#include "tpm2-util.h"

#if HAVE_TPM2
#include "alloc-util.h"
#include "dirent-util.h"
#include "dlfcn-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "memory-util.h"
#include "random-util.h"
#include "time-util.h"

static void *libtss2_esys_dl = NULL;
static void *libtss2_rc_dl = NULL;
static void *libtss2_mu_dl = NULL;

TSS2_RC (*sym_Esys_Create)(ESYS_CONTEXT *esysContext, ESYS_TR parentHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_SENSITIVE_CREATE *inSensitive, const TPM2B_PUBLIC *inPublic, const TPM2B_DATA *outsideInfo, const TPML_PCR_SELECTION *creationPCR, TPM2B_PRIVATE **outPrivate, TPM2B_PUBLIC **outPublic, TPM2B_CREATION_DATA **creationData, TPM2B_DIGEST **creationHash, TPMT_TK_CREATION **creationTicket) = NULL;
TSS2_RC (*sym_Esys_CreatePrimary)(ESYS_CONTEXT *esysContext, ESYS_TR primaryHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_SENSITIVE_CREATE *inSensitive, const TPM2B_PUBLIC *inPublic, const TPM2B_DATA *outsideInfo, const TPML_PCR_SELECTION *creationPCR, ESYS_TR *objectHandle, TPM2B_PUBLIC **outPublic, TPM2B_CREATION_DATA **creationData, TPM2B_DIGEST **creationHash, TPMT_TK_CREATION **creationTicket) = NULL;
void (*sym_Esys_Finalize)(ESYS_CONTEXT **context) = NULL;
TSS2_RC (*sym_Esys_FlushContext)(ESYS_CONTEXT *esysContext, ESYS_TR flushHandle) = NULL;
void (*sym_Esys_Free)(void *ptr) = NULL;
TSS2_RC (*sym_Esys_GetRandom)(ESYS_CONTEXT *esysContext, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, UINT16 bytesRequested, TPM2B_DIGEST **randomBytes) = NULL;
TSS2_RC (*sym_Esys_Initialize)(ESYS_CONTEXT **esys_context,  TSS2_TCTI_CONTEXT *tcti, TSS2_ABI_VERSION *abiVersion) = NULL;
TSS2_RC (*sym_Esys_Load)(ESYS_CONTEXT *esysContext, ESYS_TR parentHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_PRIVATE *inPrivate, const TPM2B_PUBLIC *inPublic, ESYS_TR *objectHandle) = NULL;
TSS2_RC (*sym_Esys_PolicyGetDigest)(ESYS_CONTEXT *esysContext, ESYS_TR policySession, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, TPM2B_DIGEST **policyDigest) = NULL;
TSS2_RC (*sym_Esys_PolicyPCR)(ESYS_CONTEXT *esysContext, ESYS_TR policySession, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_DIGEST *pcrDigest, const TPML_PCR_SELECTION *pcrs) = NULL;
TSS2_RC (*sym_Esys_StartAuthSession)(ESYS_CONTEXT *esysContext, ESYS_TR tpmKey, ESYS_TR bind, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_NONCE *nonceCaller, TPM2_SE sessionType, const TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH authHash, ESYS_TR *sessionHandle) = NULL;
TSS2_RC (*sym_Esys_Startup)(ESYS_CONTEXT *esysContext, TPM2_SU startupType) = NULL;
TSS2_RC (*sym_Esys_Unseal)(ESYS_CONTEXT *esysContext, ESYS_TR itemHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, TPM2B_SENSITIVE_DATA **outData) = NULL;

const char* (*sym_Tss2_RC_Decode)(TSS2_RC rc) = NULL;

TSS2_RC (*sym_Tss2_MU_TPM2B_PRIVATE_Marshal)(TPM2B_PRIVATE const *src, uint8_t buffer[], size_t buffer_size, size_t *offset) = NULL;
TSS2_RC (*sym_Tss2_MU_TPM2B_PRIVATE_Unmarshal)(uint8_t const buffer[], size_t buffer_size, size_t *offset, TPM2B_PRIVATE  *dest) = NULL;
TSS2_RC (*sym_Tss2_MU_TPM2B_PUBLIC_Marshal)(TPM2B_PUBLIC const *src, uint8_t buffer[], size_t buffer_size, size_t *offset) = NULL;
TSS2_RC (*sym_Tss2_MU_TPM2B_PUBLIC_Unmarshal)(uint8_t const buffer[], size_t buffer_size, size_t *offset, TPM2B_PUBLIC *dest) = NULL;

int dlopen_tpm2(void) {
        int r;

        r = dlopen_many_sym_or_warn(
                        &libtss2_esys_dl, "libtss2-esys.so.0", LOG_DEBUG,
                        DLSYM_ARG(Esys_Create),
                        DLSYM_ARG(Esys_CreatePrimary),
                        DLSYM_ARG(Esys_Finalize),
                        DLSYM_ARG(Esys_FlushContext),
                        DLSYM_ARG(Esys_Free),
                        DLSYM_ARG(Esys_GetRandom),
                        DLSYM_ARG(Esys_Initialize),
                        DLSYM_ARG(Esys_Load),
                        DLSYM_ARG(Esys_PolicyGetDigest),
                        DLSYM_ARG(Esys_PolicyPCR),
                        DLSYM_ARG(Esys_StartAuthSession),
                        DLSYM_ARG(Esys_Startup),
                        DLSYM_ARG(Esys_Unseal));
        if (r < 0)
                return r;

        r = dlopen_many_sym_or_warn(
                        &libtss2_rc_dl, "libtss2-rc.so.0", LOG_DEBUG,
                        DLSYM_ARG(Tss2_RC_Decode));
        if (r < 0)
                return r;

        return dlopen_many_sym_or_warn(
                        &libtss2_mu_dl, "libtss2-mu.so.0", LOG_DEBUG,
                        DLSYM_ARG(Tss2_MU_TPM2B_PRIVATE_Marshal),
                        DLSYM_ARG(Tss2_MU_TPM2B_PRIVATE_Unmarshal),
                        DLSYM_ARG(Tss2_MU_TPM2B_PUBLIC_Marshal),
                        DLSYM_ARG(Tss2_MU_TPM2B_PUBLIC_Unmarshal));
}

struct tpm2_context {
        ESYS_CONTEXT *esys_context;
        void *tcti_dl;
        TSS2_TCTI_CONTEXT *tcti_context;
};

static void tpm2_context_destroy(struct tpm2_context *c) {
        assert(c);

        if (c->esys_context)
                sym_Esys_Finalize(&c->esys_context);

        c->tcti_context = mfree(c->tcti_context);

        if (c->tcti_dl) {
                dlclose(c->tcti_dl);
                c->tcti_dl = NULL;
        }
}

static inline void Esys_Finalize_wrapper(ESYS_CONTEXT **c) {
        /* A wrapper around Esys_Finalize() for use with _cleanup_(). Only reasons we need this wrapper is
         * because the function itself warn logs if we'd pass a pointer to NULL, and we don't want that. */
        if (*c)
                sym_Esys_Finalize(c);
}

static inline void Esys_Freep(void *p) {
        if (*(void**) p)
                sym_Esys_Free(*(void**) p);
}

static ESYS_TR flush_context_verbose(ESYS_CONTEXT *c, ESYS_TR handle) {
        TSS2_RC rc;

        if (!c || handle == ESYS_TR_NONE)
                return ESYS_TR_NONE;

        rc = sym_Esys_FlushContext(c, handle);
        if (rc != TSS2_RC_SUCCESS) /* We ignore failures here (besides debug logging), since this is called
                                    * in error paths, where we cannot do anything about failures anymore. And
                                    * when it is called in successful codepaths by this time we already did
                                    * what we wanted to do, and got the results we wanted so there's no
                                    * reason to make this fail more loudly than necessary. */
                log_debug("Failed to get flush context of TPM, ignoring: %s", sym_Tss2_RC_Decode(rc));

        return ESYS_TR_NONE;
}

static int tpm2_init(const char *device, struct tpm2_context *ret) {
        _cleanup_(Esys_Finalize_wrapper) ESYS_CONTEXT *c = NULL;
        _cleanup_free_ TSS2_TCTI_CONTEXT *tcti = NULL;
        _cleanup_(dlclosep) void *dl = NULL;
        TSS2_RC rc;
        int r;

        r = dlopen_tpm2();
        if (r < 0)
                return log_error_errno(r, "TPM2 support not installed: %m");

        if (!device)
                device = secure_getenv("SYSTEMD_TPM2_DEVICE");

        if (device) {
                const char *param, *driver, *fn;
                const TSS2_TCTI_INFO* info;
                TSS2_TCTI_INFO_FUNC func;
                size_t sz = 0;

                param = strchr(device, ':');
                if (param) {
                        driver = strndupa(device, param - device);
                        param++;
                } else {
                        driver = "device";
                        param = device;
                }

                fn = strjoina("libtss2-tcti-", driver, ".so.0");

                dl = dlopen(fn, RTLD_NOW);
                if (!dl)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to load %s: %s", fn, dlerror());

                func = dlsym(dl, TSS2_TCTI_INFO_SYMBOL);
                if (!func)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "Failed to find TCTI info symbol " TSS2_TCTI_INFO_SYMBOL ": %s",
                                               dlerror());

                info = func();
                if (!info)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Unable to get TCTI info data.");


                log_debug("Loaded TCTI module '%s' (%s) [Version %" PRIu32 "]", info->name, info->description, info->version);

                rc = info->init(NULL, &sz, NULL);
                if (rc != TPM2_RC_SUCCESS)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "Failed to initialize TCTI context: %s", sym_Tss2_RC_Decode(rc));

                tcti = malloc0(sz);
                if (!tcti)
                        return log_oom();

                rc = info->init(tcti, &sz, param);
                if (rc != TPM2_RC_SUCCESS)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "Failed to initialize TCTI context: %s", sym_Tss2_RC_Decode(rc));
        }

        rc = sym_Esys_Initialize(&c, tcti, NULL);
        if (rc != TSS2_RC_SUCCESS)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Failed to initialize TPM context: %s", sym_Tss2_RC_Decode(rc));

        rc = sym_Esys_Startup(c, TPM2_SU_CLEAR);
        if (rc == TPM2_RC_INITIALIZE)
                log_debug("TPM already started up.");
        else if (rc == TSS2_RC_SUCCESS)
                log_debug("TPM successfully started up.");
        else
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Failed to start up TPM: %s", sym_Tss2_RC_Decode(rc));

        *ret = (struct tpm2_context) {
                .esys_context = TAKE_PTR(c),
                .tcti_context = TAKE_PTR(tcti),
                .tcti_dl = TAKE_PTR(dl),
        };

        return 0;
}

static int tpm2_credit_random(ESYS_CONTEXT *c) {
        size_t rps, done = 0;
        TSS2_RC rc;
        int r;

        assert(c);

        /* Pulls some entropy from the TPM and adds it into the kernel RNG pool. That way we can say that the
         * key we will ultimately generate with the kernel random pool is at least as good as the TPM's RNG,
         * but likely better. Note that we don't trust the TPM RNG very much, hence do not actually credit
         * any entropy. */

        for (rps = random_pool_size(); rps > 0;) {
                _cleanup_(Esys_Freep) TPM2B_DIGEST *buffer = NULL;

                rc = sym_Esys_GetRandom(
                                c,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                MIN(rps, 32U), /* 32 is supposedly a safe choice, given that AES 256bit keys are this long, and TPM2 baseline requires support for those. */
                                &buffer);
                if (rc != TSS2_RC_SUCCESS)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "Failed to acquire entropy from TPM: %s", sym_Tss2_RC_Decode(rc));

                if (buffer->size == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "Zero-sized entropy returned from TPM.");

                r = random_write_entropy(-1, buffer->buffer, buffer->size, false);
                if (r < 0)
                        return log_error_errno(r, "Failed wo write entropy to kernel: %m");

                done += buffer->size;
                rps = LESS_BY(rps, buffer->size);
        }

        log_debug("Added %zu bytes of entropy to the kernel random pool.", done);
        return 0;
}

static int tpm2_make_primary(
                ESYS_CONTEXT *c,
                ESYS_TR *ret_primary) {

        static const TPM2B_SENSITIVE_CREATE primary_sensitive = {};
        static const TPM2B_PUBLIC primary_template = {
                .size = sizeof(TPMT_PUBLIC),
                .publicArea = {
                        .type = TPM2_ALG_ECC,
                        .nameAlg = TPM2_ALG_SHA256,
                        .objectAttributes = TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH,
                        .parameters = {
                                .eccDetail = {
                                        .symmetric = {
                                                .algorithm = TPM2_ALG_AES,
                                                .keyBits.aes = 128,
                                                .mode.aes = TPM2_ALG_CFB,
                                        },
                                        .scheme.scheme = TPM2_ALG_NULL,
                                        .curveID = TPM2_ECC_NIST_P256,
                                        .kdf.scheme = TPM2_ALG_NULL,
                                },
                        },
                },
        };
        static const TPML_PCR_SELECTION creation_pcr = {};
        ESYS_TR primary = ESYS_TR_NONE;
        TSS2_RC rc;

        log_debug("Creating primary key on TPM.");

        rc = sym_Esys_CreatePrimary(
                        c,
                        ESYS_TR_RH_OWNER,
                        ESYS_TR_PASSWORD,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &primary_sensitive,
                        &primary_template,
                        NULL,
                        &creation_pcr,
                        &primary,
                        NULL,
                        NULL,
                        NULL,
                        NULL);

        if (rc != TSS2_RC_SUCCESS)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Failed to generate primary key in TPM: %s", sym_Tss2_RC_Decode(rc));

        log_debug("Successfully created primary key on TPM.");

        *ret_primary = primary;
        return 0;
}

static int tpm2_make_pcr_session(
                ESYS_CONTEXT *c,
                uint32_t pcr_mask,
                ESYS_TR *ret_session,
                TPM2B_DIGEST **ret_policy_digest) {

        static const TPMT_SYM_DEF symmetric = {
                .algorithm = TPM2_ALG_AES,
                .keyBits = {
                        .aes = 128
                },
                .mode = {
                        .aes = TPM2_ALG_CFB,
                }
        };
        TPML_PCR_SELECTION pcr_selection = {
                .count = 1,
                .pcrSelections[0].hash = TPM2_ALG_SHA256,
                .pcrSelections[0].sizeofSelect = 3,
                .pcrSelections[0].pcrSelect[0] = pcr_mask & 0xFF,
                .pcrSelections[0].pcrSelect[1] = (pcr_mask >> 8) & 0xFF,
                .pcrSelections[0].pcrSelect[2] = (pcr_mask >> 16) & 0xFF,
        };
        _cleanup_(Esys_Freep) TPM2B_DIGEST *policy_digest = NULL;
        ESYS_TR session = ESYS_TR_NONE;
        TSS2_RC rc;
        int r;

        assert(c);

        log_debug("Starting authentication session.");

        rc = sym_Esys_StartAuthSession(
                        c,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        NULL,
                        TPM2_SE_POLICY,
                        &symmetric,
                        TPM2_ALG_SHA256,
                        &session);
        if (rc != TSS2_RC_SUCCESS)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Failed to open session in TPM: %s", sym_Tss2_RC_Decode(rc));

        log_debug("Configuring PCR policy.");

        rc = sym_Esys_PolicyPCR(
                        c,
                        session,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        NULL,
                        &pcr_selection);
        if (rc != TSS2_RC_SUCCESS) {
                r = log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                    "Failed to add PCR policy to TPM: %s", sym_Tss2_RC_Decode(rc));
                goto finish;
        }

        if (DEBUG_LOGGING || ret_policy_digest) {
                log_debug("Acquiring policy digest.");

                rc = sym_Esys_PolicyGetDigest(
                                c,
                                session,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                &policy_digest);

                if (rc != TSS2_RC_SUCCESS) {
                        r = log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                            "Failed to get policy digest from TPM: %s", sym_Tss2_RC_Decode(rc));
                        goto finish;
                }

                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *h = NULL;

                        h = hexmem(policy_digest->buffer, policy_digest->size);
                        if (!h) {
                                r = log_oom();
                                goto finish;
                        }

                        log_debug("Session policy digest: %s", h);
                }
        }

        if (ret_session) {
                *ret_session = session;
                session = ESYS_TR_NONE;
        }

        if (ret_policy_digest)
                *ret_policy_digest = TAKE_PTR(policy_digest);

        r = 0;

finish:
        session = flush_context_verbose(c, session);
        return r;
}

int tpm2_seal(
                const char *device,
                uint32_t pcr_mask,
                void **ret_secret,
                size_t *ret_secret_size,
                void **ret_blob,
                size_t *ret_blob_size,
                void **ret_pcr_hash,
                size_t *ret_pcr_hash_size) {

        _cleanup_(tpm2_context_destroy) struct tpm2_context c = {};
        _cleanup_(Esys_Freep) TPM2B_DIGEST *policy_digest = NULL;
        _cleanup_(Esys_Freep) TPM2B_PRIVATE *private = NULL;
        _cleanup_(Esys_Freep) TPM2B_PUBLIC *public = NULL;
        static const TPML_PCR_SELECTION creation_pcr = {};
        _cleanup_(erase_and_freep) void *secret = NULL;
        _cleanup_free_ void *blob = NULL, *hash = NULL;
        TPM2B_SENSITIVE_CREATE hmac_sensitive;
        ESYS_TR primary = ESYS_TR_NONE;
        TPM2B_PUBLIC hmac_template;
        size_t k, blob_size;
        usec_t start;
        TSS2_RC rc;
        int r;

        assert(ret_secret);
        assert(ret_secret_size);
        assert(ret_blob);
        assert(ret_blob_size);
        assert(ret_pcr_hash);
        assert(ret_pcr_hash_size);

        assert(pcr_mask < (UINT32_C(1) << TPM2_PCRS_MAX)); /* Support 24 PCR banks */

        /* So here's what we do here: we connect to the TPM2 chip. It persistently contains a "seed" key that
         * is randomized when the TPM2 is first initialized or reset and remains stable across boots. We
         * generate a "primary" key pair derived from that (RSA). Given the seed remains fixed this will
         * result in the same key pair whenever we specify the exact same parameters for it. We then create a
         * PCR-bound policy session, which calculates a hash on the current PCR values of the indexes we
         * specify. We then generate a randomized key on the host (which is the key we actually enroll in the
         * LUKS2 keyslots), which we upload into the TPM2, where it is encrypted with the "primary" key,
         * taking the PCR policy session into account. We then download the encrypted key from the TPM2
         * ("sealing") and marshall it into binary form, which is ultimately placed in the LUKS2 JSON header.
         *
         * The TPM2 "seed" key and "primary" keys never leave the TPM2 chip (and cannot be extracted at
         * all). The random key we enroll in LUKS2 we generate on the host using the Linux random device. It
         * is stored in the LUKS2 JSON only in encrypted form with the "primary" key of the TPM2 chip, thus
         * binding the unlocking to the TPM2 chip. */

        start = now(CLOCK_MONOTONIC);

        r = tpm2_init(device, &c);
        if (r < 0)
                return r;

        r = tpm2_make_primary(c.esys_context, &primary);
        if (r < 0)
                return r;

        r = tpm2_make_pcr_session(c.esys_context, pcr_mask, NULL, &policy_digest);
        if (r < 0)
                goto finish;

        /* We use a keyed hash object (i.e. HMAC) to store the secret key we want to use for unlocking the
         * LUKS2 volume with. We don't ever use for HMAC/keyed hash operations however, we just use it
         * because it's a key type that is universally supported and suitable for symmetric binary blobs. */
        hmac_template = (TPM2B_PUBLIC) {
                .size = sizeof(TPMT_PUBLIC),
                .publicArea = {
                        .type = TPM2_ALG_KEYEDHASH,
                        .nameAlg = TPM2_ALG_SHA256,
                        .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT,
                        .parameters = {
                                .keyedHashDetail = {
                                        .scheme.scheme = TPM2_ALG_NULL,
                                },
                        },
                        .unique = {
                                .keyedHash = {
                                        .size = 32,
                                },
                        },
                        .authPolicy = *policy_digest,
                },
        };

        hmac_sensitive = (TPM2B_SENSITIVE_CREATE) {
                .size = sizeof(hmac_sensitive.sensitive),
                .sensitive.data.size = 32,
        };
        assert(sizeof(hmac_sensitive.sensitive.data.buffer) >= hmac_sensitive.sensitive.data.size);

        (void) tpm2_credit_random(c.esys_context);

        log_debug("Generating secret key data.");

        r = genuine_random_bytes(hmac_sensitive.sensitive.data.buffer, hmac_sensitive.sensitive.data.size, RANDOM_BLOCK);
        if (r < 0) {
                log_error_errno(r, "Failed to generate secret key: %m");
                goto finish;
        }

        log_debug("Creating HMAC key.");

        rc = sym_Esys_Create(
                        c.esys_context,
                        primary,
                        ESYS_TR_PASSWORD,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &hmac_sensitive,
                        &hmac_template,
                        NULL,
                        &creation_pcr,
                        &private,
                        &public,
                        NULL,
                        NULL,
                        NULL);
        if (rc != TSS2_RC_SUCCESS) {
                r = log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                    "Failed to generate HMAC key in TPM: %s", sym_Tss2_RC_Decode(rc));
                goto finish;
        }

        secret = memdup(hmac_sensitive.sensitive.data.buffer, hmac_sensitive.sensitive.data.size);
        explicit_bzero_safe(hmac_sensitive.sensitive.data.buffer, hmac_sensitive.sensitive.data.size);
        if (!secret) {
                r = log_oom();
                goto finish;
        }

        log_debug("Marshalling private and public part of HMAC key.");

        k = ALIGN8(sizeof(*private)) + ALIGN8(sizeof(*public)); /* Some roughly sensible start value */
        for (;;) {
                _cleanup_free_ void *buf = NULL;
                size_t offset = 0;

                buf = malloc(k);
                if (!buf) {
                        r = log_oom();
                        goto finish;
                }

                rc = sym_Tss2_MU_TPM2B_PRIVATE_Marshal(private, buf, k, &offset);
                if (rc == TSS2_RC_SUCCESS) {
                        rc = sym_Tss2_MU_TPM2B_PUBLIC_Marshal(public, buf, k, &offset);
                        if (rc == TSS2_RC_SUCCESS) {
                                blob = TAKE_PTR(buf);
                                blob_size = offset;
                                break;
                        }
                }
                if (rc != TSS2_MU_RC_INSUFFICIENT_BUFFER) {
                        r = log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                            "Failed to marshal private/public key: %s", sym_Tss2_RC_Decode(rc));
                        goto finish;
                }

                if (k > SIZE_MAX / 2) {
                        r = log_oom();
                        goto finish;
                }

                k *= 2;
        }

        hash = memdup(policy_digest->buffer, policy_digest->size);
        if (!hash)
                return log_oom();

        if (DEBUG_LOGGING) {
                char buf[FORMAT_TIMESPAN_MAX];
                log_debug("Completed TPM2 key sealing in %s.", format_timespan(buf, sizeof(buf), now(CLOCK_MONOTONIC) - start, 1));
        }

        *ret_secret = TAKE_PTR(secret);
        *ret_secret_size = hmac_sensitive.sensitive.data.size;
        *ret_blob = TAKE_PTR(blob);
        *ret_blob_size = blob_size;
        *ret_pcr_hash = TAKE_PTR(hash);
        *ret_pcr_hash_size = policy_digest->size;

        r = 0;

finish:
        primary = flush_context_verbose(c.esys_context, primary);
        return r;
}

int tpm2_unseal(
                const char *device,
                uint32_t pcr_mask,
                const void *blob,
                size_t blob_size,
                const void *known_policy_hash,
                size_t known_policy_hash_size,
                void **ret_secret,
                size_t *ret_secret_size) {

        _cleanup_(tpm2_context_destroy) struct tpm2_context c = {};
        ESYS_TR primary = ESYS_TR_NONE, session = ESYS_TR_NONE, hmac_key = ESYS_TR_NONE;
        _cleanup_(Esys_Freep) TPM2B_SENSITIVE_DATA* unsealed = NULL;
        _cleanup_(Esys_Freep) TPM2B_DIGEST *policy_digest = NULL;
        _cleanup_(erase_and_freep) char *secret = NULL;
        TPM2B_PRIVATE private = {};
        TPM2B_PUBLIC public = {};
        size_t offset = 0;
        TSS2_RC rc;
        usec_t start;
        int r;

        assert(blob);
        assert(blob_size > 0);
        assert(known_policy_hash_size == 0 || known_policy_hash);
        assert(ret_secret);
        assert(ret_secret_size);

        assert(pcr_mask < (UINT32_C(1) << TPM2_PCRS_MAX)); /* Support 24 PCR banks */

        r = dlopen_tpm2();
        if (r < 0)
                return log_error_errno(r, "TPM2 support is not installed.");

        /* So here's what we do here: We connect to the TPM2 chip. As we do when sealing we generate a
         * "primary" key on the TPM2 chip, with the same parameters as well as a PCR-bound policy
         * session. Given we pass the same parameters, this will result in the same "primary" key, and same
         * policy hash (the latter of course, only if the PCR values didn't change in between). We unmarshal
         * the encrypted key we stored in the LUKS2 JSON token header and upload it into the TPM2, where it
         * is decrypted if the seed and the PCR policy were right ("unsealing"). We then download the result,
         * and use it to unlock the LUKS2 volume. */

        start = now(CLOCK_MONOTONIC);

        log_debug("Unmarshalling private part of HMAC key.");

        rc = sym_Tss2_MU_TPM2B_PRIVATE_Unmarshal(blob, blob_size, &offset, &private);
        if (rc != TSS2_RC_SUCCESS)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Failed to unmarshal private key: %s", sym_Tss2_RC_Decode(rc));

        log_debug("Unmarshalling public part of HMAC key.");

        rc = sym_Tss2_MU_TPM2B_PUBLIC_Unmarshal(blob, blob_size, &offset, &public);
        if (rc != TSS2_RC_SUCCESS)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Failed to unmarshal public key: %s", sym_Tss2_RC_Decode(rc));

        r = tpm2_init(device, &c);
        if (r < 0)
                return r;

        r = tpm2_make_pcr_session(c.esys_context, pcr_mask, &session, &policy_digest);
        if (r < 0)
                goto finish;

        /* If we know the policy hash to expect, and it doesn't match, we can shortcut things here, and not
         * wait until the TPM2 tells us to go away. */
        if (known_policy_hash_size > 0 &&
            memcmp_nn(policy_digest->buffer, policy_digest->size, known_policy_hash, known_policy_hash_size) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                       "Current policy digest does not match stored policy digest, cancelling TPM2 authentication attempt.");

        r = tpm2_make_primary(c.esys_context, &primary);
        if (r < 0)
                return r;

        log_debug("Loading HMAC key into TPM.");

        rc = sym_Esys_Load(
                        c.esys_context,
                        primary,
                        ESYS_TR_PASSWORD,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &private,
                        &public,
                        &hmac_key);
        if (rc != TSS2_RC_SUCCESS) {
                r = log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                    "Failed to load HMAC key in TPM: %s", sym_Tss2_RC_Decode(rc));
                goto finish;
        }

        log_debug("Unsealing HMAC key.");

        rc = sym_Esys_Unseal(
                        c.esys_context,
                        hmac_key,
                        session,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &unsealed);
        if (rc != TSS2_RC_SUCCESS) {
                r = log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                    "Failed to unseal HMAC key in TPM: %s", sym_Tss2_RC_Decode(rc));
                goto finish;
        }

        secret = memdup(unsealed->buffer, unsealed->size);
        explicit_bzero_safe(unsealed->buffer, unsealed->size);
        if (!secret) {
                r = log_oom();
                goto finish;
        }

        if (DEBUG_LOGGING) {
                char buf[FORMAT_TIMESPAN_MAX];
                log_debug("Completed TPM2 key unsealing in %s.", format_timespan(buf, sizeof(buf), now(CLOCK_MONOTONIC) - start, 1));
        }

        *ret_secret = TAKE_PTR(secret);
        *ret_secret_size = unsealed->size;

        r = 0;

finish:
        primary = flush_context_verbose(c.esys_context, primary);
        session = flush_context_verbose(c.esys_context, session);
        hmac_key = flush_context_verbose(c.esys_context, hmac_key);
        return r;
}

#endif

int tpm2_list_devices(void) {
#if HAVE_TPM2
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_(closedirp) DIR *d = NULL;
        int r;

        r = dlopen_tpm2();
        if (r < 0)
                return log_error_errno(r, "TPM2 support is not installed.");

        t = table_new("path", "device", "driver");
        if (!t)
                return log_oom();

        d = opendir("/sys/class/tpmrm");
        if (!d) {
                log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_ERR, errno, "Failed to open /sys/class/tpmrm: %m");
                if (errno != ENOENT)
                        return -errno;
        } else {
                for (;;) {
                        _cleanup_free_ char *device_path = NULL, *device = NULL, *driver_path = NULL, *driver = NULL, *node = NULL;
                        struct dirent *de;

                        de = readdir_no_dot(d);
                        if (!de)
                                break;

                        device_path = path_join("/sys/class/tpmrm", de->d_name, "device");
                        if (!device_path)
                                return log_oom();

                        r = readlink_malloc(device_path, &device);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read device symlink %s, ignoring: %m", device_path);
                        else {
                                driver_path = path_join(device_path, "driver");
                                if (!driver_path)
                                        return log_oom();

                                r = readlink_malloc(driver_path, &driver);
                                if (r < 0)
                                        log_debug_errno(r, "Failed to read driver symlink %s, ignoring: %m", driver_path);
                        }

                        node = path_join("/dev", de->d_name);
                        if (!node)
                                return log_oom();

                        r = table_add_many(
                                        t,
                                        TABLE_PATH, node,
                                        TABLE_STRING, device ? last_path_component(device) : NULL,
                                        TABLE_STRING, driver ? last_path_component(driver) : NULL);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        }

        if (table_get_rows(t) <= 1) {
                log_info("No suitable TPM2 devices found.");
                return 0;
        }

        r = table_print(t, stdout);
        if (r < 0)
                return log_error_errno(r, "Failed to show device table: %m");

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "TPM2 not supported on this build.");
#endif
}

int tpm2_find_device_auto(
                int log_level, /* log level when no device is found */
                char **ret) {
#if HAVE_TPM2
        _cleanup_(closedirp) DIR *d = NULL;
        int r;

        r = dlopen_tpm2();
        if (r < 0)
                return log_error_errno(r, "TPM2 support is not installed.");

        d = opendir("/sys/class/tpmrm");
        if (!d) {
                log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_ERR, errno,
                               "Failed to open /sys/class/tpmrm: %m");
                if (errno != ENOENT)
                        return -errno;
        } else {
                _cleanup_free_ char *node = NULL;

                for (;;) {
                        struct dirent *de;

                        de = readdir_no_dot(d);
                        if (!de)
                                break;

                        if (node)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                                       "More than one TPM2 (tpmrm) device found.");

                        node = path_join("/dev", de->d_name);
                        if (!node)
                                return log_oom();
                }

                if (node) {
                        *ret = TAKE_PTR(node);
                        return 0;
                }
        }

        return log_full_errno(log_level, SYNTHETIC_ERRNO(ENODEV), "No TPM2 (tpmrm) device found.");
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "TPM2 not supported on this build.");
#endif
}

int tpm2_parse_pcrs(const char *s, uint32_t *ret) {
        const char *p = s;
        uint32_t mask = 0;
        int r;

        assert(s);

        if (isempty(s)) {
                *ret = 0;
                return 0;
        }

        /* Parses a "," or "+" separated list of PCR indexes. We support "," since this is a list after all,
         * and most other tools expect comma separated PCR specifications. We also support "+" since in
         * /etc/crypttab the "," is already used to separate options, hence a different separator is nice to
         * avoid escaping. */

        for (;;) {
                _cleanup_free_ char *pcr = NULL;
                unsigned n;

                r = extract_first_word(&p, &pcr, ",+", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r == 0)
                        break;
                if (r < 0)
                        return log_error_errno(r, "Failed to parse PCR list: %s", s);

                r = safe_atou(pcr, &n);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse PCR number: %s", pcr);
                if (n >= TPM2_PCRS_MAX)
                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE),
                                               "PCR number out of range (valid range 0…23): %u", n);

                mask |= UINT32_C(1) << n;
        }

        *ret = mask;
        return 0;
}

int tpm2_make_luks2_json(
                int keyslot,
                uint32_t pcr_mask,
                const void *blob,
                size_t blob_size,
                const void *policy_hash,
                size_t policy_hash_size,
                JsonVariant **ret) {

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *a = NULL;
        _cleanup_free_ char *keyslot_as_string = NULL;
        JsonVariant* pcr_array[TPM2_PCRS_MAX];
        unsigned n_pcrs = 0;
        int r;

        assert(blob || blob_size == 0);
        assert(policy_hash || policy_hash_size == 0);

        if (asprintf(&keyslot_as_string, "%i", keyslot) < 0)
                return -ENOMEM;

        for (unsigned i = 0; i < ELEMENTSOF(pcr_array); i++) {
                if ((pcr_mask & (UINT32_C(1) << i)) == 0)
                        continue;

                r = json_variant_new_integer(pcr_array + n_pcrs, i);
                if (r < 0) {
                        json_variant_unref_many(pcr_array, n_pcrs);
                        return -ENOMEM;
                }

                n_pcrs++;
        }

        r = json_variant_new_array(&a, pcr_array, n_pcrs);
        json_variant_unref_many(pcr_array, n_pcrs);
        if (r < 0)
                return -ENOMEM;

        r = json_build(&v,
                       JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("type", JSON_BUILD_STRING("systemd-tpm2")),
                                       JSON_BUILD_PAIR("keyslots", JSON_BUILD_ARRAY(JSON_BUILD_STRING(keyslot_as_string))),
                                       JSON_BUILD_PAIR("tpm2-blob", JSON_BUILD_BASE64(blob, blob_size)),
                                       JSON_BUILD_PAIR("tpm2-pcrs", JSON_BUILD_VARIANT(a)),
                                       JSON_BUILD_PAIR("tpm2-policy-hash", JSON_BUILD_HEX(policy_hash, policy_hash_size))));
        if (r < 0)
                return r;

        if (ret)
                *ret = TAKE_PTR(v);

        return keyslot;
}
