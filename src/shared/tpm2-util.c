/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "def.h"
#include "dirent-util.h"
#include "dlfcn-util.h"
#include "efi-api.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "memory-util.h"
#include "openssl-util.h"
#include "parse-util.h"
#include "random-util.h"
#include "sha256.h"
#include "stat-util.h"
#include "time-util.h"
#include "tpm2-util.h"
#include "virt.h"

#if HAVE_TPM2
static void *libtss2_esys_dl = NULL;
static void *libtss2_rc_dl = NULL;
static void *libtss2_mu_dl = NULL;

TSS2_RC (*sym_Esys_Create)(ESYS_CONTEXT *esysContext, ESYS_TR parentHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_SENSITIVE_CREATE *inSensitive, const TPM2B_PUBLIC *inPublic, const TPM2B_DATA *outsideInfo, const TPML_PCR_SELECTION *creationPCR, TPM2B_PRIVATE **outPrivate, TPM2B_PUBLIC **outPublic, TPM2B_CREATION_DATA **creationData, TPM2B_DIGEST **creationHash, TPMT_TK_CREATION **creationTicket) = NULL;
TSS2_RC (*sym_Esys_CreatePrimary)(ESYS_CONTEXT *esysContext, ESYS_TR primaryHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_SENSITIVE_CREATE *inSensitive, const TPM2B_PUBLIC *inPublic, const TPM2B_DATA *outsideInfo, const TPML_PCR_SELECTION *creationPCR, ESYS_TR *objectHandle, TPM2B_PUBLIC **outPublic, TPM2B_CREATION_DATA **creationData, TPM2B_DIGEST **creationHash, TPMT_TK_CREATION **creationTicket) = NULL;
void (*sym_Esys_Finalize)(ESYS_CONTEXT **context) = NULL;
TSS2_RC (*sym_Esys_FlushContext)(ESYS_CONTEXT *esysContext, ESYS_TR flushHandle) = NULL;
void (*sym_Esys_Free)(void *ptr) = NULL;
TSS2_RC (*sym_Esys_GetCapability)(ESYS_CONTEXT *esysContext, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, TPM2_CAP capability, UINT32 property, UINT32 propertyCount, TPMI_YES_NO *moreData, TPMS_CAPABILITY_DATA **capabilityData);
TSS2_RC (*sym_Esys_GetRandom)(ESYS_CONTEXT *esysContext, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, UINT16 bytesRequested, TPM2B_DIGEST **randomBytes) = NULL;
TSS2_RC (*sym_Esys_Initialize)(ESYS_CONTEXT **esys_context,  TSS2_TCTI_CONTEXT *tcti, TSS2_ABI_VERSION *abiVersion) = NULL;
TSS2_RC (*sym_Esys_Load)(ESYS_CONTEXT *esysContext, ESYS_TR parentHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_PRIVATE *inPrivate, const TPM2B_PUBLIC *inPublic, ESYS_TR *objectHandle) = NULL;
TSS2_RC (*sym_Esys_LoadExternal)(ESYS_CONTEXT *esysContext, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_SENSITIVE *inPrivate, const TPM2B_PUBLIC *inPublic, ESYS_TR hierarchy, ESYS_TR *objectHandle);
TSS2_RC (*sym_Esys_PCR_Extend)(ESYS_CONTEXT *esysContext, ESYS_TR pcrHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPML_DIGEST_VALUES *digests);
TSS2_RC (*sym_Esys_PCR_Read)(ESYS_CONTEXT *esysContext, ESYS_TR shandle1,ESYS_TR shandle2, ESYS_TR shandle3, const TPML_PCR_SELECTION *pcrSelectionIn, UINT32 *pcrUpdateCounter, TPML_PCR_SELECTION **pcrSelectionOut, TPML_DIGEST **pcrValues);
TSS2_RC (*sym_Esys_PolicyAuthorize)(ESYS_CONTEXT *esysContext, ESYS_TR policySession, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_DIGEST *approvedPolicy, const TPM2B_NONCE *policyRef, const TPM2B_NAME *keySign, const TPMT_TK_VERIFIED *checkTicket);
TSS2_RC (*sym_Esys_PolicyAuthValue)(ESYS_CONTEXT *esysContext, ESYS_TR policySession, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3) = NULL;
TSS2_RC (*sym_Esys_PolicyGetDigest)(ESYS_CONTEXT *esysContext, ESYS_TR policySession, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, TPM2B_DIGEST **policyDigest) = NULL;
TSS2_RC (*sym_Esys_PolicyPCR)(ESYS_CONTEXT *esysContext, ESYS_TR policySession, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_DIGEST *pcrDigest, const TPML_PCR_SELECTION *pcrs) = NULL;
TSS2_RC (*sym_Esys_StartAuthSession)(ESYS_CONTEXT *esysContext, ESYS_TR tpmKey, ESYS_TR bind, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_NONCE *nonceCaller, TPM2_SE sessionType, const TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH authHash, ESYS_TR *sessionHandle) = NULL;
TSS2_RC (*sym_Esys_Startup)(ESYS_CONTEXT *esysContext, TPM2_SU startupType) = NULL;
TSS2_RC (*sym_Esys_TRSess_SetAttributes)(ESYS_CONTEXT *esysContext, ESYS_TR session, TPMA_SESSION flags, TPMA_SESSION mask);
TSS2_RC (*sym_Esys_TR_GetName)(ESYS_CONTEXT *esysContext, ESYS_TR handle, TPM2B_NAME **name);
TSS2_RC (*sym_Esys_TR_SetAuth)(ESYS_CONTEXT *esysContext, ESYS_TR handle, TPM2B_AUTH const *authValue) = NULL;
TSS2_RC (*sym_Esys_Unseal)(ESYS_CONTEXT *esysContext, ESYS_TR itemHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, TPM2B_SENSITIVE_DATA **outData) = NULL;
TSS2_RC (*sym_Esys_VerifySignature)(ESYS_CONTEXT *esysContext, ESYS_TR keyHandle, ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3, const TPM2B_DIGEST *digest, const TPMT_SIGNATURE *signature, TPMT_TK_VERIFIED **validation);

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
                        DLSYM_ARG(Esys_GetCapability),
                        DLSYM_ARG(Esys_GetRandom),
                        DLSYM_ARG(Esys_Initialize),
                        DLSYM_ARG(Esys_Load),
                        DLSYM_ARG(Esys_LoadExternal),
                        DLSYM_ARG(Esys_PCR_Extend),
                        DLSYM_ARG(Esys_PCR_Read),
                        DLSYM_ARG(Esys_PolicyAuthorize),
                        DLSYM_ARG(Esys_PolicyAuthValue),
                        DLSYM_ARG(Esys_PolicyGetDigest),
                        DLSYM_ARG(Esys_PolicyPCR),
                        DLSYM_ARG(Esys_StartAuthSession),
                        DLSYM_ARG(Esys_Startup),
                        DLSYM_ARG(Esys_TRSess_SetAttributes),
                        DLSYM_ARG(Esys_TR_GetName),
                        DLSYM_ARG(Esys_TR_SetAuth),
                        DLSYM_ARG(Esys_Unseal),
                        DLSYM_ARG(Esys_VerifySignature));
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

void tpm2_context_destroy(struct tpm2_context *c) {
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

ESYS_TR tpm2_flush_context_verbose(ESYS_CONTEXT *c, ESYS_TR handle) {
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

int tpm2_context_init(const char *device, struct tpm2_context *ret) {
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
                        driver = strndupa_safe(device, param - device);
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

#define TPM2_CREDIT_RANDOM_FLAG_PATH "/run/systemd/tpm-rng-credited"

static int tpm2_credit_random(ESYS_CONTEXT *c) {
        size_t rps, done = 0;
        TSS2_RC rc;
        usec_t t;
        int r;

        assert(c);

        /* Pulls some entropy from the TPM and adds it into the kernel RNG pool. That way we can say that the
         * key we will ultimately generate with the kernel random pool is at least as good as the TPM's RNG,
         * but likely better. Note that we don't trust the TPM RNG very much, hence do not actually credit
         * any entropy. */

        if (access(TPM2_CREDIT_RANDOM_FLAG_PATH, F_OK) < 0) {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to detect if '" TPM2_CREDIT_RANDOM_FLAG_PATH "' exists, ignoring: %m");
        } else {
                log_debug("Not adding TPM2 entropy to the kernel random pool again.");
                return 0; /* Already done */
        }

        t = now(CLOCK_MONOTONIC);

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

                r = random_write_entropy(-1, buffer->buffer, buffer->size, /* credit= */ false);
                if (r < 0)
                        return log_error_errno(r, "Failed wo write entropy to kernel: %m");

                done += buffer->size;
                rps = LESS_BY(rps, buffer->size);
        }

        log_debug("Added %zu bytes of TPM2 entropy to the kernel random pool in %s.", done, FORMAT_TIMESPAN(now(CLOCK_MONOTONIC) - t, 0));

        r = touch(TPM2_CREDIT_RANDOM_FLAG_PATH);
        if (r < 0)
                log_debug_errno(r, "Failed to touch '" TPM2_CREDIT_RANDOM_FLAG_PATH "', ignoring: %m");

        return 0;
}

static int tpm2_make_primary(
                ESYS_CONTEXT *c,
                ESYS_TR *ret_primary,
                TPMI_ALG_PUBLIC alg,
                TPMI_ALG_PUBLIC *ret_alg) {

        static const TPM2B_SENSITIVE_CREATE primary_sensitive = {};
        static const TPM2B_PUBLIC primary_template_ecc = {
                .size = sizeof(TPMT_PUBLIC),
                .publicArea = {
                        .type = TPM2_ALG_ECC,
                        .nameAlg = TPM2_ALG_SHA256,
                        .objectAttributes = TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH,
                        .parameters.eccDetail = {
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
        };
        static const TPM2B_PUBLIC primary_template_rsa = {
                .size = sizeof(TPMT_PUBLIC),
                .publicArea = {
                        .type = TPM2_ALG_RSA,
                        .nameAlg = TPM2_ALG_SHA256,
                        .objectAttributes = TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH,
                        .parameters.rsaDetail = {
                                .symmetric = {
                                        .algorithm = TPM2_ALG_AES,
                                        .keyBits.aes = 128,
                                        .mode.aes = TPM2_ALG_CFB,
                                },
                                .scheme.scheme = TPM2_ALG_NULL,
                                .keyBits = 2048,
                        },
                },
        };

        static const TPML_PCR_SELECTION creation_pcr = {};
        ESYS_TR primary = ESYS_TR_NONE;
        TSS2_RC rc;
        usec_t ts;

        log_debug("Creating primary key on TPM.");

        /* So apparently not all TPM2 devices support ECC. ECC is generally preferably, because it's so much
         * faster, noticeably so (~10s vs. ~240ms on my system). Hence, unless explicitly configured let's
         * try to use ECC first, and if that does not work, let's fall back to RSA. */

        ts = now(CLOCK_MONOTONIC);

        if (IN_SET(alg, 0, TPM2_ALG_ECC)) {
                rc = sym_Esys_CreatePrimary(
                                c,
                                ESYS_TR_RH_OWNER,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                &primary_sensitive,
                                &primary_template_ecc,
                                NULL,
                                &creation_pcr,
                                &primary,
                                NULL,
                                NULL,
                                NULL,
                                NULL);

                if (rc != TSS2_RC_SUCCESS) {
                        if (alg != 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                                       "Failed to generate ECC primary key in TPM: %s", sym_Tss2_RC_Decode(rc));

                        log_debug("Failed to generate ECC primary key in TPM, trying RSA: %s", sym_Tss2_RC_Decode(rc));
                } else {
                        log_debug("Successfully created ECC primary key on TPM.");
                        alg = TPM2_ALG_ECC;
                }
        }

        if (IN_SET(alg, 0, TPM2_ALG_RSA)) {
                rc = sym_Esys_CreatePrimary(
                                c,
                                ESYS_TR_RH_OWNER,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                &primary_sensitive,
                                &primary_template_rsa,
                                NULL,
                                &creation_pcr,
                                &primary,
                                NULL,
                                NULL,
                                NULL,
                                NULL);
                if (rc != TSS2_RC_SUCCESS)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "Failed to generate RSA primary key in TPM: %s", sym_Tss2_RC_Decode(rc));
                else if (alg == 0) {
                        log_notice("TPM2 chip apparently does not support ECC primary keys, falling back to RSA. "
                                   "This likely means TPM2 operations will be relatively slow, please be patient.");
                        alg = TPM2_ALG_RSA;
                }

                log_debug("Successfully created RSA primary key on TPM.");
        }

        log_debug("Generating primary key on TPM2 took %s.", FORMAT_TIMESPAN(now(CLOCK_MONOTONIC) - ts, USEC_PER_MSEC));

        *ret_primary = primary;
        if (ret_alg)
                *ret_alg = alg;

        return 0;
}

void tpm2_pcr_mask_to_selection(uint32_t mask, uint16_t bank, TPML_PCR_SELECTION *ret) {
        assert(ret);

        /* We only do 24bit here, as that's what PC TPMs are supposed to support */
        assert(mask <= 0xFFFFFFU);

        *ret = (TPML_PCR_SELECTION) {
                .count = 1,
                .pcrSelections[0] = {
                        .hash = bank,
                        .sizeofSelect = 3,
                        .pcrSelect[0] = mask & 0xFF,
                        .pcrSelect[1] = (mask >> 8) & 0xFF,
                        .pcrSelect[2] = (mask >> 16) & 0xFF,
                }
        };
}

static unsigned find_nth_bit(uint32_t mask, unsigned n) {
        uint32_t bit = 1;

        assert(n < 32);

        /* Returns the bit index of the nth set bit, e.g. mask=0b101001, n=3 → 5 */

        for (unsigned i = 0; i < sizeof(mask)*8; i++) {

                if (bit & mask) {
                        if (n == 0)
                                return i;

                        n--;
                }

                bit <<= 1;
        }

        return UINT_MAX;
}

static int tpm2_pcr_mask_good(
                ESYS_CONTEXT *c,
                TPMI_ALG_HASH bank,
                uint32_t mask) {

        _cleanup_(Esys_Freep) TPML_DIGEST *pcr_values = NULL;
        TPML_PCR_SELECTION selection;
        bool good = false;
        TSS2_RC rc;

        assert(c);

        /* So we have the problem that some systems might have working TPM2 chips, but the firmware doesn't
         * actually measure into them, or only into a suboptimal bank. If so, the PCRs should be all zero or
         * all 0xFF. Detect that, so that we can warn and maybe pick a better bank. */

        tpm2_pcr_mask_to_selection(mask, bank, &selection);

        rc = sym_Esys_PCR_Read(
                        c,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &selection,
                        NULL,
                        NULL,
                        &pcr_values);
        if (rc != TSS2_RC_SUCCESS)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Failed to read TPM2 PCRs: %s", sym_Tss2_RC_Decode(rc));

        /* If at least one of the selected PCR values is something other than all 0x00 or all 0xFF we are happy. */
        for (unsigned i = 0; i < pcr_values->count; i++) {
                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *h = NULL;
                        unsigned j;

                        h = hexmem(pcr_values->digests[i].buffer, pcr_values->digests[i].size);
                        j = find_nth_bit(mask, i);
                        assert(j != UINT_MAX);

                        log_debug("PCR %u value: %s", j, strna(h));
                }

                if (!memeqbyte(0x00, pcr_values->digests[i].buffer, pcr_values->digests[i].size) &&
                    !memeqbyte(0xFF, pcr_values->digests[i].buffer, pcr_values->digests[i].size))
                        good = true;
        }

        return good;
}

static int tpm2_bank_has24(const TPMS_PCR_SELECTION *selection) {

        assert(selection);

        /* As per https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf a
         * TPM2 on a Client PC must have at least 24 PCRs. If this TPM has less, just skip over it. */
        if (selection->sizeofSelect < TPM2_PCRS_MAX/8) {
                log_debug("Skipping TPM2 PCR bank %s with fewer than 24 PCRs.",
                          strna(tpm2_pcr_bank_to_string(selection->hash)));
                return false;
        }

        assert_cc(TPM2_PCRS_MAX % 8 == 0);

        /* It's not enough to check how many PCRs there are, we also need to check that the 24 are
         * enabled for this bank. Otherwise this TPM doesn't qualify. */
        bool valid = true;
        for (size_t j = 0; j < TPM2_PCRS_MAX/8; j++)
                if (selection->pcrSelect[j] != 0xFF) {
                        valid = false;
                        break;
                }

        if (!valid)
                log_debug("TPM2 PCR bank %s has fewer than 24 PCR bits enabled, ignoring.",
                          strna(tpm2_pcr_bank_to_string(selection->hash)));

        return valid;
}

static int tpm2_get_best_pcr_bank(
                ESYS_CONTEXT *c,
                uint32_t pcr_mask,
                TPMI_ALG_HASH *ret) {

        _cleanup_(Esys_Freep) TPMS_CAPABILITY_DATA *pcap = NULL;
        TPMI_ALG_HASH supported_hash = 0, hash_with_valid_pcr = 0;
        TPMI_YES_NO more;
        TSS2_RC rc;
        int r;

        assert(c);

        rc = sym_Esys_GetCapability(
                        c,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        TPM2_CAP_PCRS,
                        0,
                        1,
                        &more,
                        &pcap);
        if (rc != TSS2_RC_SUCCESS)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Failed to determine TPM2 PCR bank capabilities: %s", sym_Tss2_RC_Decode(rc));

        assert(pcap->capability == TPM2_CAP_PCRS);

        for (size_t i = 0; i < pcap->data.assignedPCR.count; i++) {
                int good;

                /* For now we are only interested in the SHA1 and SHA256 banks */
                if (!IN_SET(pcap->data.assignedPCR.pcrSelections[i].hash, TPM2_ALG_SHA256, TPM2_ALG_SHA1))
                        continue;

                r = tpm2_bank_has24(pcap->data.assignedPCR.pcrSelections + i);
                if (r < 0)
                        return r;
                if (!r)
                        continue;

                good = tpm2_pcr_mask_good(c, pcap->data.assignedPCR.pcrSelections[i].hash, pcr_mask);
                if (good < 0)
                        return good;

                if (pcap->data.assignedPCR.pcrSelections[i].hash == TPM2_ALG_SHA256) {
                        supported_hash = TPM2_ALG_SHA256;
                        if (good) {
                                /* Great, SHA256 is supported and has initialized PCR values, we are done. */
                                hash_with_valid_pcr = TPM2_ALG_SHA256;
                                break;
                        }
                } else {
                        assert(pcap->data.assignedPCR.pcrSelections[i].hash == TPM2_ALG_SHA1);

                        if (supported_hash == 0)
                                supported_hash = TPM2_ALG_SHA1;

                        if (good && hash_with_valid_pcr == 0)
                                hash_with_valid_pcr = TPM2_ALG_SHA1;
                }
        }

        /* We preferably pick SHA256, but only if its PCRs are initialized or neither the SHA1 nor the SHA256
         * PCRs are initialized. If SHA256 is not supported but SHA1 is and its PCRs are too, we prefer
         * SHA1.
         *
         * We log at LOG_NOTICE level whenever we end up using the SHA1 bank or when the PCRs we bind to are
         * not initialized. */

        if (hash_with_valid_pcr == TPM2_ALG_SHA256) {
                assert(supported_hash == TPM2_ALG_SHA256);
                log_debug("TPM2 device supports SHA256 PCR bank and SHA256 PCRs are valid, yay!");
                *ret = TPM2_ALG_SHA256;
        } else if (hash_with_valid_pcr == TPM2_ALG_SHA1) {
                if (supported_hash == TPM2_ALG_SHA256)
                        log_notice("TPM2 device supports both SHA1 and SHA256 PCR banks, but only SHA1 PCRs are valid, falling back to SHA1 bank. This reduces the security level substantially.");
                else {
                        assert(supported_hash == TPM2_ALG_SHA1);
                        log_notice("TPM2 device lacks support for SHA256 PCR bank, but SHA1 bank is supported and SHA1 PCRs are valid, falling back to SHA1 bank. This reduces the security level substantially.");
                }

                *ret = TPM2_ALG_SHA1;
        } else if (supported_hash == TPM2_ALG_SHA256) {
                log_notice("TPM2 device supports SHA256 PCR bank but none of the selected PCRs are valid! Firmware apparently did not initialize any of the selected PCRs. Proceeding anyway with SHA256 bank. PCR policy effectively unenforced!");
                *ret = TPM2_ALG_SHA256;
        } else if (supported_hash == TPM2_ALG_SHA1) {
                log_notice("TPM2 device lacks support for SHA256 bank, but SHA1 bank is supported, but none of the selected PCRs are valid! Firmware apparently did not initialize any of the selected PCRs. Proceeding anyway with SHA1 bank. PCR policy effectively unenforced!");
                *ret = TPM2_ALG_SHA1;
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "TPM2 module supports neither SHA1 nor SHA256 PCR banks, cannot operate.");

        return 0;
}

int tpm2_get_good_pcr_banks(
                ESYS_CONTEXT *c,
                uint32_t pcr_mask,
                TPMI_ALG_HASH **ret) {

        _cleanup_free_ TPMI_ALG_HASH *good_banks = NULL, *fallback_banks = NULL;
        _cleanup_(Esys_Freep) TPMS_CAPABILITY_DATA *pcap = NULL;
        size_t n_good_banks = 0, n_fallback_banks = 0;
        TPMI_YES_NO more;
        TSS2_RC rc;
        int r;

        assert(c);
        assert(ret);

        rc = sym_Esys_GetCapability(
                        c,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        TPM2_CAP_PCRS,
                        0,
                        1,
                        &more,
                        &pcap);
        if (rc != TSS2_RC_SUCCESS)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Failed to determine TPM2 PCR bank capabilities: %s", sym_Tss2_RC_Decode(rc));

        assert(pcap->capability == TPM2_CAP_PCRS);

        for (size_t i = 0; i < pcap->data.assignedPCR.count; i++) {

                /* Let's see if this bank is superficially OK, i.e. has at least 24 enabled registers */
                r = tpm2_bank_has24(pcap->data.assignedPCR.pcrSelections + i);
                if (r < 0)
                        return r;
                if (!r)
                        continue;

                /* Let's now see if this bank has any of the selected PCRs actually initialized */
                r = tpm2_pcr_mask_good(c, pcap->data.assignedPCR.pcrSelections[i].hash, pcr_mask);
                if (r < 0)
                        return r;

                if (n_good_banks + n_fallback_banks >= INT_MAX)
                        return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "Too many good TPM2 banks?");

                if (r) {
                        if (!GREEDY_REALLOC(good_banks, n_good_banks+1))
                                return log_oom();

                        good_banks[n_good_banks++] = pcap->data.assignedPCR.pcrSelections[i].hash;
                } else {
                        if (!GREEDY_REALLOC(fallback_banks, n_fallback_banks+1))
                                return log_oom();

                        fallback_banks[n_fallback_banks++] = pcap->data.assignedPCR.pcrSelections[i].hash;
                }
        }

        /* Preferably, use the good banks (i.e. the ones the PCR values are actually initialized so
         * far). Otherwise use the fallback banks (i.e. which exist and are enabled, but so far not used. */
        if (n_good_banks > 0) {
                log_debug("Found %zu fully initialized TPM2 banks.", n_good_banks);
                *ret = TAKE_PTR(good_banks);
                return (int) n_good_banks;
        }
        if (n_fallback_banks > 0) {
                log_debug("Found %zu enabled but un-initialized TPM2 banks.", n_fallback_banks);
                *ret = TAKE_PTR(fallback_banks);
                return (int) n_fallback_banks;
        }

        /* No suitable banks found. */
        *ret = NULL;
        return 0;
}

static void hash_pin(const char *pin, size_t len, TPM2B_AUTH *auth) {
        struct sha256_ctx hash;

        assert(auth);
        assert(pin);
        auth->size = SHA256_DIGEST_SIZE;

        sha256_init_ctx(&hash);
        sha256_process_bytes(pin, len, &hash);
        sha256_finish_ctx(&hash, auth->buffer);

        explicit_bzero_safe(&hash, sizeof(hash));
}

static int tpm2_make_encryption_session(
                ESYS_CONTEXT *c,
                ESYS_TR primary,
                ESYS_TR bind_key,
                const char *pin,
                ESYS_TR *ret_session) {

        static const TPMT_SYM_DEF symmetric = {
                .algorithm = TPM2_ALG_AES,
                .keyBits.aes = 128,
                .mode.aes = TPM2_ALG_CFB,
        };
        const TPMA_SESSION sessionAttributes = TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT |
                        TPMA_SESSION_CONTINUESESSION;
        ESYS_TR session = ESYS_TR_NONE;
        TSS2_RC rc;

        assert(c);

        /*
         * if a pin is set for the seal object, use it to bind the session
         * key to that object. This prevents active bus interposers from
         * faking a TPM and seeing the unsealed value. An active interposer
         * could fake a TPM, satisfying the encrypted session, and just
         * forward everything to the *real* TPM.
         */
        if (pin) {
                TPM2B_AUTH auth = {};

                hash_pin(pin, strlen(pin), &auth);

                rc = sym_Esys_TR_SetAuth(c, bind_key, &auth);
                /* ESAPI knows about it, so clear it from our memory */
                explicit_bzero_safe(&auth, sizeof(auth));
                if (rc != TSS2_RC_SUCCESS)
                        return log_error_errno(
                                               SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                               "Failed to load PIN in TPM: %s",
                                               sym_Tss2_RC_Decode(rc));
        }

        log_debug("Starting HMAC encryption session.");

        /* Start a salted, unbound HMAC session with a well-known key (e.g. primary key) as tpmKey, which
         * means that the random salt will be encrypted with the well-known key. That way, only the TPM can
         * recover the salt, which is then used for key derivation. */
        rc = sym_Esys_StartAuthSession(
                        c,
                        primary,
                        bind_key,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        NULL,
                        TPM2_SE_HMAC,
                        &symmetric,
                        TPM2_ALG_SHA256,
                        &session);
        if (rc != TSS2_RC_SUCCESS)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Failed to open session in TPM: %s", sym_Tss2_RC_Decode(rc));

        /* Enable parameter encryption/decryption with AES in CFB mode. Together with HMAC digests (which are
         * always used for sessions), this provides confidentiality, integrity and replay protection for
         * operations that use this session. */
        rc = sym_Esys_TRSess_SetAttributes(c, session, sessionAttributes, 0xff);
        if (rc != TSS2_RC_SUCCESS)
                return log_error_errno(
                                SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                "Failed to configure TPM session: %s",
                                sym_Tss2_RC_Decode(rc));

        if (ret_session) {
                *ret_session = session;
                session = ESYS_TR_NONE;
        }

        session = tpm2_flush_context_verbose(c, session);
        return 0;
}

#if HAVE_OPENSSL
static int openssl_pubkey_to_tpm2_pubkey(EVP_PKEY *input, TPM2B_PUBLIC *output) {
#if OPENSSL_VERSION_MAJOR >= 3
        _cleanup_(BN_freep) BIGNUM *n = NULL, *e = NULL;
#else
        const BIGNUM *n = NULL, *e = NULL;
        const RSA *rsa = NULL;
#endif
        int n_bytes, e_bytes;

        assert(input);
        assert(output);

        /* Converts an OpenSSL public key to a structure that the TPM chip can process. */

        if (EVP_PKEY_base_id(input) != EVP_PKEY_RSA)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Provided public key is not an RSA key.");

#if OPENSSL_VERSION_MAJOR >= 3
        if (!EVP_PKEY_get_bn_param(input, OSSL_PKEY_PARAM_RSA_N, &n))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to get RSA modulus from public key.");
#else
        rsa = EVP_PKEY_get0_RSA(input);
        if (!rsa)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to extract RSA key from public key.");

        n = RSA_get0_n(rsa);
        if (!n)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to get RSA modulus from public key.");
#endif

        n_bytes = BN_num_bytes(n);
        assert_se(n_bytes > 0);
        if ((size_t) n_bytes > sizeof_field(TPM2B_PUBLIC, publicArea.unique.rsa.buffer))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "RSA modulus too large for TPM2 public key object.");

#if OPENSSL_VERSION_MAJOR >= 3
        if (!EVP_PKEY_get_bn_param(input, OSSL_PKEY_PARAM_RSA_E, &e))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to get RSA exponent from public key.");
#else
        e = RSA_get0_e(rsa);
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to get RSA exponent from public key.");
#endif

        e_bytes = BN_num_bytes(e);
        assert_se(e_bytes > 0);
        if ((size_t) e_bytes > sizeof_field(TPM2B_PUBLIC, publicArea.parameters.rsaDetail.exponent))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "RSA exponent too large for TPM2 public key object.");

        *output = (TPM2B_PUBLIC) {
                .size = sizeof(TPMT_PUBLIC),
                .publicArea = {
                        .type = TPM2_ALG_RSA,
                        .nameAlg = TPM2_ALG_SHA256,
                        .objectAttributes = TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH,
                        .parameters.rsaDetail = {
                                .scheme = {
                                        .scheme = TPM2_ALG_NULL,
                                        .details.anySig.hashAlg = TPM2_ALG_NULL,
                                },
                                .symmetric = {
                                        .algorithm = TPM2_ALG_NULL,
                                        .mode.sym = TPM2_ALG_NULL,
                                },
                                .keyBits = n_bytes * 8,
                                /* .exponent will be filled in below. */
                        },
                        .unique = {
                                .rsa.size = n_bytes,
                                /* .rsa.buffer will be filled in below. */
                        },
                },
        };

        if (BN_bn2bin(n, output->publicArea.unique.rsa.buffer) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to convert RSA modulus.");

        if (BN_bn2bin(e, (unsigned char*) &output->publicArea.parameters.rsaDetail.exponent) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to convert RSA exponent.");

        return 0;
}

static int find_signature(
                JsonVariant *v,
                uint16_t pcr_bank,
                uint32_t pcr_mask,
                EVP_PKEY *pk,
                const void *policy,
                size_t policy_size,
                void *ret_signature,
                size_t *ret_signature_size) {

        _cleanup_free_ void *fp = NULL;
        JsonVariant *b, *i;
        size_t fp_size;
        const char *k;
        int r;

        /* Searches for a signature blob in the specified JSON object. Search keys are PCR bank, PCR mask,
         * public key, and policy digest. */

        if (!json_variant_is_object(v))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Signature is not a JSON object.");

        k = tpm2_pcr_bank_to_string(pcr_bank);
        if (!k)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Don't know PCR bank %" PRIu16, pcr_bank);

        /* First, find field by bank */
        b = json_variant_by_key(v, k);
        if (!b)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO), "Signature lacks data for PCR bank '%s'.", k);

        if (!json_variant_is_array(b))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Bank data is not a JSON array.");

        /* Now iterate through all signatures known for this bank */
        JSON_VARIANT_ARRAY_FOREACH(i, b) {
                _cleanup_free_ void *fpj_data = NULL, *polj_data = NULL;
                JsonVariant *maskj, *fpj, *sigj, *polj;
                size_t fpj_size, polj_size;
                uint32_t parsed_mask;

                if (!json_variant_is_object(i))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Bank data element is not a JSON object");

                /* Check if the PCR mask matches our expectations */
                maskj = json_variant_by_key(i, "pcrs");
                if (!maskj)
                        continue;

                r = tpm2_parse_pcr_json_array(maskj, &parsed_mask);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse JSON PCR mask");

                if (parsed_mask != pcr_mask)
                        continue; /* Not for this PCR mask */

                /* Then check if this is for the public key we operate with */
                fpj = json_variant_by_key(i, "pkfp");
                if (!fpj)
                        continue;

                r = json_variant_unhex(fpj, &fpj_data, &fpj_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode fingerprint in JSON data: %m");

                if (!fp) {
                        r = pubkey_fingerprint(pk, EVP_sha256(), &fp, &fp_size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to calculate public key fingerprint: %m");
                }

                if (memcmp_nn(fp, fp_size, fpj_data, fpj_size) != 0)
                        continue; /* Not for this public key */

                /* Finally, check if this is for the PCR policy we expect this to be */
                polj = json_variant_by_key(i, "pol");
                if (!polj)
                        continue;

                r = json_variant_unhex(polj, &polj_data, &polj_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode policy hash JSON data: %m");

                if (memcmp_nn(policy, policy_size, polj_data, polj_size) != 0)
                        continue;

                /* This entry matches all our expectations, now return the signature included in it */
                sigj = json_variant_by_key(i, "sig");
                if (!sigj)
                        continue;

                return json_variant_unbase64(sigj, ret_signature, ret_signature_size);
        }

        return log_error_errno(SYNTHETIC_ERRNO(ENXIO), "Couldn't find signature for this PCR bank, PCR index and public key.");
}
#endif

static int tpm2_make_policy_session(
                ESYS_CONTEXT *c,
                ESYS_TR primary,
                ESYS_TR parent_session,
                TPM2_SE session_type,
                uint32_t hash_pcr_mask,
                uint16_t pcr_bank, /* If UINT16_MAX, pick best bank automatically, otherwise specify bank explicitly. */
                const void *pubkey,
                size_t pubkey_size,
                uint32_t pubkey_pcr_mask,
                JsonVariant *signature_json,
                bool use_pin,
                ESYS_TR *ret_session,
                TPM2B_DIGEST **ret_policy_digest,
                TPMI_ALG_HASH *ret_pcr_bank) {

        static const TPMT_SYM_DEF symmetric = {
                .algorithm = TPM2_ALG_AES,
                .keyBits.aes = 128,
                .mode.aes = TPM2_ALG_CFB,
        };
        _cleanup_(Esys_Freep) TPM2B_DIGEST *policy_digest = NULL;
        ESYS_TR session = ESYS_TR_NONE, pubkey_handle = ESYS_TR_NONE;
        TSS2_RC rc;
        int r;

        assert(c);
        assert(pubkey || pubkey_size == 0);
        assert(pubkey_pcr_mask == 0 || pubkey_size > 0);

        log_debug("Starting authentication session.");

        /* So apparently some TPM implementations don't implement trial mode correctly. To avoid issues let's
         * avoid it when it is easy to. At the moment we only really need trial mode for the signed PCR
         * policies (since only then we need to shove PCR values into the policy that don't match current
         * state anyway), hence if we have none of those we don't need to bother. Hence, let's patch in
         * TPM2_SE_POLICY even if trial mode is requested unless a pubkey PCR mask is specified that is
         * non-zero, i.e. signed PCR policy is requested.
         *
         * One day we should switch to calculating policy hashes client side when trial mode is requested, to
         * avoid this mess. */
        if (session_type == TPM2_SE_TRIAL && pubkey_pcr_mask == 0)
                session_type = TPM2_SE_POLICY;

        if ((hash_pcr_mask | pubkey_pcr_mask) != 0) {
                /* We are told to configure a PCR policy of some form, let's determine/validate the PCR bank to use. */

                if (pcr_bank != UINT16_MAX) {
                        r = tpm2_pcr_mask_good(c, pcr_bank, hash_pcr_mask|pubkey_pcr_mask);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                log_warning("Selected TPM2 PCRs are not initialized on this system, most likely due to a firmware issue. PCR policy is effectively not enforced. Proceeding anyway.");
                } else {
                        /* No bank configured, pick automatically. Some TPM2 devices only can do SHA1. If we
                         * detect that use that, but preferably use SHA256 */
                        r = tpm2_get_best_pcr_bank(c, hash_pcr_mask|pubkey_pcr_mask, &pcr_bank);
                        if (r < 0)
                                return r;
                }
        }

#if HAVE_OPENSSL
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pk = NULL;
        if (pubkey_size > 0) {
                /* If a pubkey is specified, load it to validate it, even if the PCR mask for this is
                 * actually zero, and we are thus not going to use it. */
                _cleanup_fclose_ FILE *f = fmemopen((void*) pubkey, pubkey_size, "r");
                if (!f)
                        return log_oom();

                pk = PEM_read_PUBKEY(f, NULL, NULL, NULL);
                if (!pk)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse PEM public key.");
        }
#endif

        rc = sym_Esys_StartAuthSession(
                        c,
                        primary,
                        ESYS_TR_NONE,
                        parent_session,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        NULL,
                        session_type,
                        &symmetric,
                        TPM2_ALG_SHA256,
                        &session);
        if (rc != TSS2_RC_SUCCESS)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Failed to open session in TPM: %s", sym_Tss2_RC_Decode(rc));

        if (pubkey_pcr_mask != 0) {
#if HAVE_OPENSSL
                log_debug("Configuring public key based PCR policy.");

                /* First: load public key into the TPM */
                TPM2B_PUBLIC pubkey_tpm2;
                r = openssl_pubkey_to_tpm2_pubkey(pk, &pubkey_tpm2);
                if (r < 0)
                        goto finish;

                rc = sym_Esys_LoadExternal(
                                c,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                NULL,
                                &pubkey_tpm2,
                                TPM2_RH_OWNER,
                                &pubkey_handle);
                if (rc != TSS2_RC_SUCCESS) {
                        r = log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                            "Failed to load public key into TPM: %s", sym_Tss2_RC_Decode(rc));
                        goto finish;
                }

                /* Acquire the "name" of what we just loaded */
                _cleanup_(Esys_Freep) TPM2B_NAME *pubkey_name = NULL;
                rc = sym_Esys_TR_GetName(
                                c,
                                pubkey_handle,
                                &pubkey_name);
                if (rc != TSS2_RC_SUCCESS) {
                        r = log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                            "Failed to get name of public key from TPM: %s", sym_Tss2_RC_Decode(rc));
                        goto finish;
                }

                /* Put together the PCR policy we want to use */
                TPML_PCR_SELECTION pcr_selection;
                tpm2_pcr_mask_to_selection(pubkey_pcr_mask, pcr_bank, &pcr_selection);
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

                /* Get the policy hash of the PCR policy */
                _cleanup_(Esys_Freep) TPM2B_DIGEST *approved_policy = NULL;
                rc = sym_Esys_PolicyGetDigest(
                                c,
                                session,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                &approved_policy);
                if (rc != TSS2_RC_SUCCESS) {
                        r = log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                            "Failed to get policy digest from TPM: %s", sym_Tss2_RC_Decode(rc));
                        goto finish;
                }

                /* When we are unlocking and have a signature, let's pass it to the TPM */
                _cleanup_(Esys_Freep) TPMT_TK_VERIFIED *check_ticket_buffer = NULL;
                const TPMT_TK_VERIFIED *check_ticket;
                if (signature_json) {
                        _cleanup_free_ void *signature_raw = NULL;
                        size_t signature_size;

                        r = find_signature(
                                        signature_json,
                                        pcr_bank,
                                        pubkey_pcr_mask,
                                        pk,
                                        approved_policy->buffer,
                                        approved_policy->size,
                                        &signature_raw,
                                        &signature_size);
                        if (r < 0)
                                goto finish;

                        /* TPM2_VerifySignature() will only verify the RSA part of the RSA+SHA256 signature,
                         * hence we need to do the SHA256 part ourselves, first */
                        TPM2B_DIGEST signature_hash = {
                                .size = SHA256_DIGEST_SIZE,
                        };
                        assert(sizeof(signature_hash.buffer) >= SHA256_DIGEST_SIZE);
                        sha256_direct(approved_policy->buffer, approved_policy->size, signature_hash.buffer);

                        TPMT_SIGNATURE policy_signature = {
                                .sigAlg = TPM2_ALG_RSASSA,
                                .signature.rsassa = {
                                        .hash = TPM2_ALG_SHA256,
                                        .sig.size = signature_size,
                                },
                        };
                        if (signature_size > sizeof(policy_signature.signature.rsassa.sig.buffer)) {
                                r = log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Signature larger than buffer.");
                                goto finish;
                        }
                        memcpy(policy_signature.signature.rsassa.sig.buffer, signature_raw, signature_size);

                        rc = sym_Esys_VerifySignature(
                                        c,
                                        pubkey_handle,
                                        ESYS_TR_NONE,
                                        ESYS_TR_NONE,
                                        ESYS_TR_NONE,
                                        &signature_hash,
                                        &policy_signature,
                                        &check_ticket_buffer);
                        if (rc != TSS2_RC_SUCCESS) {
                                r = log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                                    "Failed to validate signature in TPM: %s", sym_Tss2_RC_Decode(rc));
                                goto finish;
                        }

                        check_ticket = check_ticket_buffer;
                } else {
                        /* When enrolling, we pass a NULL ticket */
                        static const TPMT_TK_VERIFIED check_ticket_null = {
                                .tag = TPM2_ST_VERIFIED,
                                .hierarchy = TPM2_RH_OWNER,
                        };

                        check_ticket = &check_ticket_null;
                }

                rc = sym_Esys_PolicyAuthorize(
                                c,
                                session,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                approved_policy,
                                /* policyRef= */ &(const TPM2B_NONCE) {},
                                pubkey_name,
                                check_ticket);
                if (rc != TSS2_RC_SUCCESS) {
                        r = log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                            "Failed to push Authorize policy into TPM: %s", sym_Tss2_RC_Decode(rc));
                        goto finish;
                }
#else
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "OpenSSL support is disabled.");
#endif
        }

        if (hash_pcr_mask != 0) {
                log_debug("Configuring hash-based PCR policy.");

                TPML_PCR_SELECTION pcr_selection;
                tpm2_pcr_mask_to_selection(hash_pcr_mask, pcr_bank, &pcr_selection);
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
        }

        if (use_pin) {
                log_debug("Configuring PIN policy.");

                rc = sym_Esys_PolicyAuthValue(
                                c,
                                session,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE);
                if (rc != TSS2_RC_SUCCESS) {
                        r = log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                            "Failed to add authValue policy to TPM: %s",
                                            sym_Tss2_RC_Decode(rc));
                        goto finish;
                }
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

        if (ret_pcr_bank)
                *ret_pcr_bank = pcr_bank;

        r = 0;

finish:
        session = tpm2_flush_context_verbose(c, session);
        pubkey_handle = tpm2_flush_context_verbose(c, pubkey_handle);
        return r;
}

int tpm2_seal(const char *device,
              uint32_t hash_pcr_mask,
              const void *pubkey,
              const size_t pubkey_size,
              uint32_t pubkey_pcr_mask,
              const char *pin,
              void **ret_secret,
              size_t *ret_secret_size,
              void **ret_blob,
              size_t *ret_blob_size,
              void **ret_pcr_hash,
              size_t *ret_pcr_hash_size,
              uint16_t *ret_pcr_bank,
              uint16_t *ret_primary_alg) {

        _cleanup_(tpm2_context_destroy) struct tpm2_context c = {};
        _cleanup_(Esys_Freep) TPM2B_DIGEST *policy_digest = NULL;
        _cleanup_(Esys_Freep) TPM2B_PRIVATE *private = NULL;
        _cleanup_(Esys_Freep) TPM2B_PUBLIC *public = NULL;
        static const TPML_PCR_SELECTION creation_pcr = {};
        _cleanup_(erase_and_freep) void *secret = NULL;
        _cleanup_free_ void *blob = NULL, *hash = NULL;
        TPM2B_SENSITIVE_CREATE hmac_sensitive;
        ESYS_TR primary = ESYS_TR_NONE, session = ESYS_TR_NONE;
        TPMI_ALG_PUBLIC primary_alg;
        TPM2B_PUBLIC hmac_template;
        TPMI_ALG_HASH pcr_bank;
        size_t k, blob_size;
        usec_t start;
        TSS2_RC rc;
        int r;

        assert(pubkey || pubkey_size == 0);

        assert(ret_secret);
        assert(ret_secret_size);
        assert(ret_blob);
        assert(ret_blob_size);
        assert(ret_pcr_hash);
        assert(ret_pcr_hash_size);
        assert(ret_pcr_bank);

        assert(TPM2_PCR_MASK_VALID(hash_pcr_mask));
        assert(TPM2_PCR_MASK_VALID(pubkey_pcr_mask));

        /* So here's what we do here: we connect to the TPM2 chip. It persistently contains a "seed" key that
         * is randomized when the TPM2 is first initialized or reset and remains stable across boots. We
         * generate a "primary" key pair derived from that (ECC if possible, RSA as fallback). Given the seed
         * remains fixed this will result in the same key pair whenever we specify the exact same parameters
         * for it. We then create a PCR-bound policy session, which calculates a hash on the current PCR
         * values of the indexes we specify. We then generate a randomized key on the host (which is the key
         * we actually enroll in the LUKS2 keyslots), which we upload into the TPM2, where it is encrypted
         * with the "primary" key, taking the PCR policy session into account. We then download the encrypted
         * key from the TPM2 ("sealing") and marshall it into binary form, which is ultimately placed in the
         * LUKS2 JSON header.
         *
         * The TPM2 "seed" key and "primary" keys never leave the TPM2 chip (and cannot be extracted at
         * all). The random key we enroll in LUKS2 we generate on the host using the Linux random device. It
         * is stored in the LUKS2 JSON only in encrypted form with the "primary" key of the TPM2 chip, thus
         * binding the unlocking to the TPM2 chip. */

        start = now(CLOCK_MONOTONIC);

        r = tpm2_context_init(device, &c);
        if (r < 0)
                return r;

        r = tpm2_make_primary(c.esys_context, &primary, 0, &primary_alg);
        if (r < 0)
                return r;

        /* we cannot use the bind key before its created */
        r = tpm2_make_encryption_session(c.esys_context, primary, ESYS_TR_NONE, NULL, &session);
        if (r < 0)
                goto finish;

        r = tpm2_make_policy_session(
                        c.esys_context,
                        primary,
                        session,
                        TPM2_SE_TRIAL,
                        hash_pcr_mask,
                        /* pcr_bank= */ UINT16_MAX,
                        pubkey, pubkey_size,
                        pubkey_pcr_mask,
                        /* signature_json= */ NULL,
                        !!pin,
                        /* ret_session= */ NULL,
                        &policy_digest,
                        &pcr_bank);
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
                        .parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL,
                        .unique.keyedHash.size = 32,
                        .authPolicy = *policy_digest,
                },
        };

        hmac_sensitive = (TPM2B_SENSITIVE_CREATE) {
                .size = sizeof(hmac_sensitive.sensitive),
                .sensitive.data.size = 32,
        };
        if (pin)
                hash_pin(pin, strlen(pin), &hmac_sensitive.sensitive.userAuth);

        assert(sizeof(hmac_sensitive.sensitive.data.buffer) >= hmac_sensitive.sensitive.data.size);

        (void) tpm2_credit_random(c.esys_context);

        log_debug("Generating secret key data.");

        r = crypto_random_bytes(hmac_sensitive.sensitive.data.buffer, hmac_sensitive.sensitive.data.size);
        if (r < 0) {
                log_error_errno(r, "Failed to generate secret key: %m");
                goto finish;
        }

        log_debug("Creating HMAC key.");

        rc = sym_Esys_Create(
                        c.esys_context,
                        primary,
                        session, /* use HMAC session to enable parameter encryption */
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

        if (DEBUG_LOGGING)
                log_debug("Completed TPM2 key sealing in %s.", FORMAT_TIMESPAN(now(CLOCK_MONOTONIC) - start, 1));

        *ret_secret = TAKE_PTR(secret);
        *ret_secret_size = hmac_sensitive.sensitive.data.size;
        *ret_blob = TAKE_PTR(blob);
        *ret_blob_size = blob_size;
        *ret_pcr_hash = TAKE_PTR(hash);
        *ret_pcr_hash_size = policy_digest->size;
        *ret_pcr_bank = pcr_bank;
        *ret_primary_alg = primary_alg;

        r = 0;

finish:
        explicit_bzero_safe(&hmac_sensitive, sizeof(hmac_sensitive));
        primary = tpm2_flush_context_verbose(c.esys_context, primary);
        session = tpm2_flush_context_verbose(c.esys_context, session);
        return r;
}

int tpm2_unseal(const char *device,
                uint32_t hash_pcr_mask,
                uint16_t pcr_bank,
                const void *pubkey,
                size_t pubkey_size,
                uint32_t pubkey_pcr_mask,
                JsonVariant *signature,
                const char *pin,
                uint16_t primary_alg,
                const void *blob,
                size_t blob_size,
                const void *known_policy_hash,
                size_t known_policy_hash_size,
                void **ret_secret,
                size_t *ret_secret_size) {

        _cleanup_(tpm2_context_destroy) struct tpm2_context c = {};
        ESYS_TR primary = ESYS_TR_NONE, session = ESYS_TR_NONE, hmac_session = ESYS_TR_NONE,
                hmac_key = ESYS_TR_NONE;
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
        assert(pubkey_size == 0 || pubkey);
        assert(ret_secret);
        assert(ret_secret_size);

        assert(TPM2_PCR_MASK_VALID(hash_pcr_mask));
        assert(TPM2_PCR_MASK_VALID(pubkey_pcr_mask));

        r = dlopen_tpm2();
        if (r < 0)
                return log_error_errno(r, "TPM2 support is not installed.");

        /* So here's what we do here: We connect to the TPM2 chip. As we do when sealing we generate a
         * "primary" key on the TPM2 chip, with the same parameters as well as a PCR-bound policy session.
         * Given we pass the same parameters, this will result in the same "primary" key, and same policy
         * hash (the latter of course, only if the PCR values didn't change in between). We unmarshal the
         * encrypted key we stored in the LUKS2 JSON token header and upload it into the TPM2, where it is
         * decrypted if the seed and the PCR policy were right ("unsealing"). We then download the result,
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

        r = tpm2_context_init(device, &c);
        if (r < 0)
                return r;

        r = tpm2_make_primary(c.esys_context, &primary, primary_alg, NULL);
        if (r < 0)
                return r;

        log_debug("Loading HMAC key into TPM.");

        /*
         * Nothing sensitive on the bus, no need for encryption. Even if an attacker
         * gives you back a different key, the session initiation will fail if a pin
         * is provided. If an attacker gives back a bad key, we already lost since
         * primary key is not verified and they could attack there as well.
         */
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
                /* If we're in dictionary attack lockout mode, we should see a lockout error here, which we
                 * need to translate for the caller. */
                if (rc == TPM2_RC_LOCKOUT)
                        r = log_error_errno(
                                        SYNTHETIC_ERRNO(ENOLCK),
                                        "TPM2 device is in dictionary attack lockout mode.");
                else
                        r = log_error_errno(
                                        SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                        "Failed to load HMAC key in TPM: %s",
                                        sym_Tss2_RC_Decode(rc));
                goto finish;
        }

        r = tpm2_make_encryption_session(c.esys_context, primary, hmac_key, pin, &hmac_session);
        if (r < 0)
                goto finish;

        r = tpm2_make_policy_session(
                        c.esys_context,
                        primary,
                        hmac_session,
                        TPM2_SE_POLICY,
                        hash_pcr_mask,
                        pcr_bank,
                        pubkey, pubkey_size,
                        pubkey_pcr_mask,
                        signature,
                        !!pin,
                        &session,
                        &policy_digest,
                        /* ret_pcr_bank= */ NULL);
        if (r < 0)
                goto finish;

        /* If we know the policy hash to expect, and it doesn't match, we can shortcut things here, and not
         * wait until the TPM2 tells us to go away. */
        if (known_policy_hash_size > 0 &&
                memcmp_nn(policy_digest->buffer, policy_digest->size, known_policy_hash, known_policy_hash_size) != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                               "Current policy digest does not match stored policy digest, cancelling "
                                               "TPM2 authentication attempt.");

        log_debug("Unsealing HMAC key.");

        rc = sym_Esys_Unseal(
                        c.esys_context,
                        hmac_key,
                        session,
                        hmac_session, /* use HMAC session to enable parameter encryption */
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

        if (DEBUG_LOGGING)
                log_debug("Completed TPM2 key unsealing in %s.", FORMAT_TIMESPAN(now(CLOCK_MONOTONIC) - start, 1));

        *ret_secret = TAKE_PTR(secret);
        *ret_secret_size = unsealed->size;

        r = 0;

finish:
        primary = tpm2_flush_context_verbose(c.esys_context, primary);
        session = tpm2_flush_context_verbose(c.esys_context, session);
        hmac_key = tpm2_flush_context_verbose(c.esys_context, hmac_key);
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
        const char *p = ASSERT_PTR(s);
        uint32_t mask = 0;
        int r;

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

int tpm2_make_pcr_json_array(uint32_t pcr_mask, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *a = NULL;
        JsonVariant* pcr_array[TPM2_PCRS_MAX];
        unsigned n_pcrs = 0;
        int r;

        for (size_t i = 0; i < ELEMENTSOF(pcr_array); i++) {
                if ((pcr_mask & (UINT32_C(1) << i)) == 0)
                        continue;

                r = json_variant_new_integer(pcr_array + n_pcrs, i);
                if (r < 0)
                        goto finish;

                n_pcrs++;
        }

        r = json_variant_new_array(&a, pcr_array, n_pcrs);
        if (r < 0)
                goto finish;

        if (ret)
                *ret = TAKE_PTR(a);
        r = 0;

finish:
        json_variant_unref_many(pcr_array, n_pcrs);
        return r;
}

int tpm2_parse_pcr_json_array(JsonVariant *v, uint32_t *ret) {
        JsonVariant *e;
        uint32_t mask = 0;

        if (!json_variant_is_array(v))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "TPM2 PCR array is not a JSON array.");

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                uint64_t u;

                if (!json_variant_is_unsigned(e))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "TPM2 PCR is not an unsigned integer.");

                u = json_variant_unsigned(e);
                if (u >= TPM2_PCRS_MAX)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "TPM2 PCR number out of range: %" PRIu64, u);

                mask |= UINT32_C(1) << u;
        }

        if (ret)
                *ret = mask;

        return 0;
}

int tpm2_make_luks2_json(
                int keyslot,
                uint32_t hash_pcr_mask,
                uint16_t pcr_bank,
                const void *pubkey,
                size_t pubkey_size,
                uint32_t pubkey_pcr_mask,
                uint16_t primary_alg,
                const void *blob,
                size_t blob_size,
                const void *policy_hash,
                size_t policy_hash_size,
                TPM2Flags flags,
                JsonVariant **ret) {

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *hmj = NULL, *pkmj = NULL;
        _cleanup_free_ char *keyslot_as_string = NULL;
        int r;

        assert(blob || blob_size == 0);
        assert(policy_hash || policy_hash_size == 0);
        assert(pubkey || pubkey_size == 0);

        if (asprintf(&keyslot_as_string, "%i", keyslot) < 0)
                return -ENOMEM;

        r = tpm2_make_pcr_json_array(hash_pcr_mask, &hmj);
        if (r < 0)
                return r;

        if (pubkey_pcr_mask != 0) {
                r = tpm2_make_pcr_json_array(pubkey_pcr_mask, &pkmj);
                if (r < 0)
                        return r;
        }

        /* Note: We made the mistake of using "-" in the field names, which isn't particular compatible with
         * other programming languages. Let's not make things worse though, i.e. future additions to the JSON
         * object should use "_" rather than "-" in field names. */

        r = json_build(&v,
                       JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("type", JSON_BUILD_CONST_STRING("systemd-tpm2")),
                                       JSON_BUILD_PAIR("keyslots", JSON_BUILD_ARRAY(JSON_BUILD_STRING(keyslot_as_string))),
                                       JSON_BUILD_PAIR("tpm2-blob", JSON_BUILD_BASE64(blob, blob_size)),
                                       JSON_BUILD_PAIR("tpm2-pcrs", JSON_BUILD_VARIANT(hmj)),
                                       JSON_BUILD_PAIR_CONDITION(!!tpm2_pcr_bank_to_string(pcr_bank), "tpm2-pcr-bank", JSON_BUILD_STRING(tpm2_pcr_bank_to_string(pcr_bank))),
                                       JSON_BUILD_PAIR_CONDITION(!!tpm2_primary_alg_to_string(primary_alg), "tpm2-primary-alg", JSON_BUILD_STRING(tpm2_primary_alg_to_string(primary_alg))),
                                       JSON_BUILD_PAIR("tpm2-policy-hash", JSON_BUILD_HEX(policy_hash, policy_hash_size)),
                                       JSON_BUILD_PAIR("tpm2-pin", JSON_BUILD_BOOLEAN(flags & TPM2_FLAGS_USE_PIN)),
                                       JSON_BUILD_PAIR_CONDITION(pubkey_pcr_mask != 0, "tpm2_pubkey_pcrs", JSON_BUILD_VARIANT(pkmj)),
                                       JSON_BUILD_PAIR_CONDITION(pubkey_pcr_mask != 0, "tpm2_pubkey", JSON_BUILD_BASE64(pubkey, pubkey_size))));
        if (r < 0)
                return r;

        if (ret)
                *ret = TAKE_PTR(v);

        return keyslot;
}

int tpm2_parse_luks2_json(
                JsonVariant *v,
                int *ret_keyslot,
                uint32_t *ret_hash_pcr_mask,
                uint16_t *ret_pcr_bank,
                void **ret_pubkey,
                size_t *ret_pubkey_size,
                uint32_t *ret_pubkey_pcr_mask,
                uint16_t *ret_primary_alg,
                void **ret_blob,
                size_t *ret_blob_size,
                void **ret_policy_hash,
                size_t *ret_policy_hash_size,
                TPM2Flags *ret_flags) {

        _cleanup_free_ void *blob = NULL, *policy_hash = NULL, *pubkey = NULL;
        size_t blob_size = 0, policy_hash_size = 0, pubkey_size = 0;
        uint32_t hash_pcr_mask = 0, pubkey_pcr_mask = 0;
        uint16_t primary_alg = TPM2_ALG_ECC; /* ECC was the only supported algorithm in systemd < 250, use that as implied default, for compatibility */
        uint16_t pcr_bank = UINT16_MAX; /* default: pick automatically */
        int r, keyslot = -1;
        TPM2Flags flags = 0;
        JsonVariant *w;

        assert(v);

        if (ret_keyslot) {
                keyslot = cryptsetup_get_keyslot_from_token(v);
                if (keyslot < 0) {
                        /* Return a recognizable error when parsing this field, so that callers can handle parsing
                         * errors of the keyslots field gracefully, since it's not 'owned' by us, but by the LUKS2
                         * spec */
                        log_debug_errno(keyslot, "Failed to extract keyslot index from TPM2 JSON data token, skipping: %m");
                        return -EUCLEAN;
                }
        }

        w = json_variant_by_key(v, "tpm2-pcrs");
        if (!w)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "TPM2 token data lacks 'tpm2-pcrs' field.");

        r = tpm2_parse_pcr_json_array(w, &hash_pcr_mask);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse TPM2 PCR mask: %m");

        /* The bank field is optional, since it was added in systemd 250 only. Before the bank was hardcoded
         * to SHA256. */
        w = json_variant_by_key(v, "tpm2-pcr-bank");
        if (w) {
                /* The PCR bank field is optional */

                if (!json_variant_is_string(w))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "TPM2 PCR bank is not a string.");

                r = tpm2_pcr_bank_from_string(json_variant_string(w));
                if (r < 0)
                        return log_debug_errno(r, "TPM2 PCR bank invalid or not supported: %s", json_variant_string(w));

                pcr_bank = r;
        }

        /* The primary key algorithm field is optional, since it was also added in systemd 250 only. Before
         * the algorithm was hardcoded to ECC. */
        w = json_variant_by_key(v, "tpm2-primary-alg");
        if (w) {
                /* The primary key algorithm is optional */

                if (!json_variant_is_string(w))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "TPM2 primary key algorithm is not a string.");

                r = tpm2_primary_alg_from_string(json_variant_string(w));
                if (r < 0)
                        return log_debug_errno(r, "TPM2 primary key algorithm invalid or not supported: %s", json_variant_string(w));

                primary_alg = r;
        }

        w = json_variant_by_key(v, "tpm2-blob");
        if (!w)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "TPM2 token data lacks 'tpm2-blob' field.");

        r = json_variant_unbase64(w, &blob, &blob_size);
        if (r < 0)
                return log_debug_errno(r, "Invalid base64 data in 'tpm2-blob' field.");

        w = json_variant_by_key(v, "tpm2-policy-hash");
        if (!w)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "TPM2 token data lacks 'tpm2-policy-hash' field.");

        r = json_variant_unhex(w, &policy_hash, &policy_hash_size);
        if (r < 0)
                return log_debug_errno(r, "Invalid base64 data in 'tpm2-policy-hash' field.");

        w = json_variant_by_key(v, "tpm2-pin");
        if (w) {
                if (!json_variant_is_boolean(w))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "TPM2 PIN policy is not a boolean.");

                SET_FLAG(flags, TPM2_FLAGS_USE_PIN, json_variant_boolean(w));
        }

        w = json_variant_by_key(v, "tpm2_pubkey_pcrs");
        if (w) {
                r = tpm2_parse_pcr_json_array(w, &pubkey_pcr_mask);
                if (r < 0)
                        return r;
        }

        w = json_variant_by_key(v, "tpm2_pubkey");
        if (w) {
                r = json_variant_unbase64(w, &pubkey, &pubkey_size);
                if (r < 0)
                        return log_debug_errno(r, "Failed to decode PCR public key.");
        } else if (pubkey_pcr_mask != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Public key PCR mask set, but not public key included in JSON data, refusing.");

        if (ret_keyslot)
                *ret_keyslot = keyslot;
        if (ret_hash_pcr_mask)
                *ret_hash_pcr_mask = hash_pcr_mask;
        if (ret_pcr_bank)
                *ret_pcr_bank = pcr_bank;
        if (ret_pubkey)
                *ret_pubkey = TAKE_PTR(pubkey);
        if (ret_pubkey_size)
                *ret_pubkey_size = pubkey_size;
        if (ret_pubkey_pcr_mask)
                *ret_pubkey_pcr_mask = pubkey_pcr_mask;
        if (ret_primary_alg)
                *ret_primary_alg = primary_alg;
        if (ret_blob)
                *ret_blob = TAKE_PTR(blob);
        if (ret_blob_size)
                *ret_blob_size = blob_size;
        if (ret_policy_hash)
                *ret_policy_hash = TAKE_PTR(policy_hash);
        if (ret_policy_hash_size)
                *ret_policy_hash_size = policy_hash_size;
        if (ret_flags)
                *ret_flags = flags;

        return 0;
}

const char *tpm2_pcr_bank_to_string(uint16_t bank) {
        if (bank == TPM2_ALG_SHA1)
                return "sha1";
        if (bank == TPM2_ALG_SHA256)
                return "sha256";
        if (bank == TPM2_ALG_SHA384)
                return "sha384";
        if (bank == TPM2_ALG_SHA512)
                return "sha512";
        return NULL;
}

int tpm2_pcr_bank_from_string(const char *bank) {
        if (strcaseeq_ptr(bank, "sha1"))
                return TPM2_ALG_SHA1;
        if (strcaseeq_ptr(bank, "sha256"))
                return TPM2_ALG_SHA256;
        if (strcaseeq_ptr(bank, "sha384"))
                return TPM2_ALG_SHA384;
        if (strcaseeq_ptr(bank, "sha512"))
                return TPM2_ALG_SHA512;
        return -EINVAL;
}

const char *tpm2_primary_alg_to_string(uint16_t alg) {
        if (alg == TPM2_ALG_ECC)
                return "ecc";
        if (alg == TPM2_ALG_RSA)
                return "rsa";
        return NULL;
}

int tpm2_primary_alg_from_string(const char *alg) {
        if (strcaseeq_ptr(alg, "ecc"))
                return TPM2_ALG_ECC;
        if (strcaseeq_ptr(alg, "rsa"))
                return TPM2_ALG_RSA;
        return -EINVAL;
}

Tpm2Support tpm2_support(void) {
        Tpm2Support support = TPM2_SUPPORT_NONE;
        int r;

        if (detect_container() <= 0) {
                /* Check if there's a /dev/tpmrm* device via sysfs. If we run in a container we likely just
                 * got the host sysfs mounted. Since devices are generally not virtualized for containers,
                 * let's assume containers never have a TPM, at least for now. */

                r = dir_is_empty("/sys/class/tpmrm", /* ignore_hidden_or_backup= */ false);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_debug_errno(r, "Unable to test whether /sys/class/tpmrm/ exists and is populated, assuming it is not: %m");
                } else if (r == 0) /* populated! */
                        support |= TPM2_SUPPORT_SUBSYSTEM|TPM2_SUPPORT_DRIVER;
                else
                        /* If the directory exists but is empty, we know the subsystem is enabled but no
                         * driver has been loaded yet. */
                        support |= TPM2_SUPPORT_SUBSYSTEM;
        }

        if (efi_has_tpm2())
                support |= TPM2_SUPPORT_FIRMWARE;

#if HAVE_TPM2
        support |= TPM2_SUPPORT_SYSTEM;
#endif

        return support;
}

int tpm2_parse_pcr_argument(const char *arg, uint32_t *mask) {
        uint32_t m;
        int r;

        assert(mask);

        /* For use in getopt_long() command line parsers: merges masks specified on the command line */

        if (isempty(arg)) {
                *mask = 0;
                return 0;
        }

        r = tpm2_parse_pcrs(arg, &m);
        if (r < 0)
                return r;

        if (*mask == UINT32_MAX)
                *mask = m;
        else
                *mask |= m;

        return 0;
}

int tpm2_load_pcr_signature(const char *path, JsonVariant **ret) {
        _cleanup_free_ char *discovered_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        /* Tries to load a JSON PCR signature file. Takes an absolute path, a simple file name or NULL. In
         * the latter two cases searches in /etc/, /usr/lib/, /run/, as usual. */

        if (!path)
                path = "tpm2-pcr-signature.json";

        r = search_and_fopen(path, "re", NULL, (const char**) CONF_PATHS_STRV("systemd"), &f, &discovered_path);
        if (r < 0)
                return log_debug_errno(r, "Failed to find TPM PCR signature file '%s': %m", path);

        r = json_parse_file(f, discovered_path, 0, ret, NULL, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse TPM PCR signature JSON object '%s': %m", discovered_path);

        return 0;
}

int tpm2_load_pcr_public_key(const char *path, void **ret_pubkey, size_t *ret_pubkey_size) {
        _cleanup_free_ char *discovered_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        /* Tries to load a PCR public key file. Takes an absolute path, a simple file name or NULL. In the
         * latter two cases searches in /etc/, /usr/lib/, /run/, as usual. */

        if (!path)
                path = "tpm2-pcr-public-key.pem";

        r = search_and_fopen(path, "re", NULL, (const char**) CONF_PATHS_STRV("systemd"), &f, &discovered_path);
        if (r < 0)
                return log_debug_errno(r, "Failed to find TPM PCR public key file '%s': %m", path);

        r = read_full_stream(f, (char**) ret_pubkey, ret_pubkey_size);
        if (r < 0)
                return log_debug_errno(r, "Failed to load TPM PCR public key PEM file '%s': %m", discovered_path);

        return 0;
}

int pcr_mask_to_string(uint32_t mask, char **ret) {
        _cleanup_free_ char *buf = NULL;
        int r;

        assert(ret);

        for (unsigned i = 0; i < TPM2_PCRS_MAX; i++) {
                if (!(mask & (UINT32_C(1) << i)))
                        continue;

                r = strextendf_with_separator(&buf, "+", "%u", i);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(buf);
        return 0;
}
