/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "openssl-util.h"
#include "pkcs7-util.h"
#include "log.h"

#define SIGNERS_MAX 32

static void signer_done(Signer *signer) {
        assert(signer);

        iovec_done(&signer->issuer);
        iovec_done(&signer->serial);
}

void signer_free_many(Signer *signers, size_t n) {
        assert(signers || n == 0);

        FOREACH_ARRAY(i, signers, n)
                signer_done(i);

        free(signers);
}

int pkcs7_extract_signers(
                const struct iovec *sig,
                Signer **ret_signers,
                size_t *ret_n_signers) {

        assert(ret_signers);
        assert(ret_n_signers);

        if (!iovec_is_set(sig))
                return -EBADMSG;

#if HAVE_OPENSSL
        const unsigned char *d = sig->iov_base;
        _cleanup_(PKCS7_freep) PKCS7 *p7 = NULL;
        p7 = d2i_PKCS7(/* a= */ NULL, &d, (long) sig->iov_len);
        if (!p7)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Failed to parse PKCS7 DER signature data.");

        STACK_OF(PKCS7_SIGNER_INFO) *sinfos = PKCS7_get_signer_info(p7);
        if (!sinfos)
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "No signature information in PKCS7 signature?");
        int n = sk_PKCS7_SIGNER_INFO_num(sinfos);
        if (n == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "No signatures in PKCS7 signature, refusing.");
        if (n > SIGNERS_MAX) /* safety net, in case people send us weirdly complex signatures */
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Too many signatures, refusing.");
        assert(n > 0);

        size_t n_signers = 0;
        Signer *signers = new(Signer, n);
        if (!signers)
                return log_oom_debug();

        CLEANUP_ARRAY(signers, n_signers, signer_free_many);

        for (int i = 0; i < n; i++) {
                PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(p7), i);
                if (!si)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to get signer information.");

                _cleanup_(signer_done) Signer signer = {};

                _cleanup_free_ unsigned char *p = NULL;
                int len = i2d_X509_NAME(si->issuer_and_serial->issuer, &p);
                signer.issuer = IOVEC_MAKE(TAKE_PTR(p), len);

                len = i2d_ASN1_INTEGER(si->issuer_and_serial->serial, &p);
                signer.serial = IOVEC_MAKE(TAKE_PTR(p), len);

                signers[n_signers++] = TAKE_STRUCT(signer);
        }

        *ret_signers = TAKE_PTR(signers);
        *ret_n_signers = n_signers;
        return n;
#else
        return -EOPNOTSUPP;
#endif
}
