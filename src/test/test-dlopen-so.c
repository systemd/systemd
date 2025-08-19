/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "apparmor-util.h"
#include "bpf-dlopen.h"
#include "compress.h"
#include "cryptsetup-util.h"
#include "elf-util.h"
#include "gcrypt-util.h"
#include "idn-util.h"
#include "libarchive-util.h"
#include "libfido2-util.h"
#include "main-func.h"
#include "module-util.h"
#include "password-quality-util-passwdqc.h"
#include "password-quality-util-pwquality.h"
#include "pcre2-util.h"
#include "pkcs11-util.h"
#include "qrcode-util.h"
#include "tests.h"
#include "tpm2-util.h"

static int run(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        /* Try to load each of our weak library dependencies once. This is supposed to help finding cases
         * where .so versions change and distributions update, but systemd doesn't have the new so names
         * around yet. */

#if HAVE_LIBIDN2 || HAVE_LIBIDN
        ASSERT_OK(dlopen_idn());
#else
        ASSERT_ERROR(dlopen_idn(), EOPNOTSUPP);
#endif

#if HAVE_LIBCRYPTSETUP
        ASSERT_OK(dlopen_cryptsetup());
#else
        ASSERT_ERROR(dlopen_cryptsetup(), EOPNOTSUPP);
#endif

#if HAVE_PASSWDQC
        ASSERT_OK(dlopen_passwdqc());
#else
        ASSERT_ERROR(dlopen_passwdqc(), EOPNOTSUPP);
#endif

#if HAVE_PWQUALITY
        ASSERT_OK(dlopen_pwquality());
#else
        ASSERT_ERROR(dlopen_pwquality(), EOPNOTSUPP);
#endif

#if HAVE_QRENCODE
        ASSERT_OK(dlopen_qrencode());
#else
        ASSERT_ERROR(dlopen_qrencode(), EOPNOTSUPP);
#endif

#if HAVE_TPM2
        ASSERT_OK(dlopen_tpm2());
#else
        ASSERT_ERROR(dlopen_tpm2(), EOPNOTSUPP);
#endif

#if HAVE_LIBFIDO2
        ASSERT_OK(dlopen_libfido2());
#else
        ASSERT_ERROR(dlopen_libfido2(), EOPNOTSUPP);
#endif

#if HAVE_LIBBPF
        ASSERT_OK(dlopen_bpf());
#else
        ASSERT_ERROR(dlopen_bpf(), EOPNOTSUPP);
#endif

#if HAVE_ELFUTILS
        ASSERT_OK(dlopen_dw());
        ASSERT_OK(dlopen_elf());
#else
        ASSERT_ERROR(dlopen_dw(), EOPNOTSUPP);
        ASSERT_ERROR(dlopen_elf(), EOPNOTSUPP);
#endif

#if HAVE_PCRE2
        ASSERT_OK(dlopen_pcre2());
#else
        ASSERT_ERROR(dlopen_pcre2(), EOPNOTSUPP);
#endif

#if HAVE_P11KIT
        ASSERT_OK(dlopen_p11kit());
#else
        ASSERT_ERROR(dlopen_p11kit(), EOPNOTSUPP);
#endif

#if HAVE_LIBARCHIVE
        ASSERT_OK(dlopen_libarchive());
#else
        ASSERT_ERROR(dlopen_libarchive(), EOPNOTSUPP);
#endif

#if HAVE_LZ4
        ASSERT_OK(dlopen_lz4());
#else
        ASSERT_ERROR(dlopen_lz4(), EOPNOTSUPP);
#endif

#if HAVE_ZSTD
        ASSERT_OK(dlopen_zstd());
#else
        ASSERT_ERROR(dlopen_zstd(), EOPNOTSUPP);
#endif

#if HAVE_XZ
        ASSERT_OK(dlopen_lzma());
#else
        ASSERT_ERROR(dlopen_lzma(), EOPNOTSUPP);
#endif

#if HAVE_GCRYPT
        ASSERT_OK(initialize_libgcrypt(/* secmem= */ false));
#else
        ASSERT_ERROR(initialize_libgcrypt(/* secmem= */ false), EOPNOTSUPP);
#endif

#if HAVE_KMOD
        ASSERT_OK(dlopen_libkmod());
#else
        ASSERT_ERROR(dlopen_libkmod(), EOPNOTSUPP);
#endif

#if HAVE_APPARMOR
        ASSERT_OK(dlopen_libapparmor());
#else
        ASSERT_ERROR(dlopen_libapparmor(), EOPNOTSUPP);
#endif

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
