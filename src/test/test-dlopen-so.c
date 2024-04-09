/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dlfcn.h>
#include <stdlib.h>

#include "bpf-dlopen.h"
#include "compress.h"
#include "cryptsetup-util.h"
#include "elf-util.h"
#include "gcrypt-util.h"
#include "idn-util.h"
#include "libarchive-util.h"
#include "libfido2-util.h"
#include "macro.h"
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
#endif

#if HAVE_LIBCRYPTSETUP
        ASSERT_OK(dlopen_cryptsetup());
#endif

#if HAVE_PASSWDQC
        ASSERT_OK(dlopen_passwdqc());
#endif

#if HAVE_PWQUALITY
        ASSERT_OK(dlopen_pwquality());
#endif

#if HAVE_QRENCODE
        ASSERT_OK(dlopen_qrencode());
#endif

#if HAVE_TPM2
        ASSERT_OK(dlopen_tpm2());
#endif

#if HAVE_LIBFIDO2
        ASSERT_OK(dlopen_libfido2());
#endif

#if HAVE_LIBBPF
        ASSERT_OK(dlopen_bpf());
#endif

#if HAVE_ELFUTILS
        ASSERT_OK(dlopen_dw());
        ASSERT_OK(dlopen_elf());
#endif

#if HAVE_PCRE2
        ASSERT_OK(dlopen_pcre2());
#endif

#if HAVE_P11KIT
        ASSERT_OK(dlopen_p11kit());
#endif

#if HAVE_LIBARCHIVE
        ASSERT_OK(dlopen_libarchive());
#endif

#if HAVE_LZ4
        ASSERT_OK(dlopen_lz4());
#endif

#if HAVE_ZSTD
        ASSERT_OK(dlopen_zstd());
#endif

#if HAVE_XZ
        ASSERT_OK(dlopen_lzma());
#endif

#if HAVE_GCRYPT
        assert_se(initialize_libgcrypt(/* secmem= */ false) >= 0);
#endif

#if HAVE_KMOD
        ASSERT_OK(dlopen_libkmod());
#endif

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
