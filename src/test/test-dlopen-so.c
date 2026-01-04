/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "acl-util.h"
#include "apparmor-util.h"
#include "blkid-util.h"
#include "bpf-dlopen.h"
#include "compress.h"
#include "cryptsetup-util.h"
#include "elf-util.h"
#include "gcrypt-util.h"
#include "idn-util.h"
#include "libarchive-util.h"
#include "libaudit-util.h"
#include "libcrypt-util.h"
#include "libfido2-util.h"
#include "libmount-util.h"
#include "main-func.h"
#include "module-util.h"
#include "pam-util.h"
#include "password-quality-util-passwdqc.h"
#include "password-quality-util-pwquality.h"
#include "pcre2-util.h"
#include "pkcs11-util.h"
#include "qrcode-util.h"
#include "seccomp-util.h"
#include "selinux-util.h"
#include "tests.h"
#include "tpm2-util.h"

#define ASSERT_DLOPEN(func, cond)                               \
        do {                                                    \
                if (cond)                                       \
                        ASSERT_OK(func());                      \
                else                                            \
                        ASSERT_ERROR(func(), EOPNOTSUPP);       \
        } while (false)

static int run(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        /* Try to load each of our weak library dependencies once. This is supposed to help finding cases
         * where .so versions change and distributions update, but systemd doesn't have the new so names
         * around yet. */

        ASSERT_DLOPEN(dlopen_bpf, HAVE_LIBBPF);
        ASSERT_DLOPEN(dlopen_cryptsetup, HAVE_LIBCRYPTSETUP);
        ASSERT_DLOPEN(dlopen_dw, HAVE_ELFUTILS);
        ASSERT_DLOPEN(dlopen_elf, HAVE_ELFUTILS);
        ASSERT_DLOPEN(dlopen_gcrypt, HAVE_GCRYPT);
        ASSERT_DLOPEN(dlopen_idn, HAVE_LIBIDN2);
        ASSERT_DLOPEN(dlopen_libacl, HAVE_ACL);
        ASSERT_DLOPEN(dlopen_libapparmor, HAVE_APPARMOR);
        ASSERT_DLOPEN(dlopen_libarchive, HAVE_LIBARCHIVE);
        ASSERT_DLOPEN(dlopen_libaudit, HAVE_AUDIT);
        ASSERT_DLOPEN(dlopen_libblkid, HAVE_BLKID);
        ASSERT_DLOPEN(dlopen_libcrypt, HAVE_LIBCRYPT);
        ASSERT_DLOPEN(dlopen_libfido2, HAVE_LIBFIDO2);
        ASSERT_DLOPEN(dlopen_libkmod, HAVE_KMOD);
        ASSERT_DLOPEN(dlopen_libmount, HAVE_LIBMOUNT);
        ASSERT_DLOPEN(dlopen_libpam, HAVE_PAM);
        ASSERT_DLOPEN(dlopen_libseccomp, HAVE_SECCOMP);
        ASSERT_DLOPEN(dlopen_libselinux, HAVE_SELINUX);
        ASSERT_DLOPEN(dlopen_lz4, HAVE_LZ4);
        ASSERT_DLOPEN(dlopen_lzma, HAVE_XZ);
        ASSERT_DLOPEN(dlopen_p11kit, HAVE_P11KIT);
        ASSERT_DLOPEN(dlopen_passwdqc, HAVE_PASSWDQC);
        ASSERT_DLOPEN(dlopen_pcre2, HAVE_PCRE2);
        ASSERT_DLOPEN(dlopen_pwquality, HAVE_PWQUALITY);
        ASSERT_DLOPEN(dlopen_qrencode, HAVE_QRENCODE);
        ASSERT_DLOPEN(dlopen_tpm2, HAVE_TPM2);
        ASSERT_DLOPEN(dlopen_zstd, HAVE_ZSTD);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
