/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "extract-word.h"
#include "log.h"
#include "string-util.h"
#include "version.h"

const char* const systemd_features =

        /* PAM and MAC frameworks */

#if HAVE_PAM
        "+PAM"
#else
        "-PAM"
#endif

#if HAVE_AUDIT
        " +AUDIT"
#else
        " -AUDIT"
#endif

#if HAVE_SELINUX
        " +SELINUX"
#else
        " -SELINUX"
#endif

#if HAVE_APPARMOR
        " +APPARMOR"
#else
        " -APPARMOR"
#endif

#if ENABLE_IMA
        " +IMA"
#else
        " -IMA"
#endif

#if ENABLE_IPE
        " +IPE"
#else
        " -IPE"
#endif

#if ENABLE_SMACK
        " +SMACK"
#else
        " -SMACK"
#endif

#if HAVE_SECCOMP
        " +SECCOMP"
#else
        " -SECCOMP"
#endif

        /* cryptographic libraries */

#if HAVE_GCRYPT
        " +GCRYPT"
#else
        " -GCRYPT"
#endif

#if HAVE_GNUTLS
        " +GNUTLS"
#else
        " -GNUTLS"
#endif

#if HAVE_OPENSSL
        " +OPENSSL"
#else
        " -OPENSSL"
#endif

        /* all other libraries, sorted alphabetically */

#if HAVE_ACL
        " +ACL"
#else
        " -ACL"
#endif

#if HAVE_BLKID
        " +BLKID"
#else
        " -BLKID"
#endif

#if HAVE_LIBCURL
        " +CURL"
#else
        " -CURL"
#endif

#if HAVE_ELFUTILS
        " +ELFUTILS"
#else
        " -ELFUTILS"
#endif

#if HAVE_LIBFIDO2
        " +FIDO2"
#else
        " -FIDO2"
#endif

#if HAVE_LIBIDN2
        " +IDN2"
#else
        " -IDN2"
#endif

#if HAVE_LIBIDN
        " +IDN"
#else
        " -IDN"
#endif

#if HAVE_LIBIPTC
        " +IPTC"
#else
        " -IPTC"
#endif

#if HAVE_KMOD
        " +KMOD"
#else
        " -KMOD"
#endif

#if HAVE_LIBCRYPTSETUP
        " +LIBCRYPTSETUP"
#else
        " -LIBCRYPTSETUP"
#endif

#if HAVE_LIBCRYPTSETUP_PLUGINS
        " +LIBCRYPTSETUP_PLUGINS"
#else
        " -LIBCRYPTSETUP_PLUGINS"
#endif

#if HAVE_LIBFDISK
        " +LIBFDISK"
#else
        " -LIBFDISK"
#endif

#if HAVE_PCRE2
        " +PCRE2"
#else
        " -PCRE2"
#endif

#if HAVE_PWQUALITY
        " +PWQUALITY"
#else
        " -PWQUALITY"
#endif

#if HAVE_P11KIT
        " +P11KIT"
#else
        " -P11KIT"
#endif

#if HAVE_QRENCODE
        " +QRENCODE"
#else
        " -QRENCODE"
#endif

#if HAVE_TPM2
        " +TPM2"
#else
        " -TPM2"
#endif

        /* compressors */

#if HAVE_BZIP2
        " +BZIP2"
#else
        " -BZIP2"
#endif

#if HAVE_LZ4
        " +LZ4"
#else
        " -LZ4"
#endif

#if HAVE_XZ
        " +XZ"
#else
        " -XZ"
#endif

#if HAVE_ZLIB
        " +ZLIB"
#else
        " -ZLIB"
#endif

#if HAVE_ZSTD
        " +ZSTD"
#else
        " -ZSTD"
#endif

        /* other stuff that doesn't fit above */

#if BPF_FRAMEWORK
        " +BPF_FRAMEWORK"
#else
        " -BPF_FRAMEWORK"
#endif

#if HAVE_VMLINUX_H
        " +BTF"
#else
        " -BTF"
#endif

#if HAVE_XKBCOMMON
        " +XKBCOMMON"
#else
        " -XKBCOMMON"
#endif

#if ENABLE_UTMP
        " +UTMP"
#else
        " -UTMP"
#endif

#if HAVE_SYSV_COMPAT
        " +SYSVINIT"
#else
        " -SYSVINIT"
#endif

#if HAVE_LIBARCHIVE
        " +LIBARCHIVE"
#else
        " -LIBARCHIVE"
#endif

        ;

static char* systemd_features_with_color(void) {
        const char *p = systemd_features;
        _cleanup_free_ char *ret = NULL;
        int r;

        for (;;) {
                _cleanup_free_ char *word = NULL;
                char *q;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0) {
                        log_warning_errno(r, "Cannot split features string, ignoring: %m");
                        return NULL;
                }
                if (r == 0)
                        return TAKE_PTR(ret);

                if (ret && !strextend(&ret, " ")) {
                        log_oom_warning();
                        return NULL;
                }

                if (word[0] == '+')
                        q = strextend(&ret, ANSI_HIGHLIGHT_GREEN, CHAR_TO_STR(word[0]), ANSI_GREEN, word+1, ANSI_NORMAL);
                else if (word[0] == '-')
                        q = strextend(&ret, ANSI_HIGHLIGHT_RED, CHAR_TO_STR(word[0]), ANSI_RED, word+1, ANSI_NORMAL);
                else
                        q = strextend(&ret, word);
                if (!q) {
                        log_oom_warning();
                        return NULL;
                }
        }
}

int version(void) {
        _cleanup_free_ char *b = NULL;

        if (colors_enabled())
                b = systemd_features_with_color();

        printf("%ssystemd %i%s (" GIT_VERSION ")\n%s\n",
               ansi_highlight(), PROJECT_VERSION, ansi_normal(),
               b ?: systemd_features);
        return 0;
}
