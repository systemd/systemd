/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "../basic/dlopen-note.h"       /* IWYU pragma: export */
#include "forward.h"

#if HAVE_ACL
#  define LIBACL_NOTE(priority)                                         \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        acl,                                            \
                        "Support for file Access Control Lists (ACLs)", \
                        priority,                                       \
                        "libacl.so.1")
#else
#  define LIBACL_NOTE(priority)
#endif

#if HAVE_APPARMOR
#  define LIBAPPARMOR_NOTE(priority)                                    \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        apparmor,                                       \
                        "Support for AppArmor policies",                \
                        priority,                                       \
                        "libapparmor.so.1")
#else
#  define LIBAPPARMOR_NOTE(priority)
#endif

#if HAVE_LIBARCHIVE
#  define LIBARCHIVE_NOTE(priority)                                     \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        archive,                                        \
                        "Support for decompressing archive files",      \
                        priority,                                       \
                        "libarchive.so.13")
#else
#  define LIBARCHIVE_NOTE(priority)
#endif

#if HAVE_AUDIT
#  define LIBAUDIT_NOTE(priority)                     \
        ELF_NOTE_DLOPEN_ANCHORED(                     \
                        audit,                        \
                        "Support for Audit logging",  \
                        priority,                     \
                        "libaudit.so.1")
#else
#  define LIBAUDIT_NOTE(priority)
#endif

#if HAVE_BLKID
#  define LIBBLKID_NOTE(priority)                                       \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        blkid,                                          \
                        "Support for block device identification",      \
                        priority,                                       \
                        "libblkid.so.1")
#else
#  define LIBBLKID_NOTE(priority)
#endif

#if HAVE_LIBBPF
#  define LIBBPF_NOTE(priority)                                         \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        bpf,                                            \
                        "Support firewalling and sandboxing with BPF",  \
                        priority,                                       \
                        "libbpf.so.1", "libbpf.so.0")
#else
#  define LIBBPF_NOTE(priority)
#endif

#if HAVE_LIBCRYPT && defined(__GLIBC__)
#  define LIBCRYPT_NOTE(priority)                                       \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        crypt,                                          \
                        "Support for hashing passwords",                \
                        priority,                                       \
                        "libcrypt.so.2", "libcrypt.so.1", "libcrypt.so.1.1")
#else
#  define LIBCRYPT_NOTE(priority)
#endif

#if HAVE_OPENSSL
#  define LIBCRYPTO_NOTE(priority)                                      \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        libcrypto,                                      \
                        "Support for cryptographic operations",         \
                        priority,                                       \
                        "libcrypto.so.4", "libcrypto.so.3")
#else
#  define LIBCRYPTO_NOTE(priority)
#endif

#if HAVE_LIBCRYPTSETUP
#  define LIBCRYPTSETUP_NOTE(priority)                                  \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        cryptsetup,                                     \
                        "Support for disk encryption, integrity, and authentication", \
                        priority,                                       \
                        "libcryptsetup.so.12")
#else
#  define LIBCRYPTSETUP_NOTE(priority)
#endif

#if HAVE_LIBCURL
#  define LIBCURL_NOTE(priority)                                        \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        curl,                                           \
                        "Support for downloading and uploading files over HTTP", \
                        priority,                                       \
                        "libcurl.so.4")
#else
#  define LIBCURL_NOTE(priority)
#endif

#if HAVE_LIBFDISK
#  define LIBFDISK_NOTE(priority)                                       \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        fdisk,                                          \
                        "Support for reading and writing partition tables", \
                        priority,                                       \
                        "libfdisk.so.1")
#else
#  define LIBFDISK_NOTE(priority)
#endif

#if HAVE_ELFUTILS
#  define LIBDW_NOTE(priority)                                          \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        dw,                                             \
                        "Support for backtrace and ELF package metadata decoding from core files", \
                        priority,                                       \
                        "libdw.so.1")
#else
#  define LIBDW_NOTE(priority)
#endif

#if HAVE_ELFUTILS
#  define LIBELF_NOTE(priority)                                         \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        elf,                                            \
                        "Support for backtraces and reading ELF package metadata from core files", \
                        priority,                                       \
                        "libelf.so.1")
#else
#  define LIBELF_NOTE(priority)
#endif

#if HAVE_LIBFIDO2
#  define LIBFIDO2_NOTE(priority)                                       \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        fido2,                                          \
                        "Support fido2 for encryption and authentication", \
                        priority,                                       \
                        "libfido2.so.1")
#else
#  define LIBFIDO2_NOTE(priority)
#endif

#if HAVE_GNUTLS
#  define LIBGNUTLS_NOTE(priority)                              \
        ELF_NOTE_DLOPEN_ANCHORED(                               \
                        gnutls,                                 \
                        "Support for TLS via GnuTLS",           \
                        priority,                               \
                        "libgnutls.so.30")
#else
#  define LIBGNUTLS_NOTE(priority)
#endif

#if HAVE_LIBIDN2
#  define LIBIDN2_NOTE(priority)                                        \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        idn,                                            \
                        "Support for internationalized domain names",   \
                        priority,                                       \
                        "libidn2.so.0")
#else
#  define LIBIDN2_NOTE(priority)
#endif

#if HAVE_KMOD
#  define LIBKMOD_NOTE(priority)                                        \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        kmod,                                           \
                        "Support for loading kernel modules",           \
                        priority,                                       \
                        "libkmod.so.2")
#else
#  define LIBKMOD_NOTE(priority)
#endif

#if HAVE_MICROHTTPD
#  define LIBMICROHTTPD_NOTE(priority)                                  \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        microhttpd,                                     \
                        "Support for embedded HTTP server via libmicrohttpd", \
                        priority,                                       \
                        "libmicrohttpd.so.12")
#else
#  define LIBMICROHTTPD_NOTE(priority)
#endif

#if HAVE_LIBMOUNT
#  define LIBMOUNT_NOTE(priority)                                       \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        mount,                                          \
                        "Support for mount enumeration",                \
                        priority,                                       \
                        "libmount.so.1")
#else
#  define LIBMOUNT_NOTE(priority)
#endif

#if HAVE_P11KIT
#  define LIBP11KIT_NOTE(priority)                                 \
        SD_ELF_NOTE_DLOPEN_ANCHORED(                               \
                        p11kit_##priority,                         \
                        "p11-kit",                                 \
                        "Support for PKCS11 hardware tokens",      \
                        STRINGIFY(priority),                       \
                        "libp11-kit.so.0")
#else
#  define LIBP11KIT_NOTE(priority)
#endif

#if HAVE_PAM
#  define LIBPAM_NOTE(priority)                                         \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        pam,                                            \
                        "Support for LinuxPAM",                         \
                        priority,                                       \
                        "libpam.so.0")
#else
#  define LIBPAM_NOTE(priority)
#endif

#if HAVE_PASSWDQC
#  define LIBPASSWDQC_NOTE(priority)                            \
        ELF_NOTE_DLOPEN_ANCHORED(                               \
                        passwdqc,                               \
                        "Support for password quality checks",  \
                        priority,                               \
                        "libpasswdqc.so.1")
#else
#  define LIBPASSWDQC_NOTE(priority)
#endif

#if HAVE_PCRE2
#  define LIBPCRE2_NOTE(priority)                               \
        ELF_NOTE_DLOPEN_ANCHORED(                               \
                        pcre2,                                  \
                        "Support for regular expressions",      \
                        priority,                               \
                        "libpcre2-8.so.0")
#else
#  define LIBPCRE2_NOTE(priority)
#endif

#if HAVE_PWQUALITY
#  define LIBPWQUALITY_NOTE(priority)                           \
        ELF_NOTE_DLOPEN_ANCHORED(                               \
                        pwquality,                              \
                        "Support for password quality checks",  \
                        priority,                               \
                        "libpwquality.so.1")
#else
#  define LIBPWQUALITY_NOTE(priority)
#endif

#if HAVE_QRENCODE
#  define LIBQRENCODE_NOTE(priority)                            \
        ELF_NOTE_DLOPEN_ANCHORED(                               \
                        qrencode,                               \
                        "Support for generating QR codes",      \
                        priority,                               \
                        "libqrencode.so.4", "libqrencode.so.3")
#else
#  define LIBQRENCODE_NOTE(priority)
#endif

#if HAVE_SECCOMP
#  define LIBSECCOMP_NOTE(priority)                                     \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        seccomp,                                        \
                        "Support for Seccomp Sandboxes",                \
                        priority,                                       \
                        "libseccomp.so.2")
#else
#  define LIBSECCOMP_NOTE(priority)
#endif

#if HAVE_SELINUX
#  define LIBSELINUX_NOTE(priority)                                     \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        selinux,                                        \
                        "Support for SELinux",                          \
                        priority,                                       \
                        "libselinux.so.1")
#else
#  define LIBSELINUX_NOTE(priority)
#endif

#if HAVE_OPENSSL
#  define LIBSSL_NOTE(priority)                                         \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        libssl,                                         \
                        "Support for TLS",                              \
                        priority,                                       \
                        "libssl.so.4", "libssl.so.3")
#else
#  define LIBSSL_NOTE(priority)
#endif

#if HAVE_TPM2
#  define LIBTSS2_ESYS_NOTE(priority)           \
        SD_ELF_NOTE_DLOPEN_ANCHORED(            \
                        tpm2_esys_##priority,   \
                        "tpm",                  \
                        "Support for TPM",      \
                        STRINGIFY(priority),    \
                        "libtss2-esys.so.0")
#  define LIBTSS2_RC_NOTE(priority)             \
        SD_ELF_NOTE_DLOPEN_ANCHORED(            \
                        tpm2_rc_##priority,     \
                        "tpm",                  \
                        "Support for TPM",      \
                        STRINGIFY(priority),    \
                        "libtss2-rc.so.0")
#  define LIBTSS2_MU_NOTE(priority)               \
        SD_ELF_NOTE_DLOPEN_ANCHORED(              \
                        tpm2_mu_##priority,       \
                        "tpm",                    \
                        "Support for TPM",        \
                        STRINGIFY(priority),      \
                        "libtss2-mu.so.0")
#  define LIBTSS2_TCTI_DEVICE_NOTE(priority)            \
        SD_ELF_NOTE_DLOPEN_ANCHORED(                    \
                        tpm2_tcti_device_##priority,    \
                        "tpm",                          \
                        "Support for TPM",              \
                        STRINGIFY(priority),            \
                        "libtss2-tcti-device.so.0")
#else
#  define LIBTSS2_ESYS_NOTE(priority)
#  define LIBTSS2_RC_NOTE(priority)
#  define LIBTSS2_MU_NOTE(priority)
#  define LIBTSS2_TCTI_DEVICE_NOTE(priority)
#endif

#if HAVE_XKBCOMMON
#  define LIBXKBCOMMON_NOTE(priority)                                   \
        ELF_NOTE_DLOPEN_ANCHORED(                                       \
                        xkbcommon,                                      \
                        "Support for keyboard locale descriptions",     \
                        priority,                                       \
                        "libxkbcommon.so.0")
#else
#  define LIBXKBCOMMON_NOTE(priority)
#endif

#if HAVE_LIBARCHIVE
#  define ARCHIVE_NOTE(priority)                \
        COMPRESS_NOTE(priority);                \
        LIBACL_NOTE(priority);                  \
        LIBARCHIVE_NOTE(priority)
#else
#  define ARCHIVE_NOTE(priority)                \
        COMPRESS_NOTE(priority)
#endif

#define PASSWORD_NOTE(priority)                 \
        LIBPASSWDQC_NOTE(priority);             \
        LIBPWQUALITY_NOTE(priority)

#define TPM2_NOTE(priority)                                             \
        LIBTSS2_ESYS_NOTE(priority);                                    \
        LIBTSS2_RC_NOTE(priority);                                      \
        LIBTSS2_MU_NOTE(priority);                                      \
        LIBTSS2_TCTI_DEVICE_NOTE(priority)
