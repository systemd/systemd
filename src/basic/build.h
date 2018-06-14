/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#if HAVE_PAM
#define _PAM_FEATURE_ "+PAM"
#else
#define _PAM_FEATURE_ "-PAM"
#endif

#if HAVE_AUDIT
#define _AUDIT_FEATURE_ "+AUDIT"
#else
#define _AUDIT_FEATURE_ "-AUDIT"
#endif

#if HAVE_SELINUX
#define _SELINUX_FEATURE_ "+SELINUX"
#else
#define _SELINUX_FEATURE_ "-SELINUX"
#endif

#if HAVE_APPARMOR
#define _APPARMOR_FEATURE_ "+APPARMOR"
#else
#define _APPARMOR_FEATURE_ "-APPARMOR"
#endif

#if ENABLE_IMA
#define _IMA_FEATURE_ "+IMA"
#else
#define _IMA_FEATURE_ "-IMA"
#endif

#if ENABLE_SMACK
#define _SMACK_FEATURE_ "+SMACK"
#else
#define _SMACK_FEATURE_ "-SMACK"
#endif

#if HAVE_SYSV_COMPAT
#define _SYSVINIT_FEATURE_ "+SYSVINIT"
#else
#define _SYSVINIT_FEATURE_ "-SYSVINIT"
#endif

#if ENABLE_UTMP
#define _UTMP_FEATURE_ "+UTMP"
#else
#define _UTMP_FEATURE_ "-UTMP"
#endif

#if HAVE_LIBCRYPTSETUP
#define _LIBCRYPTSETUP_FEATURE_ "+LIBCRYPTSETUP"
#else
#define _LIBCRYPTSETUP_FEATURE_ "-LIBCRYPTSETUP"
#endif

#if HAVE_GCRYPT
#define _GCRYPT_FEATURE_ "+GCRYPT"
#else
#define _GCRYPT_FEATURE_ "-GCRYPT"
#endif

#if HAVE_GNUTLS
#define _GNUTLS_FEATURE_ "+GNUTLS"
#else
#define _GNUTLS_FEATURE_ "-GNUTLS"
#endif

#if HAVE_ACL
#define _ACL_FEATURE_ "+ACL"
#else
#define _ACL_FEATURE_ "-ACL"
#endif

#if HAVE_XZ
#define _XZ_FEATURE_ "+XZ"
#else
#define _XZ_FEATURE_ "-XZ"
#endif

#if HAVE_LZ4
#define _LZ4_FEATURE_ "+LZ4"
#else
#define _LZ4_FEATURE_ "-LZ4"
#endif

#if HAVE_SECCOMP
#define _SECCOMP_FEATURE_ "+SECCOMP"
#else
#define _SECCOMP_FEATURE_ "-SECCOMP"
#endif

#if HAVE_BLKID
#define _BLKID_FEATURE_ "+BLKID"
#else
#define _BLKID_FEATURE_ "-BLKID"
#endif

#if HAVE_ELFUTILS
#define _ELFUTILS_FEATURE_ "+ELFUTILS"
#else
#define _ELFUTILS_FEATURE_ "-ELFUTILS"
#endif

#if HAVE_KMOD
#define _KMOD_FEATURE_ "+KMOD"
#else
#define _KMOD_FEATURE_ "-KMOD"
#endif

#if HAVE_LIBIDN2
#define _IDN2_FEATURE_ "+IDN2"
#else
#define _IDN2_FEATURE_ "-IDN2"
#endif

#if HAVE_LIBIDN
#define _IDN_FEATURE_ "+IDN"
#else
#define _IDN_FEATURE_ "-IDN"
#endif

#if HAVE_PCRE2
#define _PCRE2_FEATURE_ "+PCRE2"
#else
#define _PCRE2_FEATURE_ "-PCRE2"
#endif

#define _CGROUP_HIEARCHY_ "default-hierarchy=" DEFAULT_HIERARCHY_NAME

#define SYSTEMD_FEATURES                                                \
        _PAM_FEATURE_ " "                                               \
        _AUDIT_FEATURE_ " "                                             \
        _SELINUX_FEATURE_ " "                                           \
        _IMA_FEATURE_ " "                                               \
        _APPARMOR_FEATURE_ " "                                          \
        _SMACK_FEATURE_ " "                                             \
        _SYSVINIT_FEATURE_ " "                                          \
        _UTMP_FEATURE_ " "                                              \
        _LIBCRYPTSETUP_FEATURE_ " "                                     \
        _GCRYPT_FEATURE_ " "                                            \
        _GNUTLS_FEATURE_ " "                                            \
        _ACL_FEATURE_ " "                                               \
        _XZ_FEATURE_ " "                                                \
        _LZ4_FEATURE_ " "                                               \
        _SECCOMP_FEATURE_ " "                                           \
        _BLKID_FEATURE_ " "                                             \
        _ELFUTILS_FEATURE_ " "                                          \
        _KMOD_FEATURE_ " "                                              \
        _IDN2_FEATURE_ " "                                              \
        _IDN_FEATURE_ " "                                               \
        _PCRE2_FEATURE_ " "                                             \
        _CGROUP_HIEARCHY_
