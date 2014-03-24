/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#ifdef HAVE_PAM
#define _PAM_FEATURE_ "+PAM"
#else
#define _PAM_FEATURE_ "-PAM"
#endif

#ifdef HAVE_AUDIT
#define _AUDIT_FEATURE_ "+AUDIT"
#else
#define _AUDIT_FEATURE_ "-AUDIT"
#endif

#ifdef HAVE_SELINUX
#define _SELINUX_FEATURE_ "+SELINUX"
#else
#define _SELINUX_FEATURE_ "-SELINUX"
#endif

#ifdef HAVE_APPARMOR
#define _APPARMOR_FEATURE_ "+APPARMOR"
#else
#define _APPARMOR_FEATURE_ "-APPARMOR"
#endif

#ifdef HAVE_IMA
#define _IMA_FEATURE_ "+IMA"
#else
#define _IMA_FEATURE_ "-IMA"
#endif

#ifdef HAVE_SYSV_COMPAT
#define _SYSVINIT_FEATURE_ "+SYSVINIT"
#else
#define _SYSVINIT_FEATURE_ "-SYSVINIT"
#endif

#ifdef HAVE_LIBCRYPTSETUP
#define _LIBCRYPTSETUP_FEATURE_ "+LIBCRYPTSETUP"
#else
#define _LIBCRYPTSETUP_FEATURE_ "-LIBCRYPTSETUP"
#endif

#ifdef HAVE_GCRYPT
#define _GCRYPT_FEATURE_ "+GCRYPT"
#else
#define _GCRYPT_FEATURE_ "-GCRYPT"
#endif

#ifdef HAVE_ACL
#define _ACL_FEATURE_ "+ACL"
#else
#define _ACL_FEATURE_ "-ACL"
#endif

#ifdef HAVE_XZ
#define _XZ_FEATURE_ "+XZ"
#else
#define _XZ_FEATURE_ "-XZ"
#endif

#ifdef HAVE_SECCOMP
#define _SECCOMP_FEATURE_ "+SECCOMP"
#else
#define _SECCOMP_FEATURE_ "-SECCOMP"
#endif

#define SYSTEMD_FEATURES _PAM_FEATURE_ " " _AUDIT_FEATURE_ " " _SELINUX_FEATURE_ " " _IMA_FEATURE_ " " _SYSVINIT_FEATURE_ " " _LIBCRYPTSETUP_FEATURE_ " " _GCRYPT_FEATURE_ " " _ACL_FEATURE_ " " _XZ_FEATURE_ " " _SECCOMP_FEATURE_ " " _APPARMOR_FEATURE_
