/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <nss.h>
#include <netdb.h>
#include <resolv.h>
#include <pwd.h>
#include <grp.h>


#define NSS_GETHOSTBYNAME_PROTOTYPES(module)            \
enum nss_status _nss_##module##_gethostbyname4_r(       \
                const char *name,                       \
                struct gaih_addrtuple **pat,            \
                char *buffer, size_t buflen,            \
                int *errnop, int *h_errnop,             \
                int32_t *ttlp) _public_;                \
enum nss_status _nss_##module##_gethostbyname3_r(       \
                const char *name,                       \
                int af,                                 \
                struct hostent *host,                   \
                char *buffer, size_t buflen,            \
                int *errnop, int *h_errnop,             \
                int32_t *ttlp,                          \
                char **canonp) _public_;                \
enum nss_status _nss_##module##_gethostbyname2_r(       \
                const char *name,                       \
                int af,                                 \
                struct hostent *host,                   \
                char *buffer, size_t buflen,            \
                int *errnop, int *h_errnop) _public_;   \
enum nss_status _nss_##module##_gethostbyname_r(        \
                const char *name,                       \
                struct hostent *host,                   \
                char *buffer, size_t buflen,            \
                int *errnop, int *h_errnop) _public_

#define NSS_GETHOSTBYADDR_PROTOTYPES(module)            \
enum nss_status _nss_##module##_gethostbyaddr2_r(       \
                const void* addr, socklen_t len,        \
                int af,                                 \
                struct hostent *host,                   \
                char *buffer, size_t buflen,            \
                int *errnop, int *h_errnop,             \
                int32_t *ttlp) _public_;                \
enum nss_status _nss_##module##_gethostbyaddr_r(        \
                const void* addr, socklen_t len,        \
                int af,                                 \
                struct hostent *host,                   \
                char *buffer, size_t buflen,            \
                int *errnop, int *h_errnop) _public_

#define NSS_GETHOSTBYNAME_FALLBACKS(module)             \
enum nss_status _nss_##module##_gethostbyname2_r(       \
                const char *name,                       \
                int af,                                 \
                struct hostent *host,                   \
                char *buffer, size_t buflen,            \
                int *errnop, int *h_errnop) {           \
        return _nss_##module##_gethostbyname3_r(        \
                        name,                           \
                        af,                             \
                        host,                           \
                        buffer, buflen,                 \
                        errnop, h_errnop,               \
                        NULL,                           \
                        NULL);                          \
}                                                       \
enum nss_status _nss_##module##_gethostbyname_r(        \
                const char *name,                       \
                struct hostent *host,                   \
                char *buffer, size_t buflen,            \
                int *errnop, int *h_errnop) {           \
        enum nss_status ret = NSS_STATUS_NOTFOUND;      \
                                                        \
        if (_res.options & RES_USE_INET6)               \
                ret = _nss_##module##_gethostbyname3_r( \
                        name,                           \
                        AF_INET6,                       \
                        host,                           \
                        buffer, buflen,                 \
                        errnop, h_errnop,               \
                        NULL,                           \
                        NULL);                          \
        if (ret == NSS_STATUS_NOTFOUND)                 \
                ret = _nss_##module##_gethostbyname3_r( \
                        name,                           \
                        AF_INET,                        \
                        host,                           \
                        buffer, buflen,                 \
                        errnop, h_errnop,               \
                        NULL,                           \
                        NULL);                          \
       return ret;                                      \
}                                                       \
struct __useless_struct_to_allow_trailing_semicolon__

#define NSS_GETHOSTBYADDR_FALLBACKS(module)             \
enum nss_status _nss_##module##_gethostbyaddr_r(        \
                const void* addr, socklen_t len,        \
                int af,                                 \
                struct hostent *host,                   \
                char *buffer, size_t buflen,            \
                int *errnop, int *h_errnop) {           \
        return _nss_##module##_gethostbyaddr2_r(        \
                        addr, len,                      \
                        af,                             \
                        host,                           \
                        buffer, buflen,                 \
                        errnop, h_errnop,               \
                        NULL);                          \
}                                                       \
struct __useless_struct_to_allow_trailing_semicolon__

#define NSS_GETPW_PROTOTYPES(module)                    \
enum nss_status _nss_##module##_getpwnam_r(             \
                const char *name,                       \
                struct passwd *pwd,                     \
                char *buffer, size_t buflen,            \
                int *errnop) _public_;                  \
enum nss_status _nss_mymachines_getpwuid_r(             \
                uid_t uid,                              \
                struct passwd *pwd,                     \
                char *buffer, size_t buflen,            \
                int *errnop) _public_

#define NSS_GETGR_PROTOTYPES(module)                    \
enum nss_status _nss_##module##_getgrnam_r(             \
                const char *name,                       \
                struct group *gr,                       \
                char *buffer, size_t buflen,            \
                int *errnop) _public_;                  \
enum nss_status _nss_##module##_getgrgid_r(             \
                gid_t gid,                              \
                struct group *gr,                       \
                char *buffer, size_t buflen,            \
                int *errnop) _public_
