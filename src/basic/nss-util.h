/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <grp.h>
#include <netdb.h>
#include <nss.h>
#include <pwd.h>
#include <resolv.h>

#define NSS_SIGNALS_BLOCK SIGALRM,SIGVTALRM,SIGPIPE,SIGCHLD,SIGTSTP,SIGIO,SIGHUP,SIGUSR1,SIGUSR2,SIGPROF,SIGURG,SIGWINCH

#ifndef DEPRECATED_RES_USE_INET6
#  define DEPRECATED_RES_USE_INET6 0x00002000
#endif

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
        if (_res.options & DEPRECATED_RES_USE_INET6)    \
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
}

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
}

#define NSS_GETPW_PROTOTYPES(module)                    \
enum nss_status _nss_##module##_getpwnam_r(             \
                const char *name,                       \
                struct passwd *pwd,                     \
                char *buffer, size_t buflen,            \
                int *errnop) _public_;                  \
enum nss_status _nss_##module##_getpwuid_r(             \
                uid_t uid,                              \
                struct passwd *pwd,                     \
                char *buffer, size_t buflen,            \
                int *errnop) _public_

#define NSS_GETSP_PROTOTYPES(module)                    \
enum nss_status _nss_##module##_getspnam_r(             \
                const char *name,                       \
                struct spwd *spwd,                      \
                char *buffer, size_t buflen,            \
                int *errnop) _public_

#define NSS_GETSG_PROTOTYPES(module)                    \
enum nss_status _nss_##module##_getsgnam_r(             \
                const char *name,                       \
                struct sgrp *sgrp,                      \
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

#define NSS_PWENT_PROTOTYPES(module)                    \
enum nss_status _nss_##module##_endpwent(               \
                void) _public_;                         \
enum nss_status _nss_##module##_setpwent(               \
                int stayopen) _public_;                 \
enum nss_status _nss_##module##_getpwent_r(             \
                struct passwd *result,                  \
                char *buffer,                           \
                size_t buflen,                          \
                int *errnop) _public_;

#define NSS_SPENT_PROTOTYPES(module)                    \
enum nss_status _nss_##module##_endspent(               \
                void) _public_;                         \
enum nss_status _nss_##module##_setspent(               \
                int stayopen) _public_;                 \
enum nss_status _nss_##module##_getspent_r(             \
                struct spwd *spwd,                      \
                char *buffer,                           \
                size_t buflen,                          \
                int *errnop) _public_;

#define NSS_GRENT_PROTOTYPES(module)                    \
enum nss_status _nss_##module##_endgrent(               \
                void) _public_;                         \
enum nss_status _nss_##module##_setgrent(               \
                int stayopen) _public_;                 \
enum nss_status _nss_##module##_getgrent_r(             \
                struct group *result,                   \
                char *buffer,                           \
                size_t buflen,                          \
                int *errnop) _public_;

#define NSS_SGENT_PROTOTYPES(module)                    \
enum nss_status _nss_##module##_endsgent(               \
                void) _public_;                         \
enum nss_status _nss_##module##_setsgent(               \
                int stayopen) _public_;                 \
enum nss_status _nss_##module##_getsgent_r(             \
                struct sgrp *sgrp,                      \
                char *buffer,                           \
                size_t buflen,                          \
                int *errnop) _public_;

#define NSS_INITGROUPS_PROTOTYPE(module)                \
enum nss_status _nss_##module##_initgroups_dyn(         \
                const char *user,                       \
                gid_t group,                            \
                long int *start,                        \
                long int *size,                         \
                gid_t **groupsp,                        \
                long int limit,                         \
                int *errnop) _public_;

typedef enum nss_status (*_nss_gethostbyname4_r_t)(
                const char *name,
                struct gaih_addrtuple **pat,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp);

typedef enum nss_status (*_nss_gethostbyname3_r_t)(
                const char *name,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp);

typedef enum nss_status (*_nss_gethostbyname2_r_t)(
                const char *name,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop);

typedef enum nss_status (*_nss_gethostbyname_r_t)(
                const char *name,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop);

typedef enum nss_status (*_nss_gethostbyaddr2_r_t)(
                const void* addr, socklen_t len,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp);
typedef enum nss_status (*_nss_gethostbyaddr_r_t)(
                const void* addr, socklen_t len,
                int af,
                struct hostent *host,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop);

typedef enum nss_status (*_nss_getpwnam_r_t)(
                const char *name,
                struct passwd *pwd,
                char *buffer, size_t buflen,
                int *errnop);
typedef enum nss_status (*_nss_getpwuid_r_t)(
                uid_t uid,
                struct passwd *pwd,
                char *buffer, size_t buflen,
                int *errnop);

typedef enum nss_status (*_nss_getgrnam_r_t)(
                const char *name,
                struct group *gr,
                char *buffer, size_t buflen,
                int *errnop);
typedef enum nss_status (*_nss_getgrgid_r_t)(
                gid_t gid,
                struct group *gr,
                char *buffer, size_t buflen,
                int *errnop);
