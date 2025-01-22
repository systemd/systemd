/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <nss.h>
#include <pthread.h>
#include <string.h>

#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "macro.h"
#include "missing_threads.h"
#include "nss-systemd.h"
#include "nss-util.h"
#include "pthread-util.h"
#include "signal-util.h"
#include "strv.h"
#include "user-record-nss.h"
#include "user-util.h"
#include "userdb-glue.h"
#include "userdb.h"

static const struct passwd root_passwd = {
        .pw_name = (char*) "root",
        .pw_passwd = (char*) PASSWORD_SEE_SHADOW,
        .pw_uid = 0,
        .pw_gid = 0,
        .pw_gecos = (char*) "Super User",
        .pw_dir = (char*) "/root",
        .pw_shell = NULL,
};

static const struct spwd root_spwd = {
        .sp_namp = (char*) "root",
        .sp_pwdp = (char*) PASSWORD_LOCKED_AND_INVALID,
        .sp_lstchg = -1,
        .sp_min = -1,
        .sp_max = -1,
        .sp_warn = -1,
        .sp_inact = -1,
        .sp_expire = -1,
        .sp_flag = ULONG_MAX, /* this appears to be what everybody does ... */
};

static const struct passwd nobody_passwd = {
        .pw_name = (char*) NOBODY_USER_NAME,
        .pw_passwd = (char*) PASSWORD_LOCKED_AND_INVALID,
        .pw_uid = UID_NOBODY,
        .pw_gid = GID_NOBODY,
        .pw_gecos = (char*) "Kernel Overflow User",
        .pw_dir = (char*) "/",
        .pw_shell = (char*) NOLOGIN,
};

static const struct spwd nobody_spwd = {
        .sp_namp = (char*) NOBODY_USER_NAME,
        .sp_pwdp = (char*) PASSWORD_LOCKED_AND_INVALID,
        .sp_lstchg = -1,
        .sp_min = -1,
        .sp_max = -1,
        .sp_warn = -1,
        .sp_inact = -1,
        .sp_expire = -1,
        .sp_flag = ULONG_MAX, /* this appears to be what everybody does ... */
};

static const struct group root_group = {
        .gr_name = (char*) "root",
        .gr_gid = 0,
        .gr_passwd = (char*) PASSWORD_SEE_SHADOW,
        .gr_mem = (char*[]) { NULL },
};

static const struct sgrp root_sgrp = {
        .sg_namp = (char*) "root",
        .sg_passwd = (char*) PASSWORD_LOCKED_AND_INVALID,
};

static const struct group nobody_group = {
        .gr_name = (char*) NOBODY_GROUP_NAME,
        .gr_gid = GID_NOBODY,
        .gr_passwd = (char*) PASSWORD_LOCKED_AND_INVALID,
        .gr_mem = (char*[]) { NULL },
};

static const struct sgrp nobody_sgrp = {
        .sg_namp = (char*) NOBODY_GROUP_NAME,
        .sg_passwd = (char*) PASSWORD_LOCKED_AND_INVALID,
};

typedef struct GetentData {
        /* As explained in NOTES section of getpwent_r(3) as 'getpwent_r() is not really reentrant since it
         * shares the reading position in the stream with all other threads', we need to protect the data in
         * UserDBIterator from multithreaded programs which may call setpwent(), getpwent_r(), or endpwent()
         * simultaneously. So, each function locks the data by using the mutex below. */
        pthread_mutex_t mutex;
        UserDBIterator *iterator;

        /* Applies to group iterations only: true while we iterate over groups defined through NSS, false
         * otherwise. */
        bool by_membership;
} GetentData;

/* On current glibc PTHREAD_MUTEX_INITIALIZER is defined in a way incompatible with
 * -Wzero-as-null-pointer-constant, work around this for now. */
DISABLE_WARNING_ZERO_AS_NULL_POINTER_CONSTANT;
static GetentData getpwent_data = {
        .mutex = PTHREAD_MUTEX_INITIALIZER,
};

static GetentData getgrent_data = {
        .mutex = PTHREAD_MUTEX_INITIALIZER,
};

static GetentData getspent_data = {
        .mutex = PTHREAD_MUTEX_INITIALIZER,
};

static GetentData getsgent_data = {
        .mutex = PTHREAD_MUTEX_INITIALIZER,
};
REENABLE_WARNING;

static void setup_logging_once(void) {
        static pthread_once_t once = PTHREAD_ONCE_INIT;
        assert_se(pthread_once(&once, log_parse_environment_variables) == 0);
}

#define NSS_ENTRYPOINT_BEGIN                    \
        BLOCK_SIGNALS(NSS_SIGNALS_BLOCK);       \
        setup_logging_once()

NSS_GETPW_PROTOTYPES(systemd);
NSS_GETSP_PROTOTYPES(systemd);
NSS_GETGR_PROTOTYPES(systemd);
NSS_GETSG_PROTOTYPES(systemd);
NSS_PWENT_PROTOTYPES(systemd);
NSS_SPENT_PROTOTYPES(systemd);
NSS_GRENT_PROTOTYPES(systemd);
NSS_SGENT_PROTOTYPES(systemd);
NSS_INITGROUPS_PROTOTYPE(systemd);

/* Since our NSS functions implement reentrant glibc APIs, we have to guarantee
 * all the string pointers we return point into the buffer provided by the
 * caller, not into our own static memory. */

static enum nss_status copy_synthesized_passwd(
                struct passwd *dest,
                const struct passwd *src,
                const char *fallback_shell,
                char *buffer, size_t buflen,
                int *errnop) {

        assert(dest);
        assert(src);
        assert(src->pw_name);
        assert(src->pw_passwd);
        assert(src->pw_gecos);
        assert(src->pw_dir);

        const char *shell = ASSERT_PTR(src->pw_shell ?: fallback_shell);

        size_t required =
                strlen(src->pw_name) + 1 +
                strlen(src->pw_passwd) + 1 +
                strlen(src->pw_gecos) + 1 +
                strlen(src->pw_dir) + 1 +
                strlen(shell) + 1;

        if (buflen < required) {
                *errnop = ERANGE;
                return NSS_STATUS_TRYAGAIN;
        }

        assert(buffer);

        *dest = *src;

        /* String fields point into the user-provided buffer */
        dest->pw_name = buffer;
        dest->pw_passwd = stpcpy(dest->pw_name, src->pw_name) + 1;
        dest->pw_gecos = stpcpy(dest->pw_passwd, src->pw_passwd) + 1;
        dest->pw_dir = stpcpy(dest->pw_gecos, src->pw_gecos) + 1;
        dest->pw_shell = stpcpy(dest->pw_dir, src->pw_dir) + 1;
        strcpy(dest->pw_shell, shell);

        return NSS_STATUS_SUCCESS;
}

static enum nss_status copy_synthesized_spwd(
                struct spwd *dest,
                const struct spwd *src,
                char *buffer, size_t buflen,
                int *errnop) {

        assert(dest);
        assert(src);
        assert(src->sp_namp);
        assert(src->sp_pwdp);

        size_t required =
                strlen(src->sp_namp) + 1 +
                strlen(src->sp_pwdp) + 1;

        if (buflen < required) {
                *errnop = ERANGE;
                return NSS_STATUS_TRYAGAIN;
        }

        assert(buffer);

        *dest = *src;

        /* String fields point into the user-provided buffer */
        dest->sp_namp = buffer;
        dest->sp_pwdp = stpcpy(dest->sp_namp, src->sp_namp) + 1;
        strcpy(dest->sp_pwdp, src->sp_pwdp);

        return NSS_STATUS_SUCCESS;
}

static enum nss_status copy_synthesized_group(
                struct group *dest,
                const struct group *src,
                char *buffer, size_t buflen,
                int *errnop) {

        assert(dest);
        assert(src);
        assert(src->gr_name);
        assert(src->gr_passwd);
        assert(src->gr_mem);
        assert(!*src->gr_mem); /* Our synthesized records' gr_mem is always just NULL... */

        size_t required =
                strlen(src->gr_name) + 1 +
                strlen(src->gr_passwd) + 1 +
                sizeof(char*); /* ...but that NULL still needs to be stored into the buffer! */

        if (buflen < ALIGN(required)) {
                *errnop = ERANGE;
                return NSS_STATUS_TRYAGAIN;
        }

        assert(buffer);

        *dest = *src;

        /* String fields point into the user-provided buffer */
        dest->gr_name = buffer;
        dest->gr_passwd = stpcpy(dest->gr_name, src->gr_name) + 1;
        dest->gr_mem = ALIGN_PTR(stpcpy(dest->gr_passwd, src->gr_passwd) + 1);
        *dest->gr_mem = NULL;

        return NSS_STATUS_SUCCESS;
}

static enum nss_status copy_synthesized_sgrp(
                struct sgrp *dest,
                const struct sgrp *src,
                char *buffer, size_t buflen,
                int *errnop) {

        assert(dest);
        assert(src);
        assert(src->sg_namp);
        assert(src->sg_passwd);

        size_t required =
                strlen(src->sg_namp) + 1 +
                strlen(src->sg_passwd) + 1;

        if (buflen < required) {
                *errnop = ERANGE;
                return NSS_STATUS_TRYAGAIN;
        }

        assert(buffer);

        *dest = *src;

        /* String fields point into the user-provided buffer */
        dest->sg_namp = buffer;
        dest->sg_passwd = stpcpy(dest->sg_namp, src->sg_namp) + 1;
        strcpy(dest->sg_passwd, src->sg_passwd);

        return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_systemd_getpwnam_r(
                const char *name,
                struct passwd *pwd,
                char *buffer, size_t buflen,
                int *errnop) {

        enum nss_status status;
        int e;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        assert(name);
        assert(pwd);
        assert(errnop);

        /* If the username is not valid, then we don't know it. Ideally libc would filter these for us
         * anyway. We don't generate EINVAL here, because it isn't really out business to complain about
         * invalid user names. */
        if (!valid_user_group_name(name, VALID_USER_RELAX))
                return NSS_STATUS_NOTFOUND;

        /* Synthesize entries for the root and nobody users, in case they are missing in /etc/passwd */
        if (secure_getenv_bool("SYSTEMD_NSS_BYPASS_SYNTHETIC") <= 0) {

                if (streq(name, root_passwd.pw_name))
                        return copy_synthesized_passwd(pwd, &root_passwd,
                                                       default_root_shell(NULL),
                                                       buffer, buflen, errnop);

                if (streq(name, nobody_passwd.pw_name)) {
                        if (!synthesize_nobody())
                                return NSS_STATUS_NOTFOUND;

                        return copy_synthesized_passwd(pwd, &nobody_passwd,
                                                       NULL,
                                                       buffer, buflen, errnop);
                }

        } else if (STR_IN_SET(name, root_passwd.pw_name, nobody_passwd.pw_name))
                return NSS_STATUS_NOTFOUND;

        status = userdb_getpwnam(name, pwd, buffer, buflen, &e);
        if (IN_SET(status, NSS_STATUS_UNAVAIL, NSS_STATUS_TRYAGAIN)) {
                UNPROTECT_ERRNO;
                *errnop = e;
                return status;
        }

        return status;
}

enum nss_status _nss_systemd_getpwuid_r(
                uid_t uid,
                struct passwd *pwd,
                char *buffer, size_t buflen,
                int *errnop) {

        enum nss_status status;
        int e;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        assert(pwd);
        assert(errnop);

        if (!uid_is_valid(uid))
                return NSS_STATUS_NOTFOUND;

        /* Synthesize data for the root user and for nobody in case they are missing from /etc/passwd */
        if (secure_getenv_bool("SYSTEMD_NSS_BYPASS_SYNTHETIC") <= 0) {

                if (uid == root_passwd.pw_uid)
                        return copy_synthesized_passwd(pwd, &root_passwd,
                                                       default_root_shell(NULL),
                                                       buffer, buflen, errnop);

                if (uid == nobody_passwd.pw_uid) {
                        if (!synthesize_nobody())
                                return NSS_STATUS_NOTFOUND;

                        return copy_synthesized_passwd(pwd, &nobody_passwd,
                                                       NULL,
                                                       buffer, buflen, errnop);
                }

        } else if (uid == root_passwd.pw_uid || uid == nobody_passwd.pw_uid)
                return NSS_STATUS_NOTFOUND;

        status = userdb_getpwuid(uid, pwd, buffer, buflen, &e);
        if (IN_SET(status, NSS_STATUS_UNAVAIL, NSS_STATUS_TRYAGAIN)) {
                UNPROTECT_ERRNO;
                *errnop = e;
                return status;
        }

        return status;
}

enum nss_status _nss_systemd_getspnam_r(
                const char *name,
                struct spwd *spwd,
                char *buffer, size_t buflen,
                int *errnop) {

        enum nss_status status;
        int e;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        assert(name);
        assert(spwd);
        assert(errnop);

        if (!valid_user_group_name(name, VALID_USER_RELAX))
                return NSS_STATUS_NOTFOUND;

        /* Synthesize entries for the root and nobody users, in case they are missing in /etc/passwd */
        if (secure_getenv_bool("SYSTEMD_NSS_BYPASS_SYNTHETIC") <= 0) {

                if (streq(name, root_spwd.sp_namp))
                        return copy_synthesized_spwd(spwd, &root_spwd, buffer, buflen, errnop);

                if (streq(name, nobody_spwd.sp_namp)) {
                        if (!synthesize_nobody())
                                return NSS_STATUS_NOTFOUND;

                        return copy_synthesized_spwd(spwd, &nobody_spwd, buffer, buflen, errnop);
                }

        } else if (STR_IN_SET(name, root_spwd.sp_namp, nobody_spwd.sp_namp))
                return NSS_STATUS_NOTFOUND;

        status = userdb_getspnam(name, spwd, buffer, buflen, &e);
        if (IN_SET(status, NSS_STATUS_UNAVAIL, NSS_STATUS_TRYAGAIN)) {
                UNPROTECT_ERRNO;
                *errnop = e;
                return status;
        }

        return status;
}

#pragma GCC diagnostic ignored "-Wsizeof-pointer-memaccess"

enum nss_status _nss_systemd_getgrnam_r(
                const char *name,
                struct group *gr,
                char *buffer, size_t buflen,
                int *errnop) {

        enum nss_status status;
        int e;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        assert(name);
        assert(gr);
        assert(errnop);

        if (!valid_user_group_name(name, VALID_USER_RELAX))
                return NSS_STATUS_NOTFOUND;

        /* Synthesize records for root and nobody, in case they are missing from /etc/group */
        if (secure_getenv_bool("SYSTEMD_NSS_BYPASS_SYNTHETIC") <= 0) {

                if (streq(name, root_group.gr_name))
                        return copy_synthesized_group(gr, &root_group, buffer, buflen, errnop);

                if (streq(name, nobody_group.gr_name)) {
                        if (!synthesize_nobody())
                                return NSS_STATUS_NOTFOUND;

                        return copy_synthesized_group(gr, &nobody_group, buffer, buflen, errnop);
                }

        } else if (STR_IN_SET(name, root_group.gr_name, nobody_group.gr_name))
                return NSS_STATUS_NOTFOUND;

        status = userdb_getgrnam(name, gr, buffer, buflen, &e);
        if (IN_SET(status, NSS_STATUS_UNAVAIL, NSS_STATUS_TRYAGAIN)) {
                UNPROTECT_ERRNO;
                *errnop = e;
                return status;
        }

        return status;
}

enum nss_status _nss_systemd_getgrgid_r(
                gid_t gid,
                struct group *gr,
                char *buffer, size_t buflen,
                int *errnop) {

        enum nss_status status;
        int e;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        assert(gr);
        assert(errnop);

        if (!gid_is_valid(gid))
                return NSS_STATUS_NOTFOUND;

        /* Synthesize records for root and nobody, in case they are missing from /etc/group */
        if (secure_getenv_bool("SYSTEMD_NSS_BYPASS_SYNTHETIC") <= 0) {

                if (gid == root_group.gr_gid)
                        return copy_synthesized_group(gr, &root_group, buffer, buflen, errnop);

                if (gid == nobody_group.gr_gid) {
                        if (!synthesize_nobody())
                                return NSS_STATUS_NOTFOUND;

                        return copy_synthesized_group(gr, &nobody_group, buffer, buflen, errnop);
                }

        } else if (gid == root_group.gr_gid || gid == nobody_group.gr_gid)
                return NSS_STATUS_NOTFOUND;

        status = userdb_getgrgid(gid, gr, buffer, buflen, &e);
        if (IN_SET(status, NSS_STATUS_UNAVAIL, NSS_STATUS_TRYAGAIN)) {
                UNPROTECT_ERRNO;
                *errnop = e;
                return status;
        }

        return status;
}

enum nss_status _nss_systemd_getsgnam_r(
                const char *name,
                struct sgrp *sgrp,
                char *buffer, size_t buflen,
                int *errnop) {

        enum nss_status status;
        int e;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        assert(name);
        assert(sgrp);
        assert(errnop);

        if (!valid_user_group_name(name, VALID_USER_RELAX))
                return NSS_STATUS_NOTFOUND;

        /* Synthesize records for root and nobody, in case they are missing from /etc/group */
        if (secure_getenv_bool("SYSTEMD_NSS_BYPASS_SYNTHETIC") <= 0) {

                if (streq(name, root_sgrp.sg_namp))
                        return copy_synthesized_sgrp(sgrp, &root_sgrp, buffer, buflen, errnop);

                if (streq(name, nobody_sgrp.sg_namp)) {
                        if (!synthesize_nobody())
                                return NSS_STATUS_NOTFOUND;

                        return copy_synthesized_sgrp(sgrp, &nobody_sgrp, buffer, buflen, errnop);
                }

        } else if (STR_IN_SET(name, root_sgrp.sg_namp, nobody_sgrp.sg_namp))
                return NSS_STATUS_NOTFOUND;

        status = userdb_getsgnam(name, sgrp, buffer, buflen, &e);
        if (IN_SET(status, NSS_STATUS_UNAVAIL, NSS_STATUS_TRYAGAIN)) {
                UNPROTECT_ERRNO;
                *errnop = e;
                return status;
        }

        return status;
}

static enum nss_status nss_systemd_endent(GetentData *p) {
        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        assert(p);

        _cleanup_(pthread_mutex_unlock_assertp) pthread_mutex_t *_l = pthread_mutex_lock_assert(&p->mutex);
        (void) _l; /* make llvm shut up about _l not being used. */

        p->iterator = userdb_iterator_free(p->iterator);
        p->by_membership = false;

        return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_systemd_endpwent(void) {
        return nss_systemd_endent(&getpwent_data);
}

enum nss_status _nss_systemd_endspent(void) {
        return nss_systemd_endent(&getspent_data);
}

enum nss_status _nss_systemd_endgrent(void) {
        return nss_systemd_endent(&getgrent_data);
}

enum nss_status _nss_systemd_endsgent(void) {
        return nss_systemd_endent(&getsgent_data);
}

enum nss_status _nss_systemd_setpwent(int stayopen) {
        int r;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        if (_nss_systemd_is_blocked())
                return NSS_STATUS_NOTFOUND;

        _cleanup_(pthread_mutex_unlock_assertp) pthread_mutex_t *_l = pthread_mutex_lock_assert(&getpwent_data.mutex);
        (void) _l; /* make llvm shut up about _l not being used. */

        getpwent_data.iterator = userdb_iterator_free(getpwent_data.iterator);
        getpwent_data.by_membership = false;

        /* Don't synthesize root/nobody when iterating. Let nss-files take care of that. If the two records
         * are missing there, then that's fine, after all getpwent() is known to be possibly incomplete
         * (think: LDAP/NIS type situations), and our synthesizing of root/nobody is a robustness fallback
         * only, which matters for getpwnam()/getpwuid() primarily, which are the main NSS entrypoints to the
         * user database. */
        r = userdb_all(/* match= */ NULL, nss_glue_userdb_flags() | USERDB_DONT_SYNTHESIZE_INTRINSIC | USERDB_DONT_SYNTHESIZE_FOREIGN, &getpwent_data.iterator);
        return r < 0 ? NSS_STATUS_UNAVAIL : NSS_STATUS_SUCCESS;
}

enum nss_status _nss_systemd_setgrent(int stayopen) {
        int r;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        if (_nss_systemd_is_blocked())
                return NSS_STATUS_NOTFOUND;

        _cleanup_(pthread_mutex_unlock_assertp) pthread_mutex_t *_l = pthread_mutex_lock_assert(&getgrent_data.mutex);
        (void) _l; /* make llvm shut up about _l not being used. */

        getgrent_data.iterator = userdb_iterator_free(getgrent_data.iterator);
        getgrent_data.by_membership = false;

        /* See _nss_systemd_setpwent() for an explanation why we use USERDB_DONT_SYNTHESIZE_INTRINSIC here */
        r = groupdb_all(/* match= */ NULL, nss_glue_userdb_flags() | USERDB_DONT_SYNTHESIZE_INTRINSIC | USERDB_DONT_SYNTHESIZE_FOREIGN, &getgrent_data.iterator);
        return r < 0 ? NSS_STATUS_UNAVAIL : NSS_STATUS_SUCCESS;
}

enum nss_status _nss_systemd_setspent(int stayopen) {
        int r;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        if (_nss_systemd_is_blocked())
                return NSS_STATUS_NOTFOUND;

        _cleanup_(pthread_mutex_unlock_assertp) pthread_mutex_t *_l = pthread_mutex_lock_assert(&getspent_data.mutex);
        (void) _l; /* make llvm shut up about _l not being used. */

        getspent_data.iterator = userdb_iterator_free(getspent_data.iterator);
        getspent_data.by_membership = false;

        /* See _nss_systemd_setpwent() for an explanation why we use USERDB_DONT_SYNTHESIZE_INTRINSIC here */
        r = userdb_all(/* match= */ NULL, nss_glue_userdb_flags() | USERDB_DONT_SYNTHESIZE_INTRINSIC | USERDB_DONT_SYNTHESIZE_FOREIGN, &getspent_data.iterator);
        return r < 0 ? NSS_STATUS_UNAVAIL : NSS_STATUS_SUCCESS;
}

enum nss_status _nss_systemd_setsgent(int stayopen) {
        int r;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        if (_nss_systemd_is_blocked())
                return NSS_STATUS_NOTFOUND;

        _cleanup_(pthread_mutex_unlock_assertp) pthread_mutex_t *_l = pthread_mutex_lock_assert(&getsgent_data.mutex);
        (void) _l; /* make llvm shut up about _l not being used. */

        getsgent_data.iterator = userdb_iterator_free(getsgent_data.iterator);
        getsgent_data.by_membership = false;

        /* See _nss_systemd_setpwent() for an explanation why we use USERDB_DONT_SYNTHESIZE here */
        r = groupdb_all(/* match= */ NULL, nss_glue_userdb_flags() | USERDB_DONT_SYNTHESIZE_INTRINSIC | USERDB_DONT_SYNTHESIZE_FOREIGN, &getsgent_data.iterator);
        return r < 0 ? NSS_STATUS_UNAVAIL : NSS_STATUS_SUCCESS;
}

enum nss_status _nss_systemd_getpwent_r(
                struct passwd *result,
                char *buffer, size_t buflen,
                int *errnop) {

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        int r;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        assert(result);
        assert(errnop);

        if (_nss_systemd_is_blocked())
                return NSS_STATUS_NOTFOUND;

        _cleanup_(pthread_mutex_unlock_assertp) pthread_mutex_t *_l = pthread_mutex_lock_assert(&getpwent_data.mutex);
        (void) _l; /* make llvm shut up about _l not being used. */

        if (!getpwent_data.iterator) {
                UNPROTECT_ERRNO;
                *errnop = EHOSTDOWN;
                return NSS_STATUS_UNAVAIL;
        }

        r = userdb_iterator_get(getpwent_data.iterator, /* match= */ NULL, &ur);
        if (r == -ESRCH)
                return NSS_STATUS_NOTFOUND;
        if (r < 0) {
                UNPROTECT_ERRNO;
                *errnop = -r;
                return NSS_STATUS_UNAVAIL;
        }

        r = nss_pack_user_record(ur, result, buffer, buflen);
        if (r < 0) {
                UNPROTECT_ERRNO;
                *errnop = -r;
                return NSS_STATUS_TRYAGAIN;
        }

        return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_systemd_getgrent_r(
                struct group *result,
                char *buffer, size_t buflen,
                int *errnop) {

        _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;
        _cleanup_free_ char **members = NULL;
        int r;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        assert(result);
        assert(errnop);

        if (_nss_systemd_is_blocked())
                return NSS_STATUS_NOTFOUND;

        _cleanup_(pthread_mutex_unlock_assertp) pthread_mutex_t *_l = pthread_mutex_lock_assert(&getgrent_data.mutex);
        (void) _l; /* make llvm shut up about _l not being used. */

        if (!getgrent_data.iterator) {
                UNPROTECT_ERRNO;
                *errnop = EHOSTDOWN;
                return NSS_STATUS_UNAVAIL;
        }

        if (!getgrent_data.by_membership) {
                r = groupdb_iterator_get(getgrent_data.iterator, /* match= */ NULL, &gr);
                if (r == -ESRCH) {
                        /* So we finished iterating native groups now. Let's now continue with iterating
                         * native memberships, and generate additional group entries for any groups
                         * referenced there that are defined in NSS only. This means for those groups there
                         * will be two or more entries generated during iteration, but this is apparently how
                         * this is supposed to work, and what other implementations do too. Clients are
                         * supposed to merge the group records found during iteration automatically. */
                        getgrent_data.iterator = userdb_iterator_free(getgrent_data.iterator);

                        r = membershipdb_all(nss_glue_userdb_flags(), &getgrent_data.iterator);
                        if (r < 0 && r != -ESRCH) {
                                UNPROTECT_ERRNO;
                                *errnop = -r;
                                return NSS_STATUS_UNAVAIL;
                        }

                        getgrent_data.by_membership = true;
                } else if (r < 0) {
                        UNPROTECT_ERRNO;
                        *errnop = -r;
                        return NSS_STATUS_UNAVAIL;
                } else if (!STR_IN_SET(gr->group_name, root_group.gr_name, nobody_group.gr_name)) {
                        r = membershipdb_by_group_strv(gr->group_name, nss_glue_userdb_flags(), &members);
                        if (r < 0 && r != -ESRCH) {
                                UNPROTECT_ERRNO;
                                *errnop = -r;
                                return NSS_STATUS_UNAVAIL;
                        }
                }
        }

        if (getgrent_data.by_membership) {
                _cleanup_(_nss_systemd_unblockp) bool blocked = false;

                if (!getgrent_data.iterator)
                        return NSS_STATUS_NOTFOUND;

                for (;;) {
                        _cleanup_free_ char *user_name = NULL, *group_name = NULL;

                        r = membershipdb_iterator_get(getgrent_data.iterator, &user_name, &group_name);
                        if (r == -ESRCH)
                                return NSS_STATUS_NOTFOUND;
                        if (r < 0) {
                                UNPROTECT_ERRNO;
                                *errnop = -r;
                                return NSS_STATUS_UNAVAIL;
                        }

                        if (STR_IN_SET(user_name, root_passwd.pw_name, nobody_passwd.pw_name))
                                continue;
                        if (STR_IN_SET(group_name, root_group.gr_name, nobody_group.gr_name))
                                continue;

                        /* We are about to recursively call into NSS, let's make sure we disable recursion into our own code. */
                        if (!blocked) {
                                r = _nss_systemd_block(true);
                                if (r < 0) {
                                        UNPROTECT_ERRNO;
                                        *errnop = -r;
                                        return NSS_STATUS_UNAVAIL;
                                }

                                blocked = true;
                        }

                        r = nss_group_record_by_name(group_name, false, &gr);
                        if (r == -ESRCH)
                                continue;
                        if (r < 0) {
                                log_debug_errno(r, "Failed to do NSS check for group '%s', ignoring: %m", group_name);
                                continue;
                        }

                        members = strv_new(user_name);
                        if (!members) {
                                UNPROTECT_ERRNO;
                                *errnop = ENOMEM;
                                return NSS_STATUS_TRYAGAIN;
                        }

                        /* Note that we currently generate one group entry per user that is part of a
                         * group. It's a bit ugly, but equivalent to generating a single entry with a set of
                         * members in them. */
                        break;
                }
        }

        r = nss_pack_group_record(gr, members, result, buffer, buflen);
        if (r < 0) {
                UNPROTECT_ERRNO;
                *errnop = -r;
                return NSS_STATUS_TRYAGAIN;
        }

        return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_systemd_getspent_r(
                struct spwd *result,
                char *buffer, size_t buflen,
                int *errnop) {

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        int r;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        assert(result);
        assert(errnop);

        if (_nss_systemd_is_blocked())
                return NSS_STATUS_NOTFOUND;

        _cleanup_(pthread_mutex_unlock_assertp) pthread_mutex_t *_l = pthread_mutex_lock_assert(&getspent_data.mutex);
        (void) _l; /* make llvm shut up about _l not being used. */

        if (!getspent_data.iterator) {
                UNPROTECT_ERRNO;
                *errnop = EHOSTDOWN;
                return NSS_STATUS_UNAVAIL;
        }

        for (;;) {
                r = userdb_iterator_get(getspent_data.iterator, /* match= */ NULL, &ur);
                if (r == -ESRCH)
                        return NSS_STATUS_NOTFOUND;
                if (r < 0) {
                        UNPROTECT_ERRNO;
                        *errnop = -r;
                        return NSS_STATUS_UNAVAIL;
                }

                if (!ur->incomplete) /* don't synthesize shadow records for records where we couldn't read shadow data */
                        break;

                ur = user_record_unref(ur);
        }

        r = nss_pack_user_record_shadow(ur, result, buffer, buflen);
        if (r < 0) {
                UNPROTECT_ERRNO;
                *errnop = -r;
                return NSS_STATUS_TRYAGAIN;
        }

        return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_systemd_getsgent_r(
                struct sgrp *result,
                char *buffer, size_t buflen,
                int *errnop) {

        _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;
        int r;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        assert(result);
        assert(errnop);

        if (_nss_systemd_is_blocked())
                return NSS_STATUS_NOTFOUND;

        _cleanup_(pthread_mutex_unlock_assertp) pthread_mutex_t *_l = pthread_mutex_lock_assert(&getsgent_data.mutex);
        (void) _l; /* make llvm shut up about _l not being used. */

        if (!getsgent_data.iterator) {
                UNPROTECT_ERRNO;
                *errnop = EHOSTDOWN;
                return NSS_STATUS_UNAVAIL;
        }

        for (;;) {
                r = groupdb_iterator_get(getsgent_data.iterator, /* match= */ NULL, &gr);
                if (r == -ESRCH)
                        return NSS_STATUS_NOTFOUND;
                if (r < 0) {
                        UNPROTECT_ERRNO;
                        *errnop = -r;
                        return NSS_STATUS_UNAVAIL;
                }

                if (!gr->incomplete) /* don't synthesize shadow records for records where we couldn't read shadow data */
                        break;

                gr = group_record_unref(gr);
        }

        r = nss_pack_group_record_shadow(gr, result, buffer, buflen);
        if (r < 0) {
                UNPROTECT_ERRNO;
                *errnop = -r;
                return NSS_STATUS_TRYAGAIN;
        }

        return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_systemd_initgroups_dyn(
                const char *user_name,
                gid_t gid,
                long *start,
                long *size,
                gid_t **groupsp,
                long int limit,
                int *errnop) {

        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        bool any = false;
        int r;

        PROTECT_ERRNO;
        NSS_ENTRYPOINT_BEGIN;

        assert(user_name);
        assert(start);
        assert(size);
        assert(groupsp);
        assert(errnop);

        if (!valid_user_group_name(user_name, VALID_USER_RELAX))
                return NSS_STATUS_NOTFOUND;

        /* Don't allow extending these two special users, the same as we won't resolve them via getpwnam() */
        if (STR_IN_SET(user_name, root_passwd.pw_name, nobody_passwd.pw_name))
                return NSS_STATUS_NOTFOUND;

        if (_nss_systemd_is_blocked())
                return NSS_STATUS_NOTFOUND;

        r = membershipdb_by_user(user_name, nss_glue_userdb_flags(), &iterator);
        if (r < 0) {
                UNPROTECT_ERRNO;
                *errnop = -r;
                return NSS_STATUS_UNAVAIL;
        }

        for (;;) {
                _cleanup_(group_record_unrefp) GroupRecord *g = NULL;
                _cleanup_free_ char *group_name = NULL;

                r = membershipdb_iterator_get(iterator, NULL, &group_name);
                if (r == -ESRCH)
                        break;
                if (r < 0) {
                        UNPROTECT_ERRNO;
                        *errnop = -r;
                        return NSS_STATUS_UNAVAIL;
                }

                /* The group might be defined via traditional NSS only, hence let's do a full look-up without
                 * disabling NSS. This means we are operating recursively here. */

                r = groupdb_by_name(group_name, /* match= */ NULL, (nss_glue_userdb_flags() & ~USERDB_EXCLUDE_NSS) | USERDB_SUPPRESS_SHADOW, &g);
                if (r == -ESRCH)
                        continue;
                if (r < 0) {
                        log_debug_errno(r, "Failed to resolve group '%s', ignoring: %m", group_name);
                        continue;
                }

                if (g->gid == gid)
                        continue;

                if (*start >= *size) {
                        gid_t *new_groups;
                        long new_size;

                        if (limit > 0 && *size >= limit) /* Reached the limit.? */
                                break;

                        if (*size > LONG_MAX/2) { /* Check for overflow */
                                UNPROTECT_ERRNO;
                                *errnop = ENOMEM;
                                return NSS_STATUS_TRYAGAIN;
                        }

                        new_size = *start * 2;
                        if (limit > 0 && new_size > limit)
                                new_size = limit;

                        /* Enlarge buffer */
                        new_groups = reallocarray(*groupsp, new_size, sizeof(**groupsp));
                        if (!new_groups) {
                                UNPROTECT_ERRNO;
                                *errnop = ENOMEM;
                                return NSS_STATUS_TRYAGAIN;
                        }

                        *groupsp = new_groups;
                        *size = new_size;
                }

                (*groupsp)[(*start)++] = g->gid;
                any = true;
        }

        return any ? NSS_STATUS_SUCCESS : NSS_STATUS_NOTFOUND;
}

static thread_local unsigned _blocked = 0;

_public_ int _nss_systemd_block(bool b) {

        /* This blocks recursively: it's blocked for as many times this function is called with `true` until
         * it is called an equal time with `false`. */

        if (b) {
                if (_blocked >= UINT_MAX)
                        return -EOVERFLOW;

                _blocked++;
        } else {
                if (_blocked <= 0)
                        return -EOVERFLOW;

                _blocked--;
        }

        return b; /* Return what is passed in, i.e. the new state from the PoV of the caller */
}

_public_ bool _nss_systemd_is_blocked(void) {
        return _blocked > 0;
}
