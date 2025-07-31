/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <gshadow.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "format-util.h"
#include "group-record.h"
#include "libcrypt-util.h"
#include "log.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "user-record.h"
#include "user-record-nss.h"
#include "user-util.h"
#include "utf8.h"

#define SET_IF(field, condition, value, fallback)  \
        field = (condition) ? (value) : (fallback)

static const char* utf8_only(const char *s) {
        return s && utf8_is_valid(s) ? s : NULL;
}

static int strv_extend_strv_utf8_only(char ***dst, char **src, bool filter_duplicates) {
        _cleanup_free_ char **t = NULL;
        size_t l, j = 0;

        /* First, do a shallow copy of s, filtering for only valid utf-8 strings */
        l = strv_length(src);
        t = new(char*, l + 1);
        if (!t)
                return -ENOMEM;

        for (size_t i = 0; i < l; i++)
                if (utf8_is_valid(src[i]))
                        t[j++] = src[i];
        if (j == 0)
                return 0;

        t[j] = NULL;
        return strv_extend_strv(dst, t, filter_duplicates);
}

int nss_passwd_to_user_record(
                const struct passwd *pwd,
                const struct spwd *spwd,
                UserRecord **ret) {

        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        int r;

        assert(pwd);

        if (isempty(pwd->pw_name))
                return -EINVAL;

        if (spwd && !streq_ptr(spwd->sp_namp, pwd->pw_name))
                return -EINVAL;

        hr = user_record_new();
        if (!hr)
                return -ENOMEM;

        r = free_and_strdup(&hr->user_name, pwd->pw_name);
        if (r < 0)
                return r;

        /* Some bad NSS modules synthesize GECOS fields with embedded ":" or "\n" characters, which are not
         * something we can output in /etc/passwd compatible format, since these are record separators
         * there. We normally refuse that, but we need to maintain compatibility with arbitrary NSS modules,
         * hence let's do what glibc does: mangle the data to fit the format. */
        if (isempty(pwd->pw_gecos) || streq_ptr(pwd->pw_gecos, hr->user_name))
                hr->real_name = mfree(hr->real_name);
        else if (valid_gecos(pwd->pw_gecos)) {
                r = free_and_strdup(&hr->real_name, pwd->pw_gecos);
                if (r < 0)
                        return r;
        } else {
                _cleanup_free_ char *mangled = NULL;

                mangled = mangle_gecos(pwd->pw_gecos);
                if (!mangled)
                        return -ENOMEM;

                free_and_replace(hr->real_name, mangled);
        }

        r = free_and_strdup(&hr->home_directory, utf8_only(empty_to_null(pwd->pw_dir)));
        if (r < 0)
                return r;

        r = free_and_strdup(&hr->shell, utf8_only(empty_to_null(pwd->pw_shell)));
        if (r < 0)
                return r;

        hr->uid = pwd->pw_uid;
        hr->gid = pwd->pw_gid;

        if (spwd &&
            looks_like_hashed_password(utf8_only(spwd->sp_pwdp))) { /* Ignore locked, disabled, and mojibake passwords */
                strv_free_erase(hr->hashed_password);
                hr->hashed_password = strv_new(spwd->sp_pwdp);
                if (!hr->hashed_password)
                        return -ENOMEM;
        } else
                hr->hashed_password = strv_free_erase(hr->hashed_password);

        /* shadow-utils suggests using "chage -E 0" (or -E 1, depending on which man page you check)
         * for locking a whole account, hence check for that. Note that it also defines a way to lock
         * just a password instead of the whole account, but that's mostly pointless in times of
         * password-less authorization, hence let's not bother. */

        SET_IF(hr->locked,
               spwd && spwd->sp_expire >= 0,
               spwd->sp_expire <= 1, -1);

        SET_IF(hr->not_after_usec,
               spwd && spwd->sp_expire > 1 && (uint64_t) spwd->sp_expire < (UINT64_MAX-1)/USEC_PER_DAY,
               spwd->sp_expire * USEC_PER_DAY, UINT64_MAX);

        SET_IF(hr->password_change_now,
               spwd && spwd->sp_lstchg >= 0,
               spwd->sp_lstchg == 0, -1);

        SET_IF(hr->last_password_change_usec,
               spwd && spwd->sp_lstchg > 0 && (uint64_t) spwd->sp_lstchg <= (UINT64_MAX-1)/USEC_PER_DAY,
               spwd->sp_lstchg * USEC_PER_DAY, UINT64_MAX);

        SET_IF(hr->password_change_min_usec,
               spwd && spwd->sp_min > 0 && (uint64_t) spwd->sp_min <= (UINT64_MAX-1)/USEC_PER_DAY,
               spwd->sp_min * USEC_PER_DAY, UINT64_MAX);

        SET_IF(hr->password_change_max_usec,
               spwd && spwd->sp_max > 0 && (uint64_t) spwd->sp_max <= (UINT64_MAX-1)/USEC_PER_DAY,
               spwd->sp_max * USEC_PER_DAY, UINT64_MAX);

        SET_IF(hr->password_change_warn_usec,
               spwd && spwd->sp_warn > 0 && (uint64_t) spwd->sp_warn <= (UINT64_MAX-1)/USEC_PER_DAY,
               spwd->sp_warn * USEC_PER_DAY, UINT64_MAX);

        SET_IF(hr->password_change_inactive_usec,
               spwd && spwd->sp_inact > 0 && (uint64_t) spwd->sp_inact <= (UINT64_MAX-1)/USEC_PER_DAY,
               spwd->sp_inact * USEC_PER_DAY, UINT64_MAX);

        hr->json = sd_json_variant_unref(hr->json);
        r = sd_json_buildo(
                        &hr->json,
                        SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(hr->user_name)),
                        SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(hr->uid)),
                        SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(user_record_gid(hr))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!hr->real_name, "realName", SD_JSON_BUILD_STRING(hr->real_name)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!hr->home_directory, "homeDirectory", SD_JSON_BUILD_STRING(hr->home_directory)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!hr->shell, "shell", SD_JSON_BUILD_STRING(hr->shell)),
                        SD_JSON_BUILD_PAIR_CONDITION(!strv_isempty(hr->hashed_password), "privileged", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("hashedPassword", SD_JSON_BUILD_STRV(hr->hashed_password)))),
                        SD_JSON_BUILD_PAIR_CONDITION(hr->locked >= 0, "locked", SD_JSON_BUILD_BOOLEAN(hr->locked)),
                        SD_JSON_BUILD_PAIR_CONDITION(hr->not_after_usec != UINT64_MAX, "notAfterUSec", SD_JSON_BUILD_UNSIGNED(hr->not_after_usec)),
                        SD_JSON_BUILD_PAIR_CONDITION(hr->password_change_now >= 0, "passwordChangeNow", SD_JSON_BUILD_BOOLEAN(hr->password_change_now)),
                        SD_JSON_BUILD_PAIR_CONDITION(hr->last_password_change_usec != UINT64_MAX, "lastPasswordChangeUSec", SD_JSON_BUILD_UNSIGNED(hr->last_password_change_usec)),
                        SD_JSON_BUILD_PAIR_CONDITION(hr->password_change_min_usec != UINT64_MAX, "passwordChangeMinUSec", SD_JSON_BUILD_UNSIGNED(hr->password_change_min_usec)),
                        SD_JSON_BUILD_PAIR_CONDITION(hr->password_change_max_usec != UINT64_MAX, "passwordChangeMaxUSec", SD_JSON_BUILD_UNSIGNED(hr->password_change_max_usec)),
                        SD_JSON_BUILD_PAIR_CONDITION(hr->password_change_warn_usec != UINT64_MAX, "passwordChangeWarnUSec", SD_JSON_BUILD_UNSIGNED(hr->password_change_warn_usec)),
                        SD_JSON_BUILD_PAIR_CONDITION(hr->password_change_inactive_usec != UINT64_MAX, "passwordChangeInactiveUSec", SD_JSON_BUILD_UNSIGNED(hr->password_change_inactive_usec)));
        if (r < 0)
                return r;

        hr->mask = USER_RECORD_REGULAR |
                (!strv_isempty(hr->hashed_password) ? USER_RECORD_PRIVILEGED : 0);

        if (ret)
                *ret = TAKE_PTR(hr);
        return 0;
}

int nss_spwd_for_passwd(const struct passwd *pwd, struct spwd *ret_spwd, char **ret_buffer) {
        size_t buflen = 4096;
        int r;

        assert(pwd);
        assert(ret_spwd);
        assert(ret_buffer);

        for (;;) {
                _cleanup_free_ char *buf = NULL;
                struct spwd spwd = {}, *result = NULL;

                buf = malloc0(buflen);
                if (!buf)
                        return -ENOMEM;

                r = getspnam_r(pwd->pw_name, &spwd, buf, buflen, &result);
                if (r == 0) {
                        if (!result)
                                return -ESRCH;

                        *ret_spwd = *result;
                        *ret_buffer = TAKE_PTR(buf);
                        return 0;
                }
                if (r < 0)
                        return -EIO; /* Weird, this should not return negative! */
                if (r != ERANGE)
                        return -r;

                if (buflen > SIZE_MAX / 2)
                        return -ERANGE;

                buflen *= 2;
                buf = mfree(buf);
        }
}

int nss_user_record_by_name(
                const char *name,
                bool with_shadow,
                UserRecord **ret) {

        _cleanup_free_ char *sbuf = NULL;
        _cleanup_free_ struct passwd *result = NULL;
        bool incomplete = false;
        struct spwd spwd, *sresult = NULL;
        int r;

        assert(name);

        r = getpwnam_malloc(name, &result);
        if (r < 0)
                return r;

        if (with_shadow) {
                r = nss_spwd_for_passwd(result, &spwd, &sbuf);
                if (r < 0) {
                        log_debug_errno(r, "Failed to do shadow lookup for user %s, ignoring: %m", name);
                        incomplete = ERRNO_IS_PRIVILEGE(r);
                } else
                        sresult = &spwd;
        } else
                incomplete = true;

        r = nss_passwd_to_user_record(result, sresult, ret);
        if (r < 0)
                return r;

        if (ret)
                (*ret)->incomplete = incomplete;
        return 0;
}

int nss_user_record_by_uid(
                uid_t uid,
                bool with_shadow,
                UserRecord **ret) {

        _cleanup_free_ char *sbuf = NULL;
        _cleanup_free_ struct passwd *result = NULL;
        bool incomplete = false;
        struct spwd spwd, *sresult = NULL;
        int r;

        r = getpwuid_malloc(uid, &result);
        if (r < 0)
                return r;

        if (with_shadow)  {
                r = nss_spwd_for_passwd(result, &spwd, &sbuf);
                if (r < 0) {
                        log_debug_errno(r, "Failed to do shadow lookup for UID " UID_FMT ", ignoring: %m", uid);
                        incomplete = ERRNO_IS_PRIVILEGE(r);
                } else
                        sresult = &spwd;
        } else
                incomplete = true;

        r = nss_passwd_to_user_record(result, sresult, ret);
        if (r < 0)
                return r;

        if (ret)
                (*ret)->incomplete = incomplete;
        return 0;
}

int nss_group_to_group_record(
                const struct group *grp,
                const struct sgrp *sgrp,
                GroupRecord **ret) {

        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;
        int r;

        assert(grp);

        if (isempty(grp->gr_name))
                return -EINVAL;

        if (sgrp && !streq_ptr(sgrp->sg_namp, grp->gr_name))
                return -EINVAL;

        g = group_record_new();
        if (!g)
                return -ENOMEM;

        g->group_name = strdup(grp->gr_name);
        if (!g->group_name)
                return -ENOMEM;

        r = strv_extend_strv_utf8_only(&g->members, grp->gr_mem, false);
        if (r < 0)
                return r;

        g->gid = grp->gr_gid;

        if (sgrp) {
                if (looks_like_hashed_password(utf8_only(sgrp->sg_passwd))) {
                        g->hashed_password = strv_new(sgrp->sg_passwd);
                        if (!g->hashed_password)
                                return -ENOMEM;
                }

                r = strv_extend_strv_utf8_only(&g->members, sgrp->sg_mem, true);
                if (r < 0)
                        return r;

                r = strv_extend_strv_utf8_only(&g->administrators, sgrp->sg_adm, false);
                if (r < 0)
                        return r;
        }

        r = sd_json_buildo(
                        &g->json,
                        SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(g->group_name)),
                        SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(g->gid)),
                        SD_JSON_BUILD_PAIR_CONDITION(!strv_isempty(g->members), "members", SD_JSON_BUILD_STRV(g->members)),
                        SD_JSON_BUILD_PAIR_CONDITION(!strv_isempty(g->hashed_password), "privileged", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("hashedPassword", SD_JSON_BUILD_STRV(g->hashed_password)))),
                        SD_JSON_BUILD_PAIR_CONDITION(!strv_isempty(g->administrators), "administrators", SD_JSON_BUILD_STRV(g->administrators)));
        if (r < 0)
                return r;

        g->mask = USER_RECORD_REGULAR |
                (!strv_isempty(g->hashed_password) ? USER_RECORD_PRIVILEGED : 0);

        if (ret)
                *ret = TAKE_PTR(g);
        return 0;
}

int nss_sgrp_for_group(const struct group *grp, struct sgrp *ret_sgrp, char **ret_buffer) {
        size_t buflen = 4096;
        int r;

        assert(grp);
        assert(ret_sgrp);
        assert(ret_buffer);

        for (;;) {
                _cleanup_free_ char *buf = NULL;
                struct sgrp sgrp = {}, *result = NULL;

                buf = malloc0(buflen);
                if (!buf)
                        return -ENOMEM;

                r = getsgnam_r(grp->gr_name, &sgrp, buf, buflen, &result);
                if (r == 0) {
                        if (!result)
                                return -ESRCH;

                        *ret_sgrp = *result;
                        *ret_buffer = TAKE_PTR(buf);
                        return 0;
                }
                if (r < 0)
                        return -EIO; /* Weird, this should not return negative! */
                if (r != ERANGE)
                        return -r;

                if (buflen > SIZE_MAX / 2)
                        return -ERANGE;

                buflen *= 2;
                buf = mfree(buf);
        }
}

int nss_group_record_by_name(
                const char *name,
                bool with_shadow,
                GroupRecord **ret) {

        _cleanup_free_ char *sbuf = NULL;
        _cleanup_free_ struct group *result = NULL;
        bool incomplete = false;
        struct sgrp sgrp, *sresult = NULL;
        int r;

        assert(name);

        r = getgrnam_malloc(name, &result);
        if (r < 0)
                return r;

        if (with_shadow) {
                r = nss_sgrp_for_group(result, &sgrp, &sbuf);
                if (r < 0) {
                        log_debug_errno(r, "Failed to do shadow lookup for group %s, ignoring: %m", result->gr_name);
                        incomplete = ERRNO_IS_PRIVILEGE(r);
                } else
                        sresult = &sgrp;
        } else
                incomplete = true;

        r = nss_group_to_group_record(result, sresult, ret);
        if (r < 0)
                return r;

        if (ret)
                (*ret)->incomplete = incomplete;
        return 0;
}

int nss_group_record_by_gid(
                gid_t gid,
                bool with_shadow,
                GroupRecord **ret) {

        _cleanup_free_ char *sbuf = NULL;
        _cleanup_free_ struct group *result = NULL;
        bool incomplete = false;
        struct sgrp sgrp, *sresult = NULL;
        int r;

        r = getgrgid_malloc(gid, &result);
        if (r < 0)
                return r;

        if (with_shadow) {
                r = nss_sgrp_for_group(result, &sgrp, &sbuf);
                if (r < 0) {
                        log_debug_errno(r, "Failed to do shadow lookup for group %s, ignoring: %m", result->gr_name);
                        incomplete = ERRNO_IS_PRIVILEGE(r);
                } else
                        sresult = &sgrp;
        } else
                incomplete = true;

        r = nss_group_to_group_record(result, sresult, ret);
        if (r < 0)
                return r;

        if (ret)
                (*ret)->incomplete = incomplete;
        return 0;
}
