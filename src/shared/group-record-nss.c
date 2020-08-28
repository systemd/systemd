/* SPDX-License-Identifier: LGPL-2.1+ */

#include "errno-util.h"
#include "group-record-nss.h"
#include "libcrypt-util.h"
#include "strv.h"

int nss_group_to_group_record(
                const struct group *grp,
                const struct sgrp *sgrp,
                GroupRecord **ret) {

        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;
        int r;

        assert(grp);
        assert(ret);

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

        g->members = strv_copy(grp->gr_mem);
        if (!g->members)
                return -ENOMEM;

        g->gid = grp->gr_gid;

        if (sgrp) {
                if (looks_like_hashed_password(sgrp->sg_passwd)) {
                        g->hashed_password = strv_new(sgrp->sg_passwd);
                        if (!g->hashed_password)
                                return -ENOMEM;
                }

                r = strv_extend_strv(&g->members, sgrp->sg_mem, 1);
                if (r < 0)
                        return r;

                g->administrators = strv_copy(sgrp->sg_adm);
                if (!g->administrators)
                        return -ENOMEM;
        }

        r = json_build(&g->json, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(g->group_name)),
                                       JSON_BUILD_PAIR("gid", JSON_BUILD_UNSIGNED(g->gid)),
                                       JSON_BUILD_PAIR_CONDITION(!strv_isempty(g->members), "members", JSON_BUILD_STRV(g->members)),
                                       JSON_BUILD_PAIR_CONDITION(!strv_isempty(g->hashed_password), "privileged", JSON_BUILD_OBJECT(JSON_BUILD_PAIR("hashedPassword", JSON_BUILD_STRV(g->hashed_password)))),
                                       JSON_BUILD_PAIR_CONDITION(!strv_isempty(g->administrators), "administrators", JSON_BUILD_STRV(g->administrators))));
        if (r < 0)
                return r;

        g->mask = USER_RECORD_REGULAR |
                (!strv_isempty(g->hashed_password) ? USER_RECORD_PRIVILEGED : 0);

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
                struct sgrp sgrp, *result;

                buf = malloc(buflen);
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

int nss_group_record_by_name(const char *name, GroupRecord **ret) {
        _cleanup_free_ char *buf = NULL, *sbuf = NULL;
        struct group grp, *result;
        bool incomplete = false;
        size_t buflen = 4096;
        struct sgrp sgrp;
        int r;

        assert(name);
        assert(ret);

        for (;;) {
                buf = malloc(buflen);
                if (!buf)
                        return -ENOMEM;

                r = getgrnam_r(name, &grp, buf, buflen, &result);
                if (r == 0)  {
                        if (!result)
                                return -ESRCH;

                        break;
                }

                if (r < 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "getgrnam_r() returned a negative value");
                if (r != ERANGE)
                        return -r;
                if (buflen > SIZE_MAX / 2)
                        return -ERANGE;

                buflen *= 2;
                buf = mfree(buf);
        }

        r = nss_sgrp_for_group(result, &sgrp, &sbuf);
        if (r < 0) {
                log_debug_errno(r, "Failed to do shadow lookup for group %s, ignoring: %m", result->gr_name);
                incomplete = ERRNO_IS_PRIVILEGE(r);
        }

        r = nss_group_to_group_record(result, r >= 0 ? &sgrp : NULL, ret);
        if (r < 0)
                return r;

        (*ret)->incomplete = incomplete;
        return 0;
}

int nss_group_record_by_gid(gid_t gid, GroupRecord **ret) {
        _cleanup_free_ char *buf = NULL, *sbuf = NULL;
        struct group grp, *result;
        bool incomplete = false;
        size_t buflen = 4096;
        struct sgrp sgrp;
        int r;

        assert(ret);

        for (;;) {
                buf = malloc(buflen);
                if (!buf)
                        return -ENOMEM;

                r = getgrgid_r(gid, &grp, buf, buflen, &result);
                if (r == 0)  {
                        if (!result)
                                return -ESRCH;
                        break;
                }

                if (r < 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "getgrgid_r() returned a negative value");
                if (r != ERANGE)
                        return -r;
                if (buflen > SIZE_MAX / 2)
                        return -ERANGE;

                buflen *= 2;
                buf = mfree(buf);
        }

        r = nss_sgrp_for_group(result, &sgrp, &sbuf);
        if (r < 0) {
                log_debug_errno(r, "Failed to do shadow lookup for group %s, ignoring: %m", result->gr_name);
                incomplete = ERRNO_IS_PRIVILEGE(r);
        }

        r = nss_group_to_group_record(result, r >= 0 ? &sgrp : NULL, ret);
        if (r < 0)
                return r;

        (*ret)->incomplete = incomplete;
        return 0;
}
