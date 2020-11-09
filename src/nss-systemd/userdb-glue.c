/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "env-util.h"
#include "fd-util.h"
#include "nss-systemd.h"
#include "strv.h"
#include "user-record-nss.h"
#include "user-record.h"
#include "userdb-glue.h"
#include "userdb.h"

UserDBFlags nss_glue_userdb_flags(void) {
        UserDBFlags flags = USERDB_AVOID_NSS;

        /* Make sure that we don't go in circles when allocating a dynamic UID by checking our own database */
        if (getenv_bool_secure("SYSTEMD_NSS_DYNAMIC_BYPASS") > 0)
                flags |= USERDB_AVOID_DYNAMIC_USER;

        return flags;
}

int nss_pack_user_record(
                UserRecord *hr,
                struct passwd *pwd,
                char *buffer,
                size_t buflen) {

        const char *rn, *hd, *shell;
        size_t required;

        assert(hr);
        assert(pwd);

        assert_se(hr->user_name);
        required = strlen(hr->user_name) + 1;

        assert_se(rn = user_record_real_name(hr));
        required += strlen(rn) + 1;

        assert_se(hd = user_record_home_directory(hr));
        required += strlen(hd) + 1;

        assert_se(shell = user_record_shell(hr));
        required += strlen(shell) + 1;

        if (buflen < required)
                return -ERANGE;

        *pwd = (struct passwd) {
                .pw_name = buffer,
                .pw_uid = hr->uid,
                .pw_gid = user_record_gid(hr),
                .pw_passwd = (char*) "x", /* means: see shadow file */
        };

        assert(buffer);

        pwd->pw_gecos = stpcpy(pwd->pw_name, hr->user_name) + 1;
        pwd->pw_dir = stpcpy(pwd->pw_gecos, rn) + 1;
        pwd->pw_shell = stpcpy(pwd->pw_dir, hd) + 1;
        strcpy(pwd->pw_shell, shell);

        return 0;
}

enum nss_status userdb_getpwnam(
                const char *name,
                struct passwd *pwd,
                char *buffer, size_t buflen,
                int *errnop) {

        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        int r;

        assert(pwd);
        assert(errnop);

        if (_nss_systemd_is_blocked())
                return NSS_STATUS_NOTFOUND;

        r = userdb_by_name(name, nss_glue_userdb_flags(), &hr);
        if (r == -ESRCH)
                return NSS_STATUS_NOTFOUND;
        if (r < 0) {
                *errnop = -r;
                return NSS_STATUS_UNAVAIL;
        }

        r = nss_pack_user_record(hr, pwd, buffer, buflen);
        if (r < 0) {
                *errnop = -r;
                return NSS_STATUS_TRYAGAIN;
        }

        return NSS_STATUS_SUCCESS;
}

enum nss_status userdb_getpwuid(
                uid_t uid,
                struct passwd *pwd,
                char *buffer,
                size_t buflen,
                int *errnop) {

        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        int r;

        assert(pwd);
        assert(errnop);

        if (_nss_systemd_is_blocked())
                return NSS_STATUS_NOTFOUND;

        r = userdb_by_uid(uid, nss_glue_userdb_flags(), &hr);
        if (r == -ESRCH)
                return NSS_STATUS_NOTFOUND;
        if (r < 0) {
                *errnop = -r;
                return NSS_STATUS_UNAVAIL;
        }

        r = nss_pack_user_record(hr, pwd, buffer, buflen);
        if (r < 0) {
                *errnop = -r;
                return NSS_STATUS_TRYAGAIN;
        }

        return NSS_STATUS_SUCCESS;
}

int nss_pack_group_record(
                GroupRecord *g,
                char **extra_members,
                struct group *gr,
                char *buffer,
                size_t buflen) {

        char **array = NULL, *p, **m;
        size_t required, n = 0, i = 0;

        assert(g);
        assert(gr);

        assert_se(g->group_name);
        required = strlen(g->group_name) + 1;

        STRV_FOREACH(m, g->members) {
                required += sizeof(char*);  /* space for ptr array entry */
                required += strlen(*m) + 1;
                n++;
        }
        STRV_FOREACH(m, extra_members) {
                if (strv_contains(g->members, *m))
                        continue;

                required += sizeof(char*);
                required += strlen(*m) + 1;
                n++;
        }

        required += sizeof(char*); /* trailing NULL in ptr array entry */

        if (buflen < required)
                return -ERANGE;

        array = (char**) buffer; /* place ptr array at beginning of buffer, under assumption buffer is aligned */
        p = buffer + sizeof(void*) * (n + 1); /* place member strings right after the ptr array */

        STRV_FOREACH(m, g->members) {
                array[i++] = p;
                p = stpcpy(p, *m) + 1;
        }
        STRV_FOREACH(m, extra_members) {
                if (strv_contains(g->members, *m))
                        continue;

                array[i++] = p;
                p = stpcpy(p, *m) + 1;
        }

        assert_se(i == n);
        array[n] = NULL;

        *gr = (struct group) {
                .gr_name = strcpy(p, g->group_name),
                .gr_gid = g->gid,
                .gr_passwd = (char*) "x", /* means: see shadow file */
                .gr_mem = array,
        };

        return 0;
}

enum nss_status userdb_getgrnam(
                const char *name,
                struct group *gr,
                char *buffer,
                size_t buflen,
                int *errnop) {

        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;
        _cleanup_strv_free_ char **members = NULL;
        int r;

        assert(gr);
        assert(errnop);

        if (_nss_systemd_is_blocked())
                return NSS_STATUS_NOTFOUND;

        r = groupdb_by_name(name, nss_glue_userdb_flags(), &g);
        if (r < 0 && r != -ESRCH) {
                *errnop = -r;
                return NSS_STATUS_UNAVAIL;
        }

        r = membershipdb_by_group_strv(name, nss_glue_userdb_flags(), &members);
        if (r < 0) {
                *errnop = -r;
                return NSS_STATUS_UNAVAIL;
        }

        if (!g) {
                _cleanup_(_nss_systemd_unblockp) bool blocked = false;

                if (strv_isempty(members))
                        return NSS_STATUS_NOTFOUND;

                /* Grmbl, so we are supposed to extend a group entry, but the group entry itself is not
                 * accessible via non-NSS. Hence let's do what we have to do, and query NSS after all to
                 * acquire it, so that we can extend it (that's because glibc's group merging feature will
                 * merge groups only if both GID and name match and thus we need to have both first). It
                 * sucks behaving recursively likely this, but it's apparently what everybody does. We break
                 * the recursion for ourselves via the _nss_systemd_block_nss() lock. */

                r = _nss_systemd_block(true);
                if (r < 0)
                        return r;

                blocked = true;

                r = nss_group_record_by_name(name, false, &g);
                if (r == -ESRCH)
                        return NSS_STATUS_NOTFOUND;
                if (r < 0) {
                        *errnop = -r;
                        return NSS_STATUS_UNAVAIL;
                }
        }

        r = nss_pack_group_record(g, members, gr, buffer, buflen);
        if (r < 0) {
                *errnop = -r;
                return NSS_STATUS_TRYAGAIN;
        }

        return NSS_STATUS_SUCCESS;
}

enum nss_status userdb_getgrgid(
                gid_t gid,
                struct group *gr,
                char *buffer,
                size_t buflen,
                int *errnop) {


        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;
        _cleanup_strv_free_ char **members = NULL;
        bool from_nss;
        int r;

        assert(gr);
        assert(errnop);

        if (_nss_systemd_is_blocked())
                return NSS_STATUS_NOTFOUND;

        r = groupdb_by_gid(gid, nss_glue_userdb_flags(), &g);
        if (r < 0 && r != -ESRCH) {
                *errnop = -r;
                return NSS_STATUS_UNAVAIL;
        }

        if (!g) {
                _cleanup_(_nss_systemd_unblockp) bool blocked = false;

                /* So, quite possibly we have to extend an existing group record with additional members. But
                 * to do this we need to know the group name first. The group didn't exist via non-NSS
                 * queries though, hence let's try to acquire it here recursively via NSS. */

                r = _nss_systemd_block(true);
                if (r < 0)
                        return r;

                blocked = true;

                r = nss_group_record_by_gid(gid, false, &g);
                if (r == -ESRCH)
                        return NSS_STATUS_NOTFOUND;
                if (r < 0) {
                        *errnop = -r;
                        return NSS_STATUS_UNAVAIL;
                }

                from_nss = true;
        } else
                from_nss = false;

        r = membershipdb_by_group_strv(g->group_name, nss_glue_userdb_flags(), &members);
        if (r < 0) {
                *errnop = -r;
                return NSS_STATUS_UNAVAIL;
        }

        /* If we acquired the record via NSS then there's no reason to respond unless we have to augment the
         * list of members of the group */
        if (from_nss && strv_isempty(members))
                return NSS_STATUS_NOTFOUND;

        r = nss_pack_group_record(g, members, gr, buffer, buflen);
        if (r < 0) {
                *errnop = -r;
                return NSS_STATUS_TRYAGAIN;
        }

        return NSS_STATUS_SUCCESS;
}
