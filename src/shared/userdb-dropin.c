/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "path-util.h"
#include "stdio-util.h"
#include "user-util.h"
#include "userdb-dropin.h"

static int load_user(
                FILE *f,
                const char *path,
                const char *name,
                uid_t uid,
                UserDBFlags flags,
                UserRecord **ret) {

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *u = NULL;
        bool have_privileged;
        int r;

        assert(f);

        r = json_parse_file(f, path, 0, &v, NULL, NULL);
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, USERDB_SUPPRESS_SHADOW) || !path || !(name || uid_is_valid(uid)))
                have_privileged = false;
        else {
                _cleanup_(json_variant_unrefp) JsonVariant *privileged_v = NULL;
                _cleanup_free_ char *d = NULL, *j = NULL;

                /* Let's load the "privileged" section from a companion file. But only if USERDB_AVOID_SHADOW
                 * is not set. After all, the privileged section kinda takes the role of the data from the
                 * shadow file, hence it makes sense to use the same flag here.
                 *
                 * The general assumption is that whoever provides these records makes the .user file
                 * world-readable, but the .privilege file readable to root and the assigned UID only. But we
                 * won't verify that here, as it would be too late. */

                r = path_extract_directory(path, &d);
                if (r < 0)
                        return r;

                if (name) {
                        j = strjoin(d, "/", name, ".user-privileged");
                        if (!j)
                                return -ENOMEM;
                } else {
                        assert(uid_is_valid(uid));
                        if (asprintf(&j, "%s/" UID_FMT ".user-privileged", d, uid) < 0)
                                return -ENOMEM;
                }

                r = json_parse_file(NULL, j, JSON_PARSE_SENSITIVE, &privileged_v, NULL, NULL);
                if (ERRNO_IS_PRIVILEGE(r))
                        have_privileged = false;
                else if (r == -ENOENT)
                        have_privileged = true; /* if the privileged file doesn't exist, we are complete */
                else if (r < 0)
                        return r;
                else {
                        r = json_variant_merge(&v, privileged_v);
                        if (r < 0)
                                return r;

                        have_privileged = true;
                }
        }

        u = user_record_new();
        if (!u)
                return -ENOMEM;

        r = user_record_load(
                        u, v,
                        USER_RECORD_REQUIRE_REGULAR|
                        USER_RECORD_ALLOW_PER_MACHINE|
                        USER_RECORD_ALLOW_BINDING|
                        USER_RECORD_ALLOW_SIGNATURE|
                        (have_privileged ? USER_RECORD_ALLOW_PRIVILEGED : 0)|
                        USER_RECORD_PERMISSIVE);
        if (r < 0)
                return r;

        if (name && !streq_ptr(name, u->user_name))
                return -EINVAL;

        if (uid_is_valid(uid) && uid != u->uid)
                return -EINVAL;

        u->incomplete = !have_privileged;

        if (ret)
                *ret = TAKE_PTR(u);

        return 0;
}

int dropin_user_record_by_name(const char *name, const char *path, UserDBFlags flags, UserRecord **ret) {
        _cleanup_free_ char *found_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(name);

        if (path) {
                f = fopen(path, "re");
                if (!f)
                        return errno == ENOENT ? -ESRCH : -errno; /* We generally want ESRCH to indicate no such user */
        } else {
                const char *j;

                j = strjoina(name, ".user");
                if (!filename_is_valid(j)) /* Doesn't qualify as valid filename? Then it's definitely not provided as a drop-in */
                        return -ESRCH;

                r = search_and_fopen_nulstr(j, "re", NULL, USERDB_DROPIN_DIR_NULSTR("userdb"), &f, &found_path);
                if (r == -ENOENT)
                        return -ESRCH;
                if (r < 0)
                        return r;

                path = found_path;
        }

        return load_user(f, path, name, UID_INVALID, flags, ret);
}

int dropin_user_record_by_uid(uid_t uid, const char *path, UserDBFlags flags, UserRecord **ret) {
        _cleanup_free_ char *found_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(uid_is_valid(uid));

        if (path) {
                f = fopen(path, "re");
                if (!f)
                        return errno == ENOENT ? -ESRCH : -errno;
        } else {
                char buf[DECIMAL_STR_MAX(uid_t) + STRLEN(".user") + 1];

                xsprintf(buf, UID_FMT ".user", uid);
                /* Note that we don't bother to validate this as a filename, as this is generated from a decimal
                 * integer, i.e. is definitely OK as a filename */

                r = search_and_fopen_nulstr(buf, "re", NULL, USERDB_DROPIN_DIR_NULSTR("userdb"), &f, &found_path);
                if (r == -ENOENT)
                        return -ESRCH;
                if (r < 0)
                        return r;

                path = found_path;
        }

        return load_user(f, path, NULL, uid, flags, ret);
}

static int load_group(
                FILE *f,
                const char *path,
                const char *name,
                gid_t gid,
                UserDBFlags flags,
                GroupRecord **ret) {

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;
        bool have_privileged;
        int r;

        assert(f);

        r = json_parse_file(f, path, 0, &v, NULL, NULL);
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, USERDB_SUPPRESS_SHADOW) || !path || !(name || gid_is_valid(gid)))
                have_privileged = false;
        else {
                _cleanup_(json_variant_unrefp) JsonVariant *privileged_v = NULL;
                _cleanup_free_ char *d = NULL, *j = NULL;

                r = path_extract_directory(path, &d);
                if (r < 0)
                        return r;

                if (name) {
                        j = strjoin(d, "/", name, ".group-privileged");
                        if (!j)
                                return -ENOMEM;
                } else {
                        assert(gid_is_valid(gid));
                        if (asprintf(&j, "%s/" GID_FMT ".group-privileged", d, gid) < 0)
                                return -ENOMEM;
                }

                r = json_parse_file(NULL, j, JSON_PARSE_SENSITIVE, &privileged_v, NULL, NULL);
                if (ERRNO_IS_PRIVILEGE(r))
                        have_privileged = false;
                else if (r == -ENOENT)
                        have_privileged = true; /* if the privileged file doesn't exist, we are complete */
                else if (r < 0)
                        return r;
                else {
                        r = json_variant_merge(&v, privileged_v);
                        if (r < 0)
                                return r;

                        have_privileged = true;
                }
        }

        g = group_record_new();
        if (!g)
                return -ENOMEM;

        r = group_record_load(
                        g, v,
                        USER_RECORD_REQUIRE_REGULAR|
                        USER_RECORD_ALLOW_PER_MACHINE|
                        USER_RECORD_ALLOW_BINDING|
                        USER_RECORD_ALLOW_SIGNATURE|
                        (have_privileged ? USER_RECORD_ALLOW_PRIVILEGED : 0)|
                        USER_RECORD_PERMISSIVE);
        if (r < 0)
                return r;

        if (name && !streq_ptr(name, g->group_name))
                return -EINVAL;

        if (gid_is_valid(gid) && gid != g->gid)
                return -EINVAL;

        g->incomplete = !have_privileged;

        if (ret)
                *ret = TAKE_PTR(g);

        return 0;
}

int dropin_group_record_by_name(const char *name, const char *path, UserDBFlags flags, GroupRecord **ret) {
        _cleanup_free_ char *found_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(name);

        if (path) {
                f = fopen(path, "re");
                if (!f)
                        return errno == ENOENT ? -ESRCH : -errno;
        } else {
                const char *j;

                j = strjoina(name, ".group");
                if (!filename_is_valid(j)) /* Doesn't qualify as valid filename? Then it's definitely not provided as a drop-in */
                        return -ESRCH;

                r = search_and_fopen_nulstr(j, "re", NULL, USERDB_DROPIN_DIR_NULSTR("userdb"), &f, &found_path);
                if (r == -ENOENT)
                        return -ESRCH;
                if (r < 0)
                        return r;

                path = found_path;
        }

        return load_group(f, path, name, GID_INVALID, flags, ret);
}

int dropin_group_record_by_gid(gid_t gid, const char *path, UserDBFlags flags, GroupRecord **ret) {
        _cleanup_free_ char *found_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(gid_is_valid(gid));

        if (path) {
                f = fopen(path, "re");
                if (!f)
                        return errno == ENOENT ? -ESRCH : -errno;
        } else {
                char buf[DECIMAL_STR_MAX(gid_t) + STRLEN(".group") + 1];

                xsprintf(buf, GID_FMT ".group", gid);

                r = search_and_fopen_nulstr(buf, "re", NULL, USERDB_DROPIN_DIR_NULSTR("userdb"), &f, &found_path);
                if (r == -ENOENT)
                        return -ESRCH;
                if (r < 0)
                        return r;

                path = found_path;
        }

        return load_group(f, path, NULL, gid, flags, ret);
}
