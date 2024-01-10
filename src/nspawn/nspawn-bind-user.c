/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "chase.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "nspawn-bind-user.h"
#include "nspawn.h"
#include "path-util.h"
#include "user-util.h"
#include "userdb.h"

static int check_etc_passwd_collisions(
                const char *directory,
                const char *name,
                uid_t uid) {

        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(directory);
        assert(name || uid_is_valid(uid));

        r = chase_and_fopen_unlocked("/etc/passwd", directory, CHASE_PREFIX_ROOT, "re", NULL, &f);
        if (r == -ENOENT)
                return 0; /* no user database? then no user, hence no collision */
        if (r < 0)
                return log_error_errno(r, "Failed to open /etc/passwd of container: %m");

        for (;;) {
                struct passwd *pw;

                r = fgetpwent_sane(f, &pw);
                if (r < 0)
                        return log_error_errno(r, "Failed to iterate through /etc/passwd of container: %m");
                if (r == 0) /* EOF */
                        return 0; /* no collision */

                if (name && streq_ptr(pw->pw_name, name))
                        return 1; /* name collision */
                if (uid_is_valid(uid) && pw->pw_uid == uid)
                        return 1; /* UID collision */
        }
}

static int check_etc_group_collisions(
                const char *directory,
                const char *name,
                gid_t gid) {

        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(directory);
        assert(name || gid_is_valid(gid));

        r = chase_and_fopen_unlocked("/etc/group", directory, CHASE_PREFIX_ROOT, "re", NULL, &f);
        if (r == -ENOENT)
                return 0; /* no group database? then no group, hence no collision */
        if (r < 0)
                return log_error_errno(r, "Failed to open /etc/group of container: %m");

        for (;;) {
                struct group *gr;

                r = fgetgrent_sane(f, &gr);
                if (r < 0)
                        return log_error_errno(r, "Failed to iterate through /etc/group of container: %m");
                if (r == 0)
                        return 0; /* no collision */

                if (name && streq_ptr(gr->gr_name, name))
                        return 1; /* name collision */
                if (gid_is_valid(gid) && gr->gr_gid == gid)
                        return 1; /* gid collision */
        }
}

static int convert_user(
                const char *directory,
                UserRecord *u,
                GroupRecord *g,
                uid_t allocate_uid,
                UserRecord **ret_converted_user,
                GroupRecord **ret_converted_group) {

        _cleanup_(group_record_unrefp) GroupRecord *converted_group = NULL;
        _cleanup_(user_record_unrefp) UserRecord *converted_user = NULL;
        _cleanup_free_ char *h = NULL;
        JsonVariant *p, *hp = NULL;
        int r;

        assert(u);
        assert(g);
        assert(u->gid == g->gid);

        r = check_etc_passwd_collisions(directory, u->user_name, UID_INVALID);
        if (r < 0)
                return r;
        if (r > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY),
                                       "Sorry, the user '%s' already exists in the container.", u->user_name);

        r = check_etc_group_collisions(directory, g->group_name, GID_INVALID);
        if (r < 0)
                return r;
        if (r > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY),
                                       "Sorry, the group '%s' already exists in the container.", g->group_name);

        h = path_join("/run/host/home/", u->user_name);
        if (!h)
                return log_oom();

        /* Acquire the source hashed password array as-is, so that it retains the JSON_VARIANT_SENSITIVE flag */
        p = json_variant_by_key(u->json, "privileged");
        if (p)
                hp = json_variant_by_key(p, "hashedPassword");

        r = user_record_build(
                        &converted_user,
                        JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(u->user_name)),
                                        JSON_BUILD_PAIR("uid", JSON_BUILD_UNSIGNED(allocate_uid)),
                                        JSON_BUILD_PAIR("gid", JSON_BUILD_UNSIGNED(allocate_uid)),
                                        JSON_BUILD_PAIR_CONDITION(u->disposition >= 0, "disposition", JSON_BUILD_STRING(user_disposition_to_string(u->disposition))),
                                        JSON_BUILD_PAIR("homeDirectory", JSON_BUILD_STRING(h)),
                                        JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.NSpawn")),
                                        JSON_BUILD_PAIR_CONDITION(!strv_isempty(u->hashed_password), "privileged", JSON_BUILD_OBJECT(
                                                                                  JSON_BUILD_PAIR("hashedPassword", JSON_BUILD_VARIANT(hp))))));
        if (r < 0)
                return log_error_errno(r, "Failed to build container user record: %m");

        r = group_record_build(
                        &converted_group,
                        JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(g->group_name)),
                                        JSON_BUILD_PAIR("gid", JSON_BUILD_UNSIGNED(allocate_uid)),
                                        JSON_BUILD_PAIR_CONDITION(g->disposition >= 0, "disposition", JSON_BUILD_STRING(user_disposition_to_string(g->disposition))),
                                        JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.NSpawn"))));
        if (r < 0)
                return log_error_errno(r, "Failed to build container group record: %m");

        *ret_converted_user = TAKE_PTR(converted_user);
        *ret_converted_group = TAKE_PTR(converted_group);

        return 0;
}

static int find_free_uid(const char *directory, uid_t max_uid, uid_t *current_uid) {
        int r;

        assert(directory);
        assert(current_uid);

        for (;; (*current_uid)++) {
                if (*current_uid > MAP_UID_MAX || *current_uid > max_uid)
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(EBUSY),
                                        "No suitable available UID in range " UID_FMT "…" UID_FMT " in container detected, can't map user.",
                                        MAP_UID_MIN, MAP_UID_MAX);

                r = check_etc_passwd_collisions(directory, NULL, *current_uid);
                if (r < 0)
                        return r;
                if (r > 0) /* already used */
                        continue;

                /* We want to use the UID also as GID, hence check for it in /etc/group too */
                r = check_etc_group_collisions(directory, NULL, (gid_t) *current_uid);
                if (r <= 0)
                        return r;
        }
}

BindUserContext* bind_user_context_free(BindUserContext *c) {
        if (!c)
                return NULL;

        assert(c->n_data == 0 || c->data);

        for (size_t i = 0; i < c->n_data; i++) {
                user_record_unref(c->data[i].host_user);
                group_record_unref(c->data[i].host_group);
                user_record_unref(c->data[i].payload_user);
                group_record_unref(c->data[i].payload_group);
        }

        return mfree(c);
}

int bind_user_prepare(
                const char *directory,
                char **bind_user,
                uid_t uid_shift,
                uid_t uid_range,
                CustomMount **custom_mounts,
                size_t *n_custom_mounts,
                BindUserContext **ret) {

        _cleanup_(bind_user_context_freep) BindUserContext *c = NULL;
        uid_t current_uid = MAP_UID_MIN;
        int r;

        assert(custom_mounts);
        assert(n_custom_mounts);
        assert(ret);

        /* This resolves the users specified in 'bind_user', generates a minimalized JSON user + group record
         * for it to stick in the container, allocates a UID/GID for it, and updates the custom mount table,
         * to include an appropriate bind mount mapping.
         *
         * This extends the passed custom_mounts/n_custom_mounts with the home directories, and allocates a
         * new BindUserContext for the user records */

        if (strv_isempty(bind_user)) {
                *ret = NULL;
                return 0;
        }

        c = new0(BindUserContext, 1);
        if (!c)
                return log_oom();

        STRV_FOREACH(n, bind_user) {
                _cleanup_(user_record_unrefp) UserRecord *u = NULL, *cu = NULL;
                _cleanup_(group_record_unrefp) GroupRecord *g = NULL, *cg = NULL;
                _cleanup_free_ char *sm = NULL, *sd = NULL;
                CustomMount *cm;

                r = userdb_by_name(*n, USERDB_DONT_SYNTHESIZE, &u);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve user '%s': %m", *n);

                /* For now, let's refuse mapping the root/nobody users explicitly. The records we generate
                 * are strictly additive, nss-systemd is typically placed last in /etc/nsswitch.conf. Thus
                 * even if we wanted, we couldn't override the root or nobody user records. Note we also
                 * check for name conflicts in /etc/passwd + /etc/group later on, which would usually filter
                 * out root/nobody too, hence these checks might appear redundant — but they actually are
                 * not, as we want to support environments where /etc/passwd and /etc/group are non-existent,
                 * and the user/group databases fully synthesized at runtime. Moreover, the name of the
                 * user/group name of the "nobody" account differs between distros, hence a check by numeric
                 * UID is safer. */
                if (u->uid == 0 || streq(u->user_name, "root"))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Mapping 'root' user not supported, sorry.");
                if (u->uid == UID_NOBODY || STR_IN_SET(u->user_name, NOBODY_USER_NAME, "nobody"))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Mapping 'nobody' user not supported, sorry.");

                if (u->uid >= uid_shift && u->uid < uid_shift + uid_range)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "UID of user '%s' to map is already in container UID range, refusing.", u->user_name);

                r = groupdb_by_gid(u->gid, USERDB_DONT_SYNTHESIZE, &g);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve group of user '%s': %m", u->user_name);

                if (g->gid >= uid_shift && g->gid < uid_shift + uid_range)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "GID of group '%s' to map is already in container GID range, refusing.", g->group_name);

                /* We want to synthesize exactly one user + group from the host into the container. This only
                 * makes sense if the user on the host has its own private group. We can't reasonably check
                 * this, so we just check of the name of user and group match.
                 *
                 * One of these days we might want to support users in a shared/common group too, but it's
                 * not clear to me how this would have to be mapped, precisely given that the common group
                 * probably already exists in the container. */
                if (!streq(u->user_name, g->group_name))
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Sorry, mapping users without private groups is currently not supported.");

                r = find_free_uid(directory, uid_range, &current_uid);
                if (r < 0)
                        return r;

                r = convert_user(directory, u, g, current_uid, &cu, &cg);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC(c->data, c->n_data + 1))
                        return log_oom();

                sm = strdup(u->home_directory);
                if (!sm)
                        return log_oom();

                sd = strdup(cu->home_directory);
                if (!sd)
                        return log_oom();

                cm = reallocarray(*custom_mounts, sizeof(CustomMount), *n_custom_mounts + 1);
                if (!cm)
                        return log_oom();

                *custom_mounts = cm;

                (*custom_mounts)[(*n_custom_mounts)++] = (CustomMount) {
                        .type = CUSTOM_MOUNT_BIND,
                        .source = TAKE_PTR(sm),
                        .destination = TAKE_PTR(sd),
                };

                c->data[c->n_data++] = (BindUserData) {
                        .host_user = TAKE_PTR(u),
                        .host_group = TAKE_PTR(g),
                        .payload_user = TAKE_PTR(cu),
                        .payload_group = TAKE_PTR(cg),
                };

                current_uid++;
        }

        *ret = TAKE_PTR(c);
        return 1;
}

static int write_and_symlink(
                const char *root,
                JsonVariant *v,
                const char *name,
                uid_t uid,
                const char *suffix,
                WriteStringFileFlags extra_flags) {

        _cleanup_free_ char *j = NULL, *f = NULL, *p = NULL, *q = NULL;
        int r;

        assert(root);
        assert(v);
        assert(name);
        assert(uid_is_valid(uid));
        assert(suffix);

        r = json_variant_format(v, JSON_FORMAT_NEWLINE, &j);
        if (r < 0)
                return log_error_errno(r, "Failed to format user record JSON: %m");

        f = strjoin(name, suffix);
        if (!f)
                return log_oom();

        p = path_join(root, "/run/host/userdb/", f);
        if (!p)
                return log_oom();

        if (asprintf(&q, "%s/run/host/userdb/" UID_FMT "%s", root, uid, suffix) < 0)
                return log_oom();

        if (symlink(f, q) < 0)
                return log_error_errno(errno, "Failed to create symlink '%s': %m", q);

        r = userns_lchown(q, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust access mode of '%s': %m", q);

        r = write_string_file(p, j, WRITE_STRING_FILE_CREATE|extra_flags);
        if (r < 0)
                return log_error_errno(r, "Failed to write %s: %m", p);

        r = userns_lchown(p, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust access mode of '%s': %m", p);

        return 0;
}

int bind_user_setup(
                const BindUserContext *c,
                const char *root) {

        static const UserRecordLoadFlags strip_flags = /* Removes privileged info */
                USER_RECORD_REQUIRE_REGULAR|
                USER_RECORD_STRIP_PRIVILEGED|
                USER_RECORD_ALLOW_PER_MACHINE|
                USER_RECORD_ALLOW_BINDING|
                USER_RECORD_ALLOW_SIGNATURE|
                USER_RECORD_PERMISSIVE;
        static const UserRecordLoadFlags shadow_flags = /* Extracts privileged info */
                USER_RECORD_STRIP_REGULAR|
                USER_RECORD_ALLOW_PRIVILEGED|
                USER_RECORD_STRIP_PER_MACHINE|
                USER_RECORD_STRIP_BINDING|
                USER_RECORD_STRIP_SIGNATURE|
                USER_RECORD_EMPTY_OK|
                USER_RECORD_PERMISSIVE;
        int r;

        assert(root);

        if (!c || c->n_data == 0)
                return 0;

        r = make_run_host(root);
        if (r < 0)
                return r;

        r = userns_mkdir(root, "/run/host/home", 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/host/home: %m");

        r = userns_mkdir(root, "/run/host/userdb", 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/host/userdb: %m");

        for (size_t i = 0; i < c->n_data; i++) {
                _cleanup_(group_record_unrefp) GroupRecord *stripped_group = NULL, *shadow_group = NULL;
                _cleanup_(user_record_unrefp) UserRecord *stripped_user = NULL, *shadow_user = NULL;
                const BindUserData *d = c->data + i;

                /* First, write shadow (i.e. privileged) data for group record */
                r = group_record_clone(d->payload_group, shadow_flags, &shadow_group);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract privileged information from group record: %m");

                if (!json_variant_is_blank_object(shadow_group->json)) {
                        r = write_and_symlink(
                                        root,
                                        shadow_group->json,
                                        d->payload_group->group_name,
                                        d->payload_group->gid,
                                        ".group-privileged",
                                        WRITE_STRING_FILE_MODE_0600);
                        if (r < 0)
                                return r;
                }

                /* Second, write main part of group record. */
                r = group_record_clone(d->payload_group, strip_flags, &stripped_group);
                if (r < 0)
                        return log_error_errno(r, "Failed to strip privileged information from group record: %m");

                r = write_and_symlink(
                                root,
                                stripped_group->json,
                                d->payload_group->group_name,
                                d->payload_group->gid,
                                ".group",
                                0);
                if (r < 0)
                        return r;

                /* Third, write out user shadow data. i.e. extract privileged info from user record */
                r = user_record_clone(d->payload_user, shadow_flags, &shadow_user);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract privileged information from user record: %m");

                if (!json_variant_is_blank_object(shadow_user->json)) {
                        r = write_and_symlink(
                                        root,
                                        shadow_user->json,
                                        d->payload_user->user_name,
                                        d->payload_user->uid,
                                        ".user-privileged",
                                        WRITE_STRING_FILE_MODE_0600);
                        if (r < 0)
                                return r;
                }

                /* Finally write out the main part of the user record */
                r = user_record_clone(d->payload_user, strip_flags, &stripped_user);
                if (r < 0)
                        return log_error_errno(r, "Failed to strip privileged information from user record: %m");

                r = write_and_symlink(
                                root,
                                stripped_user->json,
                                d->payload_user->user_name,
                                d->payload_user->uid,
                                ".user",
                                0);
                if (r < 0)
                        return r;
        }

        return 1;
}
