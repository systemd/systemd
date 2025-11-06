/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <grp.h>
#include <pwd.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "fd-util.h"
#include "format-util.h"
#include "json-util.h"
#include "log.h"
#include "machine-bind-user.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "userdb.h"

static int check_etc_passwd_collisions(
                const char *directory,
                const char *name,
                uid_t uid) {

        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(name || uid_is_valid(uid));

        if (!directory)
                return 0;

        r = chase_and_fopen_unlocked("/etc/passwd", directory, CHASE_PREFIX_ROOT, "re", NULL, &f);
        if (r == -ENOENT)
                return 0; /* no user database? then no user, hence no collision */
        if (r < 0)
                return log_error_errno(r, "Failed to open /etc/passwd of machine: %m");

        for (;;) {
                struct passwd *pw;

                r = fgetpwent_sane(f, &pw);
                if (r < 0)
                        return log_error_errno(r, "Failed to iterate through /etc/passwd of machine: %m");
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

        assert(name || gid_is_valid(gid));

        if (!directory)
                return 0;

        r = chase_and_fopen_unlocked("/etc/group", directory, CHASE_PREFIX_ROOT, "re", NULL, &f);
        if (r == -ENOENT)
                return 0; /* no group database? then no group, hence no collision */
        if (r < 0)
                return log_error_errno(r, "Failed to open /etc/group of machine: %m");

        for (;;) {
                struct group *gr;

                r = fgetgrent_sane(f, &gr);
                if (r < 0)
                        return log_error_errno(r, "Failed to iterate through /etc/group of machine: %m");
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
                const char *shell,
                bool shell_copy,
                UserRecord **ret_converted_user,
                GroupRecord **ret_converted_group) {

        _cleanup_(group_record_unrefp) GroupRecord *converted_group = NULL;
        _cleanup_(user_record_unrefp) UserRecord *converted_user = NULL;
        _cleanup_free_ char *h = NULL;
        sd_json_variant *p, *hp = NULL, *ssh = NULL;
        int r;

        assert(u);
        assert(g);
        assert(user_record_gid(u) == g->gid);

        if (shell_copy)
                shell = u->shell;

        r = check_etc_passwd_collisions(directory, u->user_name, UID_INVALID);
        if (r < 0)
                return r;
        if (r > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY),
                                       "Sorry, the user '%s' already exists in the machine.", u->user_name);

        r = check_etc_group_collisions(directory, g->group_name, GID_INVALID);
        if (r < 0)
                return r;
        if (r > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY),
                                       "Sorry, the group '%s' already exists in the machine.", g->group_name);

        h = path_join("/run/host/home/", u->user_name);
        if (!h)
                return log_oom();

        /* Acquire the source hashed password array as-is, so that it retains the JSON_VARIANT_SENSITIVE flag */
        p = sd_json_variant_by_key(u->json, "privileged");
        if (p) {
                hp = sd_json_variant_by_key(p, "hashedPassword");
                ssh = sd_json_variant_by_key(p, "sshAuthorizedKeys");
        }

        r = user_record_build(
                        &converted_user,
                        SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(u->user_name)),
                                        SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(allocate_uid)),
                                        SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(allocate_uid)),
                                        SD_JSON_BUILD_PAIR_CONDITION(u->disposition >= 0, "disposition", SD_JSON_BUILD_STRING(user_disposition_to_string(u->disposition))),
                                        SD_JSON_BUILD_PAIR("homeDirectory", SD_JSON_BUILD_STRING(h)),
                                        SD_JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.NSpawn")),
                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("shell", shell),
                                        SD_JSON_BUILD_PAIR("privileged", SD_JSON_BUILD_OBJECT(
                                                                           SD_JSON_BUILD_PAIR_CONDITION(!strv_isempty(u->hashed_password), "hashedPassword", SD_JSON_BUILD_VARIANT(hp)),
                                                                           SD_JSON_BUILD_PAIR_CONDITION(!!ssh, "sshAuthorizedKeys", SD_JSON_BUILD_VARIANT(ssh))))));
        if (r < 0)
                return log_error_errno(r, "Failed to build machine user record: %m");

        r = group_record_build(
                        &converted_group,
                        SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(g->group_name)),
                                        SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(allocate_uid)),
                                        SD_JSON_BUILD_PAIR_CONDITION(g->disposition >= 0, "disposition", SD_JSON_BUILD_STRING(user_disposition_to_string(g->disposition))),
                                        SD_JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.NSpawn"))));
        if (r < 0)
                return log_error_errno(r, "Failed to build machine group record: %m");

        *ret_converted_user = TAKE_PTR(converted_user);
        *ret_converted_group = TAKE_PTR(converted_group);

        return 0;
}

static int find_free_uid(const char *directory, uid_t *current_uid) {
        int r;

        assert(current_uid);

        for (;; (*current_uid)++) {
                if (*current_uid > MAP_UID_MAX)
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(EBUSY),
                                        "No suitable available UID in range " UID_FMT "…" UID_FMT " in machine detected, can't map user.",
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

MachineBindUserContext* machine_bind_user_context_free(MachineBindUserContext *c) {
        if (!c)
                return NULL;

        FOREACH_ARRAY(d, c->data, c->n_data) {
                user_record_unref(d->host_user);
                group_record_unref(d->host_group);
                user_record_unref(d->payload_user);
                group_record_unref(d->payload_group);
        }

        return mfree(c);
}

int machine_bind_user_prepare(
                const char *directory,
                char **bind_user,
                const char *bind_user_shell,
                bool bind_user_shell_copy,
                MachineBindUserContext **ret) {

        _cleanup_(machine_bind_user_context_freep) MachineBindUserContext *c = NULL;
        uid_t current_uid = MAP_UID_MIN;
        int r;

        assert(ret);

        /* This resolves the users specified in 'bind_user', generates a minimalized JSON user + group record
         * for it to stick in the machine, allocates a UID/GID for it, and updates the custom mount table,
         * to include an appropriate bind mount mapping.
         *
         * This extends the passed custom_mounts/n_custom_mounts with the home directories, and allocates a
         * new BindUserContext for the user records */

        if (strv_isempty(bind_user)) {
                *ret = NULL;
                return 0;
        }

        c = new0(MachineBindUserContext, 1);
        if (!c)
                return log_oom();

        STRV_FOREACH(n, bind_user) {
                _cleanup_(user_record_unrefp) UserRecord *u = NULL, *cu = NULL;
                _cleanup_(group_record_unrefp) GroupRecord *g = NULL, *cg = NULL;

                r = userdb_by_name(*n, /* match= */ NULL, USERDB_DONT_SYNTHESIZE_INTRINSIC|USERDB_DONT_SYNTHESIZE_FOREIGN, &u);
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
                if (user_record_is_root(u))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Mapping 'root' user not supported, sorry.");

                if (user_record_is_nobody(u))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Mapping 'nobody' user not supported, sorry.");

                if (!uid_is_valid(u->uid))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot bind user with no UID, refusing.");

                r = groupdb_by_gid(user_record_gid(u), /* match= */ NULL, USERDB_DONT_SYNTHESIZE_INTRINSIC|USERDB_DONT_SYNTHESIZE_FOREIGN, &g);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve group of user '%s': %m", u->user_name);

                /* We want to synthesize exactly one user + group from the host into the machine. This only
                 * makes sense if the user on the host has its own private group. We can't reasonably check
                 * this, so we just check of the name of user and group match.
                 *
                 * One of these days we might want to support users in a shared/common group too, but it's
                 * not clear to me how this would have to be mapped, precisely given that the common group
                 * probably already exists in the machine. */
                if (!streq(u->user_name, g->group_name))
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Sorry, mapping users without private groups is currently not supported.");

                r = find_free_uid(directory, &current_uid);
                if (r < 0)
                        return r;

                r = convert_user(directory, u, g, current_uid, bind_user_shell, bind_user_shell_copy, &cu, &cg);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC(c->data, c->n_data + 1))
                        return log_oom();

                c->data[c->n_data++] = (MachineBindUserData) {
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
