/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "machined-varlink.h"
#include "mkdir.h"
#include "user-util.h"
#include "varlink.h"

typedef struct LookupParameters {
        const char *user_name;
        const char *group_name;
        union {
                uid_t uid;
                gid_t gid;
        };
        const char *service;
} LookupParameters;

static int build_user_json(const char *user_name, uid_t uid, const char *real_name, JsonVariant **ret) {
        assert(user_name);
        assert(uid_is_valid(uid));
        assert(ret);

        return json_build(ret, JSON_BUILD_OBJECT(
                                   JSON_BUILD_PAIR("record", JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(user_name)),
                                       JSON_BUILD_PAIR("uid", JSON_BUILD_UNSIGNED(uid)),
                                       JSON_BUILD_PAIR("gid", JSON_BUILD_UNSIGNED(GID_NOBODY)),
                                       JSON_BUILD_PAIR_CONDITION(!isempty(real_name), "realName", JSON_BUILD_STRING(real_name)),
                                       JSON_BUILD_PAIR("homeDirectory", JSON_BUILD_CONST_STRING("/")),
                                       JSON_BUILD_PAIR("shell", JSON_BUILD_STRING(NOLOGIN)),
                                       JSON_BUILD_PAIR("locked", JSON_BUILD_BOOLEAN(true)),
                                       JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.Machine")),
                                       JSON_BUILD_PAIR("disposition", JSON_BUILD_CONST_STRING("container"))))));
}

static bool user_match_lookup_parameters(LookupParameters *p, const char *name, uid_t uid) {
        assert(p);

        if (p->user_name && !streq(name, p->user_name))
                return false;

        if (uid_is_valid(p->uid) && uid != p->uid)
                return false;

        return true;
}

static int user_lookup_uid(Manager *m, uid_t uid, char **ret_name, char **ret_real_name) {
        _cleanup_free_ char *n = NULL, *rn = NULL;
        uid_t converted_uid;
        Machine *machine;
        int r;

        assert(m);
        assert(uid_is_valid(uid));
        assert(ret_name);
        assert(ret_real_name);

        if (uid < 0x10000) /* Host UID range */
                return -ESRCH;

        r = manager_find_machine_for_uid(m, uid, &machine, &converted_uid);
        if (r < 0)
                return r;
        if (!r)
                return -ESRCH;

        if (asprintf(&n, "vu-%s-" UID_FMT, machine->name, converted_uid) < 0)
                return -ENOMEM;

        /* Don't synthesize invalid user/group names (too long...) */
        if (!valid_user_group_name(n, 0))
                return -ESRCH;

        if (asprintf(&rn, "UID " UID_FMT " of Container %s", converted_uid, machine->name) < 0)
                return -ENOMEM;

        /* Don't synthesize invalid real names either, but since this field doesn't matter much, simply invalidate things */
        if (!valid_gecos(rn))
                rn = mfree(rn);

        *ret_name = TAKE_PTR(n);
        *ret_real_name = TAKE_PTR(rn);
        return 0;
}

static int user_lookup_name(Manager *m, const char *name, uid_t *ret_uid, char **ret_real_name) {
        _cleanup_free_ char *mn = NULL, *rn = NULL;
        uid_t uid, converted_uid;
        Machine *machine;
        const char *e, *d;
        int r;

        assert(m);
        assert(ret_uid);
        assert(ret_real_name);

        if (!valid_user_group_name(name, 0))
                return -ESRCH;

        e = startswith(name, "vu-");
        if (!e)
                return -ESRCH;

        d = strrchr(e, '-');
        if (!d)
                return -ESRCH;

        if (parse_uid(d + 1, &uid) < 0)
                return -ESRCH;

        mn = strndup(e, d - e);
        if (!mn)
                return -ENOMEM;

        machine = hashmap_get(m->machines, mn);
        if (!machine)
                return -ESRCH;

        if (machine->class != MACHINE_CONTAINER)
                return -ESRCH;

        r = machine_translate_uid(machine, uid, &converted_uid);
        if (r < 0)
                return r;

        if (asprintf(&rn, "UID " UID_FMT " of Container %s", uid, machine->name) < 0)
                return -ENOMEM;
        if (!valid_gecos(rn))
                rn = mfree(rn);

        *ret_uid = converted_uid;
        *ret_real_name = TAKE_PTR(rn);
        return 0;
}

static int vl_method_get_user_record(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "uid",      JSON_VARIANT_UNSIGNED, json_dispatch_uid_gid,      offsetof(LookupParameters, uid),       0         },
                { "userName", JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(LookupParameters, user_name), JSON_SAFE },
                { "service",  JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(LookupParameters, service),   0         },
                {}
        };

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        LookupParameters p = {
                .uid = UID_INVALID,
        };
        _cleanup_free_ char *found_name = NULL, *found_real_name = NULL;
        uid_t found_uid = UID_INVALID, uid;
        Manager *m = ASSERT_PTR(userdata);
        const char *un;
        int r;

        assert(parameters);

        r = json_dispatch(parameters, dispatch_table, NULL, 0, &p);
        if (r < 0)
                return r;

        if (!streq_ptr(p.service, "io.systemd.Machine"))
                return varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        if (uid_is_valid(p.uid))
                r = user_lookup_uid(m, p.uid, &found_name, &found_real_name);
        else if (p.user_name)
                r = user_lookup_name(m, p.user_name, &found_uid, &found_real_name);
        else
                return varlink_error(link, "io.systemd.UserDatabase.EnumerationNotSupported", NULL);
        if (r == -ESRCH)
                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
        if (r < 0)
                return r;

        uid = uid_is_valid(found_uid) ? found_uid : p.uid;
        un = found_name ?: p.user_name;

        if (!user_match_lookup_parameters(&p, un, uid))
                return varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        r = build_user_json(un, uid, found_real_name, &v);
        if (r < 0)
                return r;

        return varlink_reply(link, v);
}

static int build_group_json(const char *group_name, gid_t gid, const char *description, JsonVariant **ret) {
        assert(group_name);
        assert(gid_is_valid(gid));
        assert(ret);

        return json_build(ret, JSON_BUILD_OBJECT(
                                   JSON_BUILD_PAIR("record", JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(group_name)),
                                       JSON_BUILD_PAIR("gid", JSON_BUILD_UNSIGNED(gid)),
                                       JSON_BUILD_PAIR_CONDITION(!isempty(description), "description", JSON_BUILD_STRING(description)),
                                       JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.Machine")),
                                       JSON_BUILD_PAIR("disposition", JSON_BUILD_CONST_STRING("container"))))));
    }

static bool group_match_lookup_parameters(LookupParameters *p, const char *name, gid_t gid) {
        assert(p);

        if (p->group_name && !streq(name, p->group_name))
                return false;

        if (gid_is_valid(p->gid) && gid != p->gid)
                return false;

        return true;
}

static int group_lookup_gid(Manager *m, gid_t gid, char **ret_name, char **ret_description) {
        _cleanup_free_ char *n = NULL, *d = NULL;
        gid_t converted_gid;
        Machine *machine;
        int r;

        assert(m);
        assert(gid_is_valid(gid));
        assert(ret_name);
        assert(ret_description);

        if (gid < 0x10000) /* Host GID range */
                return -ESRCH;

        r = manager_find_machine_for_gid(m, gid, &machine, &converted_gid);
        if (r < 0)
                return r;
        if (!r)
                return -ESRCH;

        if (asprintf(&n, "vg-%s-" GID_FMT, machine->name, converted_gid) < 0)
                return -ENOMEM;

        if (!valid_user_group_name(n, 0))
                return -ESRCH;

        if (asprintf(&d, "GID " GID_FMT " of Container %s", converted_gid, machine->name) < 0)
                return -ENOMEM;
        if (!valid_gecos(d))
                d = mfree(d);

        *ret_name = TAKE_PTR(n);
        *ret_description = TAKE_PTR(d);

        return 0;
}

static int group_lookup_name(Manager *m, const char *name, gid_t *ret_gid, char **ret_description) {
        _cleanup_free_ char *mn = NULL, *desc = NULL;
        gid_t gid, converted_gid;
        Machine *machine;
        const char *e, *d;
        int r;

        assert(m);
        assert(ret_gid);
        assert(ret_description);

        if (!valid_user_group_name(name, 0))
                return -ESRCH;

        e = startswith(name, "vg-");
        if (!e)
                return -ESRCH;

        d = strrchr(e, '-');
        if (!d)
                return -ESRCH;

        if (parse_gid(d + 1, &gid) < 0)
                return -ESRCH;

        mn = strndup(e, d - e);
        if (!mn)
                return -ENOMEM;

        machine = hashmap_get(m->machines, mn);
        if (!machine)
                return -ESRCH;

        if (machine->class != MACHINE_CONTAINER)
                return -ESRCH;

        r = machine_translate_gid(machine, gid, &converted_gid);
        if (r < 0)
                return r;

        if (asprintf(&desc, "GID " GID_FMT " of Container %s", gid, machine->name) < 0)
                return -ENOMEM;
        if (!valid_gecos(desc))
                desc = mfree(desc);

        *ret_gid = converted_gid;
        *ret_description = TAKE_PTR(desc);
        return 0;
}

static int vl_method_get_group_record(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "gid",       JSON_VARIANT_UNSIGNED, json_dispatch_uid_gid,      offsetof(LookupParameters, gid),        0         },
                { "groupName", JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(LookupParameters, group_name), JSON_SAFE },
                { "service",   JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(LookupParameters, service),    0         },
                {}
        };

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        LookupParameters p = {
                .gid = GID_INVALID,
        };
        _cleanup_free_ char *found_name = NULL, *found_description = NULL;
        uid_t found_gid = GID_INVALID, gid;
        Manager *m = ASSERT_PTR(userdata);
        const char *gn;
        int r;

        assert(parameters);

        r = json_dispatch(parameters, dispatch_table, NULL, 0, &p);
        if (r < 0)
                return r;

        if (!streq_ptr(p.service, "io.systemd.Machine"))
                return varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        if (gid_is_valid(p.gid))
                r = group_lookup_gid(m, p.gid, &found_name, &found_description);
        else if (p.group_name)
                r = group_lookup_name(m, p.group_name, (uid_t*) &found_gid, &found_description);
        else
                return varlink_error(link, "io.systemd.UserDatabase.EnumerationNotSupported", NULL);
        if (r == -ESRCH)
                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
        if (r < 0)
                return r;

        gid = gid_is_valid(found_gid) ? found_gid : p.gid;
        gn = found_name ?: p.group_name;

        if (!group_match_lookup_parameters(&p, gn, gid))
                return varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        r = build_group_json(gn, gid, found_description, &v);
        if (r < 0)
                return r;

        return varlink_reply(link, v);
}

static int vl_method_get_memberships(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "userName",  JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, user_name),  JSON_SAFE },
                { "groupName", JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, group_name), JSON_SAFE },
                { "service",   JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, service),    0         },
                {}
        };

        LookupParameters p = {};
        int r;

        assert(parameters);

        r = json_dispatch(parameters, dispatch_table, NULL, 0, &p);
        if (r < 0)
                return r;

        if (!streq_ptr(p.service, "io.systemd.Machine"))
                return varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        /* We don't support auxiliary groups for machines. */
        return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
}

int manager_varlink_init(Manager *m) {
        _cleanup_(varlink_server_unrefp) VarlinkServer *s = NULL;
        int r;

        assert(m);

        if (m->varlink_server)
                return 0;

        r = varlink_server_new(&s, VARLINK_SERVER_ACCOUNT_UID|VARLINK_SERVER_INHERIT_USERDATA);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        varlink_server_set_userdata(s, m);

        r = varlink_server_bind_method_many(
                        s,
                        "io.systemd.UserDatabase.GetUserRecord",  vl_method_get_user_record,
                        "io.systemd.UserDatabase.GetGroupRecord", vl_method_get_group_record,
                        "io.systemd.UserDatabase.GetMemberships", vl_method_get_memberships);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        (void) mkdir_p("/run/systemd/userdb", 0755);

        r = varlink_server_listen_address(s, "/run/systemd/userdb/io.systemd.Machine", 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket: %m");

        r = varlink_server_attach_event(s, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        m->varlink_server = TAKE_PTR(s);
        return 0;
}

void manager_varlink_done(Manager *m) {
        assert(m);

        m->varlink_server = varlink_server_unref(m->varlink_server);
}
