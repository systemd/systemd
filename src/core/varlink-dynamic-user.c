/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "dynamic-user.h"
#include "hashmap.h"
#include "json-util.h"
#include "manager.h"
#include "string-util.h"
#include "uid-classification.h"
#include "user-util.h"
#include "varlink-dynamic-user.h"
#include "varlink-util.h"

typedef struct LookupParameters {
        const char *user_name;
        const char *group_name;
        union {
                uid_t uid;
                gid_t gid;
        };
        const char *service;
} LookupParameters;

static int build_user_json(const char *user_name, uid_t uid, sd_json_variant **ret) {
        assert(user_name);
        assert(uid_is_valid(uid));
        assert(ret);

        return sd_json_buildo(ret, SD_JSON_BUILD_PAIR("record", SD_JSON_BUILD_OBJECT(
                                       SD_JSON_BUILD_PAIR_STRING("userName", user_name),
                                       SD_JSON_BUILD_PAIR_UNSIGNED("uid", uid),
                                       SD_JSON_BUILD_PAIR_UNSIGNED("gid", uid),
                                       SD_JSON_BUILD_PAIR("realName", JSON_BUILD_CONST_STRING("Dynamic User")),
                                       SD_JSON_BUILD_PAIR("homeDirectory", JSON_BUILD_CONST_STRING("/")),
                                       SD_JSON_BUILD_PAIR("shell", JSON_BUILD_CONST_STRING(NOLOGIN)),
                                       SD_JSON_BUILD_PAIR_BOOLEAN("locked", true),
                                       SD_JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.DynamicUser")),
                                       SD_JSON_BUILD_PAIR("disposition", JSON_BUILD_CONST_STRING("dynamic")))));
}

static bool user_match_lookup_parameters(LookupParameters *p, const char *name, uid_t uid) {
        assert(p);

        if (p->user_name && !streq(name, p->user_name))
                return false;

        if (uid_is_valid(p->uid) && uid != p->uid)
                return false;

        return true;
}

int vl_method_get_user_record(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "uid",      SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uid_gid,            offsetof(LookupParameters, uid),       0             },
                { "userName", SD_JSON_VARIANT_STRING,   json_dispatch_const_user_group_name, offsetof(LookupParameters, user_name), SD_JSON_RELAX },
                { "service",  SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string,       offsetof(LookupParameters, service),   0             },
                {}
        };

        LookupParameters p = {
                .uid = UID_INVALID,
        };
        _cleanup_free_ char *found_name = NULL;
        uid_t found_uid = UID_INVALID, uid;
        Manager *m = ASSERT_PTR(userdata);
        const char *un;
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, "io.systemd.DynamicUser"))
                return sd_varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        r = varlink_set_sentinel(link, "io.systemd.UserDatabase.NoRecordFound");
        if (r < 0)
                return r;

        if (uid_is_valid(p.uid))
                r = dynamic_user_lookup_uid(m, p.uid, &found_name);
        else if (p.user_name)
                r = dynamic_user_lookup_name(m, p.user_name, &found_uid);
        else {
                DynamicUser *d;

                HASHMAP_FOREACH(d, m->dynamic_users) {
                        r = dynamic_user_current(d, &uid);
                        if (r == -EAGAIN) /* not realized yet? */
                                continue;
                        if (r < 0)
                                return r;

                        if (!uid_is_dynamic(uid))
                                continue;

                        if (!user_match_lookup_parameters(&p, d->name, uid))
                                continue;

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                        r = build_user_json(d->name, uid, &v);
                        if (r < 0)
                                return r;

                        r = sd_varlink_reply(link, v);
                        if (r < 0)
                                return r;
                }

                return 0;
        }
        if (r == -ESRCH)
                return 0;
        if (r < 0)
                return r;

        uid = uid_is_valid(found_uid) ? found_uid : p.uid;
        un = found_name ?: p.user_name;

        if (!user_match_lookup_parameters(&p, un, uid))
                return sd_varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = build_user_json(un, uid, &v);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, v);
}

static int build_group_json(const char *group_name, gid_t gid, sd_json_variant **ret) {
        assert(group_name);
        assert(gid_is_valid(gid));
        assert(ret);

        return sd_json_buildo(ret, SD_JSON_BUILD_PAIR("record", SD_JSON_BUILD_OBJECT(
                                       SD_JSON_BUILD_PAIR_STRING("groupName", group_name),
                                       SD_JSON_BUILD_PAIR("description", JSON_BUILD_CONST_STRING("Dynamic Group")),
                                       SD_JSON_BUILD_PAIR_UNSIGNED("gid", gid),
                                       SD_JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.DynamicUser")),
                                       SD_JSON_BUILD_PAIR("disposition", JSON_BUILD_CONST_STRING("dynamic")))));
}

static bool group_match_lookup_parameters(LookupParameters *p, const char *name, gid_t gid) {
        assert(p);

        if (p->group_name && !streq(name, p->group_name))
                return false;

        if (gid_is_valid(p->gid) && gid != p->gid)
                return false;

        return true;
}

int vl_method_get_group_record(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "gid",       SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uid_gid,            offsetof(LookupParameters, gid),        0             },
                { "groupName", SD_JSON_VARIANT_STRING,   json_dispatch_const_user_group_name, offsetof(LookupParameters, group_name), SD_JSON_RELAX },
                { "service",   SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string,       offsetof(LookupParameters, service),    0             },
                {}
        };

        LookupParameters p = {
                .gid = GID_INVALID,
        };
        _cleanup_free_ char *found_name = NULL;
        uid_t found_gid = GID_INVALID, gid;
        Manager *m = ASSERT_PTR(userdata);
        const char *gn;
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = varlink_set_sentinel(link, "io.systemd.UserDatabase.NoRecordFound");
        if (r < 0)
                return r;

        if (!streq_ptr(p.service, "io.systemd.DynamicUser"))
                return sd_varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        if (gid_is_valid(p.gid))
                r = dynamic_user_lookup_uid(m, (uid_t) p.gid, &found_name);
        else if (p.group_name)
                r = dynamic_user_lookup_name(m, p.group_name, &found_gid);
        else {
                DynamicUser *d;

                HASHMAP_FOREACH(d, m->dynamic_users) {
                        uid_t uid;

                        r = dynamic_user_current(d, &uid);
                        if (r == -EAGAIN)
                                continue;
                        if (r < 0)
                                return r;

                        if (!gid_is_dynamic((gid_t) uid))
                                continue;

                        if (!group_match_lookup_parameters(&p, d->name, (gid_t) uid))
                                continue;

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                        r = build_group_json(d->name, (gid_t) uid, &v);
                        if (r < 0)
                                return r;

                        r = sd_varlink_reply(link, v);
                        if (r < 0)
                                return r;
                }

                return 0;
        }
        if (r == -ESRCH)
                return 0;
        if (r < 0)
                return r;

        gid = gid_is_valid(found_gid) ? found_gid : p.gid;
        gn = found_name ?: p.group_name;

        if (!group_match_lookup_parameters(&p, gn, gid))
                return sd_varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = build_group_json(gn, gid, &v);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, v);
}

int vl_method_get_memberships(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "userName",  SD_JSON_VARIANT_STRING, json_dispatch_const_user_group_name, offsetof(LookupParameters, user_name),  SD_JSON_RELAX },
                { "groupName", SD_JSON_VARIANT_STRING, json_dispatch_const_user_group_name, offsetof(LookupParameters, group_name), SD_JSON_RELAX },
                { "service",   SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,       offsetof(LookupParameters, service),    0             },
                {}
        };

        LookupParameters p = {};
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, "io.systemd.DynamicUser"))
                return sd_varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        /* We don't support auxiliary groups with dynamic users. */
        return sd_varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
}
