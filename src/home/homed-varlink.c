/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "group-record.h"
#include "homed-varlink.h"
#include "strv.h"
#include "user-record-util.h"
#include "user-record.h"
#include "user-util.h"
#include "format-util.h"

typedef struct LookupParameters {
        const char *user_name;
        const char *group_name;
        union {
                uid_t uid;
                gid_t gid;
        };
        const char *service;
} LookupParameters;

static bool client_is_trusted(Varlink *link, Home *h) {
        uid_t peer_uid;
        int r;

        assert(link);
        assert(h);

        r = varlink_get_peer_uid(link, &peer_uid);
        if (r < 0) {
                log_debug_errno(r, "Unable to query peer UID, ignoring: %m");
                return false;
        }

        return peer_uid == 0 || peer_uid == h->uid;
}

static int build_user_json(Home *h, bool trusted, JsonVariant **ret) {
        _cleanup_(user_record_unrefp) UserRecord *augmented = NULL;
        UserRecordLoadFlags flags;
        int r;

        assert(h);
        assert(ret);

        flags = USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_BINDING|USER_RECORD_STRIP_SECRET|USER_RECORD_ALLOW_STATUS|USER_RECORD_ALLOW_SIGNATURE|USER_RECORD_PERMISSIVE;
        if (trusted)
                flags |= USER_RECORD_ALLOW_PRIVILEGED;
        else
                flags |= USER_RECORD_STRIP_PRIVILEGED;

        r = home_augment_status(h, flags, &augmented);
        if (r < 0)
                return r;

        return json_build(ret, JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("record", JSON_BUILD_VARIANT(augmented->json)),
                                          JSON_BUILD_PAIR("incomplete", JSON_BUILD_BOOLEAN(augmented->incomplete))));
}

static bool home_user_match_lookup_parameters(LookupParameters *p, Home *h) {
        assert(p);
        assert(h);

        if (p->user_name && !streq(p->user_name, h->user_name))
                return false;

        if (uid_is_valid(p->uid) && h->uid != p->uid)
                return false;

        return true;
}

int vl_method_get_user_record(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "uid",            JSON_VARIANT_UNSIGNED, json_dispatch_uid_gid,      offsetof(LookupParameters, uid),       0         },
                { "userName",       JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(LookupParameters, user_name), JSON_SAFE },
                { "service",        JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(LookupParameters, service),   0         },
                {}
        };

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        LookupParameters p = {
                .uid = UID_INVALID,
        };
        Manager *m = ASSERT_PTR(userdata);
        bool trusted;
        Home *h;
        int r;

        assert(parameters);

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, m->userdb_service))
                return varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        if (uid_is_valid(p.uid))
                h = hashmap_get(m->homes_by_uid, UID_TO_PTR(p.uid));
        else if (p.user_name)
                h = hashmap_get(m->homes_by_name, p.user_name);
        else {

                /* If neither UID nor name was specified, then dump all homes. Do so with varlink_notify()
                 * for all entries but the last, so that clients can stream the results, and easily process
                 * them piecemeal. */

                HASHMAP_FOREACH(h, m->homes_by_name) {

                        if (!home_user_match_lookup_parameters(&p, h))
                                continue;

                        if (v) {
                                /* An entry set from the previous iteration? Then send it now */
                                r = varlink_notify(link, v);
                                if (r < 0)
                                        return r;

                                v = json_variant_unref(v);
                        }

                        trusted = client_is_trusted(link, h);

                        r = build_user_json(h, trusted, &v);
                        if (r < 0)
                                return r;
                }

                if (!v)
                        return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

                return varlink_reply(link, v);
        }

        if (!h)
                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

        if (!home_user_match_lookup_parameters(&p, h))
                return varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        trusted = client_is_trusted(link, h);

        r = build_user_json(h, trusted, &v);
        if (r < 0)
                return r;

        return varlink_reply(link, v);
}

static int build_group_json(Home *h, JsonVariant **ret) {
        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;
        int r;

        assert(h);
        assert(ret);

        g = group_record_new();
        if (!g)
                return -ENOMEM;

        r = group_record_synthesize(g, h->record);
        if (r < 0)
                return r;

        assert(!FLAGS_SET(g->mask, USER_RECORD_SECRET));
        assert(!FLAGS_SET(g->mask, USER_RECORD_PRIVILEGED));

        return json_build(ret,
                          JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("record", JSON_BUILD_VARIANT(g->json))));
}

static bool home_group_match_lookup_parameters(LookupParameters *p, Home *h) {
        assert(p);
        assert(h);

        if (p->group_name && !streq(h->user_name, p->group_name))
                return false;

        if (gid_is_valid(p->gid) && h->uid != (uid_t) p->gid)
                return false;

        return true;
}

int vl_method_get_group_record(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

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
        Manager *m = ASSERT_PTR(userdata);
        Home *h;
        int r;

        assert(parameters);

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, m->userdb_service))
                return varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        if (gid_is_valid(p.gid))
                h = hashmap_get(m->homes_by_uid, UID_TO_PTR((uid_t) p.gid));
        else if (p.group_name)
                h = hashmap_get(m->homes_by_name, p.group_name);
        else {

                HASHMAP_FOREACH(h, m->homes_by_name) {

                        if (!home_group_match_lookup_parameters(&p, h))
                                continue;

                        if (v) {
                                r = varlink_notify(link, v);
                                if (r < 0)
                                        return r;

                                v = json_variant_unref(v);
                        }

                        r = build_group_json(h, &v);
                        if (r < 0)
                                return r;
                }

                if (!v)
                        return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

                return varlink_reply(link, v);
        }

        if (!h)
                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

        if (!home_group_match_lookup_parameters(&p, h))
                return varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        r = build_group_json(h, &v);
        if (r < 0)
                return r;

        return varlink_reply(link, v);
}

int vl_method_get_memberships(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "userName",  JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, user_name),  JSON_SAFE },
                { "groupName", JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, group_name), JSON_SAFE },
                { "service",   JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, service),    0         },
                {}
        };

        Manager *m = ASSERT_PTR(userdata);
        LookupParameters p = {};
        Home *h;
        int r;

        assert(parameters);

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, m->userdb_service))
                return varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        if (p.user_name) {
                const char *last = NULL;

                h = hashmap_get(m->homes_by_name, p.user_name);
                if (!h)
                        return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

                if (p.group_name) {
                        if (!strv_contains(h->record->member_of, p.group_name))
                                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

                        return varlink_replyb(link, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(h->user_name)),
                                                                      JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(p.group_name))));
                }

                STRV_FOREACH(i, h->record->member_of) {
                        if (last) {
                                r = varlink_notifyb(link, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(h->user_name)),
                                                                            JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(last))));
                                if (r < 0)
                                        return r;
                        }

                        last = *i;
                }

                if (last)
                        return varlink_replyb(link, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(h->user_name)),
                                                                      JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(last))));

        } else if (p.group_name) {
                const char *last = NULL;

                HASHMAP_FOREACH(h, m->homes_by_name) {

                        if (!strv_contains(h->record->member_of, p.group_name))
                                continue;

                        if (last) {
                                r = varlink_notifyb(link, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(last)),
                                                                            JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(p.group_name))));
                                if (r < 0)
                                        return r;
                        }

                        last = h->user_name;
                }

                if (last)
                        return varlink_replyb(link, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(last)),
                                                                      JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(p.group_name))));
        } else {
                const char *last_user_name = NULL, *last_group_name = NULL;

                HASHMAP_FOREACH(h, m->homes_by_name)
                        STRV_FOREACH(j, h->record->member_of) {

                                if (last_user_name) {
                                        assert(last_group_name);

                                        r = varlink_notifyb(link, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(last_user_name)),
                                                                                    JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(last_group_name))));

                                        if (r < 0)
                                                return r;
                                }

                                last_user_name = h->user_name;
                                last_group_name = *j;
                        }

                if (last_user_name) {
                        assert(last_group_name);
                        return varlink_replyb(link, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(last_user_name)),
                                                                      JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(last_group_name))));
                }
        }

        return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
}
