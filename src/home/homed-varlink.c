/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "group-record.h"
#include "hashmap.h"
#include "homed-home.h"
#include "homed-manager.h"
#include "homed-varlink.h"
#include "json-util.h"
#include "log.h"
#include "string-util.h"
#include "strv.h"
#include "user-record.h"
#include "user-record-util.h"
#include "user-util.h"

typedef struct LookupParameters {
        const char *user_name;
        const char *group_name;
        union {
                uid_t uid;
                gid_t gid;
        };
        const char *service;
} LookupParameters;

static bool client_is_trusted(sd_varlink *link, Home *h) {
        uid_t peer_uid;
        int r;

        assert(link);
        assert(h);

        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0) {
                log_debug_errno(r, "Unable to query peer UID, ignoring: %m");
                return false;
        }

        return peer_uid == 0 || peer_uid == h->uid;
}

static int build_user_json(Home *h, bool trusted, sd_json_variant **ret) {
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

        return sd_json_buildo(ret,
                              SD_JSON_BUILD_PAIR("record", SD_JSON_BUILD_VARIANT(augmented->json)),
                              SD_JSON_BUILD_PAIR("incomplete", SD_JSON_BUILD_BOOLEAN(augmented->incomplete)));
}

static bool home_user_match_lookup_parameters(LookupParameters *p, Home *h) {
        assert(p);
        assert(h);

        if (p->user_name && !user_record_matches_user_name(h->record, p->user_name))
                return false;

        if (uid_is_valid(p->uid) && h->uid != p->uid)
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

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        LookupParameters p = {
                .uid = UID_INVALID,
        };
        Manager *m = ASSERT_PTR(userdata);
        bool trusted;
        Home *h;
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, m->userdb_service))
                return sd_varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        if (uid_is_valid(p.uid))
                h = hashmap_get(m->homes_by_uid, UID_TO_PTR(p.uid));
        else if (p.user_name) {
                r = manager_get_home_by_name(m, p.user_name, &h);
                if (r < 0)
                        return r;
        } else {

                /* If neither UID nor name was specified, then dump all homes. Do so with varlink_notify()
                 * for all entries but the last, so that clients can stream the results, and easily process
                 * them piecemeal. */

                HASHMAP_FOREACH(h, m->homes_by_uid) {

                        if (!home_user_match_lookup_parameters(&p, h))
                                continue;

                        if (v) {
                                /* An entry set from the previous iteration? Then send it now */
                                r = sd_varlink_notify(link, v);
                                if (r < 0)
                                        return r;

                                v = sd_json_variant_unref(v);
                        }

                        trusted = client_is_trusted(link, h);

                        r = build_user_json(h, trusted, &v);
                        if (r < 0)
                                return r;
                }

                if (!v)
                        return sd_varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

                return sd_varlink_reply(link, v);
        }

        if (!h)
                return sd_varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

        if (!home_user_match_lookup_parameters(&p, h))
                return sd_varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        trusted = client_is_trusted(link, h);

        r = build_user_json(h, trusted, &v);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, v);
}

static int build_group_json(Home *h, sd_json_variant **ret) {
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

        return sd_json_buildo(ret, SD_JSON_BUILD_PAIR("record", SD_JSON_BUILD_VARIANT(g->json)));
}

static bool home_group_match_lookup_parameters(LookupParameters *p, Home *h) {
        assert(p);
        assert(h);

        if (p->group_name && !user_record_matches_user_name(h->record, p->group_name))
                return false;

        if (gid_is_valid(p->gid) && h->uid != (uid_t) p->gid)
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

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        LookupParameters p = {
                .gid = GID_INVALID,
        };
        Manager *m = ASSERT_PTR(userdata);
        Home *h;
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, m->userdb_service))
                return sd_varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        if (gid_is_valid(p.gid))
                h = hashmap_get(m->homes_by_uid, UID_TO_PTR((uid_t) p.gid));
        else if (p.group_name) {
                r = manager_get_home_by_name(m, p.group_name, &h);
                if (r < 0)
                        return r;
        } else {

                HASHMAP_FOREACH(h, m->homes_by_uid) {

                        if (!home_group_match_lookup_parameters(&p, h))
                                continue;

                        if (v) {
                                r = sd_varlink_notify(link, v);
                                if (r < 0)
                                        return r;

                                v = sd_json_variant_unref(v);
                        }

                        r = build_group_json(h, &v);
                        if (r < 0)
                                return r;
                }

                if (!v)
                        return sd_varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

                return sd_varlink_reply(link, v);
        }

        if (!h)
                return sd_varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

        if (!home_group_match_lookup_parameters(&p, h))
                return sd_varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        r = build_group_json(h, &v);
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

        Manager *m = ASSERT_PTR(userdata);
        LookupParameters p = {};
        Home *h;
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, m->userdb_service))
                return sd_varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        if (p.user_name) {
                const char *last = NULL;

                r = manager_get_home_by_name(m, p.user_name, &h);
                if (r < 0)
                        return r;
                if (!h)
                        return sd_varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

                if (p.group_name) {
                        if (!strv_contains(h->record->member_of, p.group_name))
                                return sd_varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

                        return sd_varlink_replybo(
                                        link,
                                        SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(h->user_name)),
                                        SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(p.group_name)));
                }

                STRV_FOREACH(i, h->record->member_of) {
                        if (last) {
                                r = sd_varlink_notifybo(
                                                link,
                                                SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(h->user_name)),
                                                SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(last)));
                                if (r < 0)
                                        return r;
                        }

                        last = *i;
                }

                if (last)
                        return sd_varlink_replybo(
                                        link,
                                        SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(h->user_name)),
                                        SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(last)));

        } else if (p.group_name) {
                const char *last = NULL;

                HASHMAP_FOREACH(h, m->homes_by_uid) {

                        if (!strv_contains(h->record->member_of, p.group_name))
                                continue;

                        if (last) {
                                r = sd_varlink_notifybo(
                                                link,
                                                SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(last)),
                                                SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(p.group_name)));
                                if (r < 0)
                                        return r;
                        }

                        last = h->user_name;
                }

                if (last)
                        return sd_varlink_replybo(
                                        link,
                                        SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(last)),
                                        SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(p.group_name)));
        } else {
                const char *last_user_name = NULL, *last_group_name = NULL;

                HASHMAP_FOREACH(h, m->homes_by_uid)
                        STRV_FOREACH(j, h->record->member_of) {

                                if (last_user_name) {
                                        assert(last_group_name);

                                        r = sd_varlink_notifybo(
                                                        link,
                                                        SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(last_user_name)),
                                                        SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(last_group_name)));

                                        if (r < 0)
                                                return r;
                                }

                                last_user_name = h->user_name;
                                last_group_name = *j;
                        }

                if (last_user_name) {
                        assert(last_group_name);
                        return sd_varlink_replybo(
                                        link,
                                        SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(last_user_name)),
                                        SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(last_group_name)));
                }
        }

        return sd_varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
}
