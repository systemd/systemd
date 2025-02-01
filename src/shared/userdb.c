/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/auxv.h>

#include "sd-varlink.h"

#include "bitfield.h"
#include "conf-files.h"
#include "dirent-util.h"
#include "dlfcn-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "json-util.h"
#include "missing_syscall.h"
#include "parse-util.h"
#include "set.h"
#include "socket-util.h"
#include "strv.h"
#include "uid-classification.h"
#include "user-record-nss.h"
#include "user-util.h"
#include "userdb.h"
#include "userdb-dropin.h"

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(link_hash_ops, void, trivial_hash_func, trivial_compare_func, sd_varlink, sd_varlink_unref);

typedef enum LookupWhat {
        LOOKUP_USER,
        LOOKUP_GROUP,
        LOOKUP_MEMBERSHIP,
        _LOOKUP_WHAT_MAX,
} LookupWhat;

struct UserDBIterator {
        LookupWhat what;
        UserDBFlags flags;
        Set *links;

        const char *method; /* Note, this is a const static string! */
        sd_json_variant *query;

        bool more:1;
        bool nss_covered:1;
        bool nss_iterating:1;
        bool dropin_covered:1;
        bool synthesize_root:1;
        bool synthesize_nobody:1;
        bool nss_systemd_blocked:1;

        char **dropins;
        size_t current_dropin;
        int error;
        unsigned n_found;

        sd_event *event;
        UserRecord *found_user;                   /* when .what == LOOKUP_USER */
        GroupRecord *found_group;                 /* when .what == LOOKUP_GROUP */

        char *found_user_name, *found_group_name; /* when .what == LOOKUP_MEMBERSHIP */
        char **members_of_group;
        size_t index_members_of_group;
        char *filter_user_name, *filter_group_name;
};

static int userdb_connect(UserDBIterator *iterator, const char *path, const char *method, bool more, sd_json_variant *query);

UserDBIterator* userdb_iterator_free(UserDBIterator *iterator) {
        if (!iterator)
                return NULL;

        sd_json_variant_unref(iterator->query);

        set_free(iterator->links);
        strv_free(iterator->dropins);

        switch (iterator->what) {

        case LOOKUP_USER:
                user_record_unref(iterator->found_user);

                if (iterator->nss_iterating)
                        endpwent();

                break;

        case LOOKUP_GROUP:
                group_record_unref(iterator->found_group);

                if (iterator->nss_iterating)
                        endgrent();

                break;

        case LOOKUP_MEMBERSHIP:
                free(iterator->found_user_name);
                free(iterator->found_group_name);
                strv_free(iterator->members_of_group);
                free(iterator->filter_user_name);
                free(iterator->filter_group_name);

                if (iterator->nss_iterating)
                        endgrent();

                break;

        default:
                assert_not_reached();
        }

        sd_event_unref(iterator->event);

        if (iterator->nss_systemd_blocked)
                assert_se(userdb_block_nss_systemd(false) >= 0);

        return mfree(iterator);
}

static UserDBIterator* userdb_iterator_new(LookupWhat what, UserDBFlags flags) {
        UserDBIterator *i;

        assert(what >= 0);
        assert(what < _LOOKUP_WHAT_MAX);

        i = new(UserDBIterator, 1);
        if (!i)
                return NULL;

        *i = (UserDBIterator) {
                .what = what,
                .flags = flags,
                .synthesize_root = !FLAGS_SET(flags, USERDB_DONT_SYNTHESIZE_INTRINSIC),
                .synthesize_nobody = !FLAGS_SET(flags, USERDB_DONT_SYNTHESIZE_INTRINSIC),
        };

        return i;
}

static int userdb_iterator_block_nss_systemd(UserDBIterator *iterator) {
        int r;

        assert(iterator);

        if (iterator->nss_systemd_blocked)
                return 0;

        r = userdb_block_nss_systemd(true);
        if (r < 0)
                return r;

        iterator->nss_systemd_blocked = true;
        return 1;
}

struct user_group_data {
        sd_json_variant *record;
        bool incomplete;
};

static void user_group_data_done(struct user_group_data *d) {
        sd_json_variant_unref(d->record);
}

struct membership_data {
        char *user_name;
        char *group_name;
};

static void membership_data_done(struct membership_data *d) {
        free(d->user_name);
        free(d->group_name);
}

static int userdb_maybe_restart_query(
                UserDBIterator *iterator,
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id) {

        int r;

        assert(iterator);
        assert(link);
        assert(error_id);

        /* These fields were added in v258 and didn't exist in previous implementations. Hence, we consider
         * their support optional: if any service refuses any of these fields, we'll restart the query
         * without them, and apply the filtering they are supposed to do client side. */
        static const char *const fields[] = {
                "fuzzyNames",
                "dispositionMask",
                "uidMin",
                "uidMax",
                "gidMin",
                "gidMax",
                NULL
        };

        /* Figure out if the reported error indicates any of the suppressible fields are at fault, and that
         * our query actually included them */
        bool restart = false;
        STRV_FOREACH(f, fields) {
                if (!sd_varlink_error_is_invalid_parameter(error_id, parameters, *f))
                        continue;

                if (!sd_json_variant_by_key(iterator->query, *f))
                        continue;

                restart = true;
                break;
        }

        if (!restart)
                return 0;

        /* Now patch the fields out */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *patched_query =
                sd_json_variant_ref(iterator->query);

        r = sd_json_variant_filter(&patched_query, (char**const) fields);
        if (r < 0)
                return r;

        /* NB: we stored the socket path in the varlink connection description when we set things up here! */
        r = userdb_connect(
                        iterator,
                        ASSERT_PTR(sd_varlink_get_description(link)),
                        iterator->method,
                        iterator->more,
                        patched_query);
        if (r < 0)
                return r;

        log_debug("Restarted query to service '%s' due to missing features.", sd_varlink_get_description(link));
        return 1;
}

static int userdb_on_query_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        UserDBIterator *iterator = ASSERT_PTR(userdata);
        int r;

        if (error_id) {
                log_debug("Got lookup error: %s", error_id);

                r = userdb_maybe_restart_query(iterator, link, parameters, error_id);
                if (r < 0)
                        return r;
                if (r > 0) {
                        r = 0;
                        goto finish;
                }

                /* Convert various forms of record not found into -ESRCH, since NSS typically doesn't care,
                 * about the details. Note that if a userName specification is refused as invalid parameter,
                 * we also turn this into -ESRCH following the logic that there cannot be a user record for a
                 * completely invalid user name. */
                if (STR_IN_SET(error_id,
                               "io.systemd.UserDatabase.NoRecordFound",
                               "io.systemd.UserDatabase.ConflictingRecordFound") ||
                    sd_varlink_error_is_invalid_parameter(error_id, parameters, "userName") ||
                    sd_varlink_error_is_invalid_parameter(error_id, parameters, "groupName"))
                        r = -ESRCH;
                else if (streq(error_id, "io.systemd.UserDatabase.NonMatchingRecordFound"))
                        r = -ENOEXEC;
                else if (streq(error_id, "io.systemd.UserDatabase.ServiceNotAvailable"))
                        r = -EHOSTDOWN;
                else if (streq(error_id, "io.systemd.UserDatabase.EnumerationNotSupported"))
                        r = -EOPNOTSUPP;
                else if (streq(error_id, SD_VARLINK_ERROR_TIMEOUT))
                        r = -ETIMEDOUT;
                else
                        r = -EIO;

                goto finish;
        }

        switch (iterator->what) {

        case LOOKUP_USER: {
                _cleanup_(user_group_data_done) struct user_group_data user_data = {};

                static const sd_json_dispatch_field dispatch_table[] = {
                        { "record",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_variant, offsetof(struct user_group_data, record),     0 },
                        { "incomplete", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool, offsetof(struct user_group_data, incomplete), 0 },
                        {}
                };
                _cleanup_(user_record_unrefp) UserRecord *hr = NULL;

                assert_se(!iterator->found_user);

                r = sd_json_dispatch(parameters, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &user_data);
                if (r < 0)
                        goto finish;

                if (!user_data.record) {
                        r = log_debug_errno(SYNTHETIC_ERRNO(EIO), "Reply is missing record key");
                        goto finish;
                }

                hr = user_record_new();
                if (!hr) {
                        r = -ENOMEM;
                        goto finish;
                }

                r = user_record_load(hr, user_data.record, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_PERMISSIVE);
                if (r < 0)
                        goto finish;

                if (!hr->service) {
                        r = log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "User record does not carry service information, refusing.");
                        goto finish;
                }

                hr->incomplete = user_data.incomplete;

                /* We match the root user by the name since the name is our primary key. We match the nobody
                 * use by UID though, since the name might differ on OSes */
                if (streq_ptr(hr->user_name, "root"))
                        iterator->synthesize_root = false;
                if (hr->uid == UID_NOBODY)
                        iterator->synthesize_nobody = false;

                iterator->found_user = TAKE_PTR(hr);
                iterator->n_found++;

                /* More stuff coming? then let's just exit cleanly here */
                if (FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES))
                        return 0;

                /* Otherwise, let's remove this link and exit cleanly then */
                r = 0;
                goto finish;
        }

        case LOOKUP_GROUP: {
                _cleanup_(user_group_data_done) struct user_group_data group_data = {};

                static const sd_json_dispatch_field dispatch_table[] = {
                        { "record",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_variant, offsetof(struct user_group_data, record),     0 },
                        { "incomplete", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool, offsetof(struct user_group_data, incomplete), 0 },
                        {}
                };
                _cleanup_(group_record_unrefp) GroupRecord *g = NULL;

                assert_se(!iterator->found_group);

                r = sd_json_dispatch(parameters, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &group_data);
                if (r < 0)
                        goto finish;

                if (!group_data.record) {
                        r = log_debug_errno(SYNTHETIC_ERRNO(EIO), "Reply is missing record key");
                        goto finish;
                }

                g = group_record_new();
                if (!g) {
                        r = -ENOMEM;
                        goto finish;
                }

                r = group_record_load(g, group_data.record, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_PERMISSIVE);
                if (r < 0)
                        goto finish;

                if (!g->service) {
                        r = log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Group record does not carry service information, refusing.");
                        goto finish;
                }

                g->incomplete = group_data.incomplete;

                if (streq_ptr(g->group_name, "root"))
                        iterator->synthesize_root = false;
                if (g->gid == GID_NOBODY)
                        iterator->synthesize_nobody = false;

                iterator->found_group = TAKE_PTR(g);
                iterator->n_found++;

                if (FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES))
                        return 0;

                r = 0;
                goto finish;
        }

        case LOOKUP_MEMBERSHIP: {
                _cleanup_(membership_data_done) struct membership_data membership_data = {};

                static const sd_json_dispatch_field dispatch_table[] = {
                        { "userName",  SD_JSON_VARIANT_STRING, json_dispatch_user_group_name, offsetof(struct membership_data, user_name),  SD_JSON_RELAX },
                        { "groupName", SD_JSON_VARIANT_STRING, json_dispatch_user_group_name, offsetof(struct membership_data, group_name), SD_JSON_RELAX },
                        {}
                };

                assert(!iterator->found_user_name);
                assert(!iterator->found_group_name);

                r = sd_json_dispatch(parameters, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &membership_data);
                if (r < 0)
                        goto finish;

                iterator->found_user_name = TAKE_PTR(membership_data.user_name);
                iterator->found_group_name = TAKE_PTR(membership_data.group_name);
                iterator->n_found++;

                if (FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES))
                        return 0;

                r = 0;
                goto finish;
        }

        default:
                assert_not_reached();
        }

finish:
        /* If we got one ESRCH or ENOEXEC, let that win. This way when we do a wild dump we won't be tripped
         * up by bad errors – as long as at least one connection ended somewhat cleanly */
        if (IN_SET(r, -ESRCH, -ENOEXEC) || iterator->error == 0)
                iterator->error = -r;

        assert_se(set_remove(iterator->links, link) == link);
        link = sd_varlink_unref(link);
        return 0;
}

static int userdb_connect(
                UserDBIterator *iterator,
                const char *path,
                const char *method,
                bool more,
                sd_json_variant *query) {

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        assert(iterator);
        assert(path);
        assert(method);

        r = sd_varlink_connect_address(&vl, path);
        if (r < 0)
                return log_debug_errno(r, "Unable to connect to %s: %m", path);

        sd_varlink_set_userdata(vl, iterator);

        if (!iterator->event) {
                r = sd_event_new(&iterator->event);
                if (r < 0)
                        return log_debug_errno(r, "Unable to allocate event loop: %m");
        }

        r = sd_varlink_attach_event(vl, iterator->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_debug_errno(r, "Failed to attach varlink connection to event loop: %m");

        /* Note, this is load bearing: we store the socket path as description for the varlink
         * connection. That's not just good for debugging, but we reuse this information in case we need to
         * reissue the query with a reduced set of parameters. */
        r = sd_varlink_set_description(vl, path);
        if (r < 0)
                return log_debug_errno(r, "Failed to set varlink connection description: %m");

        r = sd_varlink_bind_reply(vl, userdb_on_query_reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to bind reply callback: %m");

        _cleanup_free_ char *service = NULL;
        r = path_extract_filename(path, &service);
        if (r < 0)
                return log_debug_errno(r, "Failed to extract service name from socket path: %m");
        assert(r != O_DIRECTORY);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *patched_query = sd_json_variant_ref(query);
        r = sd_json_variant_set_field_string(&patched_query, "service", service);
        if (r < 0)
                return log_debug_errno(r, "Unable to set service JSON field: %m");

        if (more)
                r = sd_varlink_observe(vl, method, patched_query);
        else
                r = sd_varlink_invoke(vl, method, patched_query);
        if (r < 0)
                return log_debug_errno(r, "Failed to invoke varlink method: %m");

        r = set_ensure_consume(&iterator->links, &link_hash_ops, TAKE_PTR(vl));
        if (r < 0)
                return log_debug_errno(r, "Failed to add varlink connection to set: %m");
        return r;
}

static int userdb_start_query(
                UserDBIterator *iterator,
                const char *method, /* must be a static string, we are not going to copy this here! */
                bool more,
                sd_json_variant *query,
                UserDBFlags flags) {

        _cleanup_strv_free_ char **except = NULL, **only = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        const char *e;
        int r, ret = 0;

        assert(iterator);
        assert(method);

        if (FLAGS_SET(flags, USERDB_EXCLUDE_VARLINK))
                return -ENOLINK;

        assert(!iterator->query);
        iterator->method = method; /* note: we don't make a copy here! */
        iterator->query = sd_json_variant_ref(query);
        iterator->more = more;

        e = getenv("SYSTEMD_BYPASS_USERDB");
        if (e) {
                r = parse_boolean(e);
                if (r > 0)
                        return -ENOLINK;
                if (r < 0) {
                        except = strv_split(e, ":");
                        if (!except)
                                return -ENOMEM;
                }
        }

        e = getenv("SYSTEMD_ONLY_USERDB");
        if (e) {
                only = strv_split(e, ":");
                if (!only)
                        return -ENOMEM;
        }

        /* First, let's talk to the multiplexer, if we can */
        if ((flags & (USERDB_AVOID_MULTIPLEXER|USERDB_EXCLUDE_DYNAMIC_USER|USERDB_EXCLUDE_NSS|USERDB_EXCLUDE_DROPIN|USERDB_DONT_SYNTHESIZE_INTRINSIC|USERDB_DONT_SYNTHESIZE_FOREIGN)) == 0 &&
            !strv_contains(except, "io.systemd.Multiplexer") &&
            (!only || strv_contains(only, "io.systemd.Multiplexer"))) {
                r = userdb_connect(iterator, "/run/systemd/userdb/io.systemd.Multiplexer", method, more, query);
                if (r >= 0) {
                        iterator->nss_covered = true; /* The multiplexer does NSS */
                        iterator->dropin_covered = true; /* It also handles drop-in stuff */
                        return 0;
                }
        }

        d = opendir("/run/systemd/userdb/");
        if (!d) {
                if (errno == ENOENT)
                        return -ESRCH;

                return -errno;
        }

        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_free_ char *p = NULL;
                bool is_nss, is_dropin;

                if (streq(de->d_name, "io.systemd.Multiplexer")) /* We already tried this above, don't try this again */
                        continue;

                if (FLAGS_SET(flags, USERDB_EXCLUDE_DYNAMIC_USER) &&
                    streq(de->d_name, "io.systemd.DynamicUser"))
                        continue;

                /* Avoid NSS if this is requested. Note that we also skip NSS when we were asked to skip the
                 * multiplexer, since in that case it's safer to do NSS in the client side emulation below
                 * (and when we run as part of systemd-userdbd.service we don't want to talk to ourselves
                 * anyway). */
                is_nss = streq(de->d_name, "io.systemd.NameServiceSwitch");
                if ((flags & (USERDB_EXCLUDE_NSS|USERDB_AVOID_MULTIPLEXER)) && is_nss)
                        continue;

                /* Similar for the drop-in service */
                is_dropin = streq(de->d_name, "io.systemd.DropIn");
                if ((flags & (USERDB_EXCLUDE_DROPIN|USERDB_AVOID_MULTIPLEXER)) && is_dropin)
                        continue;

                if (strv_contains(except, de->d_name))
                        continue;

                if (only && !strv_contains(only, de->d_name))
                        continue;

                p = path_join("/run/systemd/userdb/", de->d_name);
                if (!p)
                        return -ENOMEM;

                r = userdb_connect(iterator, p, method, more, query);
                if (is_nss && r >= 0) /* Turn off fallback NSS + dropin if we found the NSS/dropin service
                                       * and could connect to it */
                        iterator->nss_covered = true;
                if (is_dropin && r >= 0)
                        iterator->dropin_covered = true;

                if (ret == 0 && r < 0)
                        ret = r;
        }

        if (set_isempty(iterator->links))
                return ret < 0 ? ret : -ESRCH; /* propagate last error we saw if we couldn't connect to anything. */

        /* We connected to some services, in this case, ignore the ones we failed on */
        return 0;
}

static int userdb_process(
                UserDBIterator *iterator,
                UserRecord **ret_user_record,
                GroupRecord **ret_group_record,
                char **ret_user_name,
                char **ret_group_name) {

        int r;

        assert(iterator);

        for (;;) {
                if (iterator->what == LOOKUP_USER && iterator->found_user) {
                        if (ret_user_record)
                                *ret_user_record = TAKE_PTR(iterator->found_user);
                        else
                                iterator->found_user = user_record_unref(iterator->found_user);

                        if (ret_group_record)
                                *ret_group_record = NULL;
                        if (ret_user_name)
                                *ret_user_name = NULL;
                        if (ret_group_name)
                                *ret_group_name = NULL;

                        return 0;
                }

                if (iterator->what == LOOKUP_GROUP && iterator->found_group) {
                        if (ret_group_record)
                                *ret_group_record = TAKE_PTR(iterator->found_group);
                        else
                                iterator->found_group = group_record_unref(iterator->found_group);

                        if (ret_user_record)
                                *ret_user_record = NULL;
                        if (ret_user_name)
                                *ret_user_name = NULL;
                        if (ret_group_name)
                                *ret_group_name = NULL;

                        return 0;
                }

                if (iterator->what == LOOKUP_MEMBERSHIP && iterator->found_user_name && iterator->found_group_name) {
                        if (ret_user_name)
                                *ret_user_name = TAKE_PTR(iterator->found_user_name);
                        else
                                iterator->found_user_name = mfree(iterator->found_user_name);

                        if (ret_group_name)
                                *ret_group_name = TAKE_PTR(iterator->found_group_name);
                        else
                                iterator->found_group_name = mfree(iterator->found_group_name);

                        if (ret_user_record)
                                *ret_user_record = NULL;
                        if (ret_group_record)
                                *ret_group_record = NULL;

                        return 0;
                }

                if (set_isempty(iterator->links)) {
                        if (iterator->error == 0)
                                return -ESRCH;

                        return -abs(iterator->error);
                }

                if (!iterator->event)
                        return -ESRCH;

                r = sd_event_run(iterator->event, UINT64_MAX);
                if (r < 0)
                        return r;
        }
}

static int synthetic_root_user_build(UserRecord **ret) {
        return user_record_build(
                        ret,
                        SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("userName", JSON_BUILD_CONST_STRING("root")),
                                          SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(0)),
                                          SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(0)),
                                          SD_JSON_BUILD_PAIR("homeDirectory", JSON_BUILD_CONST_STRING("/root")),
                                          SD_JSON_BUILD_PAIR("disposition", JSON_BUILD_CONST_STRING("intrinsic"))));
}

static int synthetic_nobody_user_build(UserRecord **ret) {
        return user_record_build(
                        ret,
                        SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("userName", JSON_BUILD_CONST_STRING(NOBODY_USER_NAME)),
                                          SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(UID_NOBODY)),
                                          SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(GID_NOBODY)),
                                          SD_JSON_BUILD_PAIR("shell", JSON_BUILD_CONST_STRING(NOLOGIN)),
                                          SD_JSON_BUILD_PAIR("locked", SD_JSON_BUILD_BOOLEAN(true)),
                                          SD_JSON_BUILD_PAIR("disposition", JSON_BUILD_CONST_STRING("intrinsic"))));
}

static int synthetic_foreign_user_build(uid_t foreign_uid, UserRecord **ret) {
        assert(ret);

        if (!uid_is_valid(foreign_uid))
                return -ESRCH;
        if (foreign_uid > 0xFFFF)
                return -ESRCH;

        _cleanup_free_ char *un = NULL;
        if (asprintf(&un, "foreign-" UID_FMT, foreign_uid) < 0)
                return -ENOMEM;

        _cleanup_free_ char *rn = NULL;
        if (asprintf(&rn, "Foreign System Image UID " UID_FMT, foreign_uid) < 0)
                return -ENOMEM;

        return user_record_build(
                        ret,
                        SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(un)),
                                        SD_JSON_BUILD_PAIR("realName", SD_JSON_BUILD_STRING(rn)),
                                        SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(FOREIGN_UID_BASE + foreign_uid)),
                                        SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(FOREIGN_UID_BASE + foreign_uid)),
                                        SD_JSON_BUILD_PAIR("shell", JSON_BUILD_CONST_STRING(NOLOGIN)),
                                        SD_JSON_BUILD_PAIR("locked", SD_JSON_BUILD_BOOLEAN(true)),
                                        SD_JSON_BUILD_PAIR("disposition", JSON_BUILD_CONST_STRING("foreign"))));
}

static int user_name_foreign_extract_uid(const char *name, uid_t *ret_uid) {
        int r;

        assert(name);
        assert(ret_uid);

        /* Parses the inner UID from a user name of the foreign UID range, in the form "foreign-NNN". Returns
         * > 0 if that worked, 0 if it didn't. */

        const char *e = startswith(name, "foreign-");
        if (!e)
                goto nomatch;

        uid_t uid;
        r = parse_uid(e, &uid);
        if (r < 0)
                goto nomatch;

        if (uid > 0xFFFF)
                goto nomatch;

        *ret_uid = uid;
        return 1;

nomatch:
        *ret_uid = UID_INVALID;
        return 0;
}

static int query_append_disposition_mask(sd_json_variant **query, uint64_t mask) {
        int r;

        assert(query);

        if (FLAGS_SET(mask, USER_DISPOSITION_MASK_ALL))
                return 0;

        _cleanup_strv_free_ char **dispositions = NULL;
        for (UserDisposition d = 0; d < _USER_DISPOSITION_MAX; d++) {
                if (!BITS_SET(mask, d))
                        continue;

                r = strv_extend(&dispositions, user_disposition_to_string(d));
                if (r < 0)
                        return r;
        }

        return sd_json_variant_merge_objectbo(
                        query,
                        SD_JSON_BUILD_PAIR_STRV("dispositionMask", dispositions));
}

static int query_append_uid_match(sd_json_variant **query, const UserDBMatch *match) {
        int r;

        assert(query);

        if (!userdb_match_is_set(match))
                return 0;

        r = sd_json_variant_merge_objectbo(
                        query,
                        SD_JSON_BUILD_PAIR_CONDITION(!strv_isempty(match->fuzzy_names), "fuzzyNames", SD_JSON_BUILD_STRV(match->fuzzy_names)),
                        SD_JSON_BUILD_PAIR_CONDITION(match->uid_min > 0, "uidMin", SD_JSON_BUILD_UNSIGNED(match->uid_min)),
                        SD_JSON_BUILD_PAIR_CONDITION(match->uid_max < UID_INVALID-1, "uidMax", SD_JSON_BUILD_UNSIGNED(match->uid_max)));
        if (r < 0)
                return r;

        return query_append_disposition_mask(query, match->disposition_mask);
}

static int userdb_by_name_fallbacks(
                const char *name,
                UserDBIterator *iterator,
                UserDBFlags flags,
                UserRecord **ret) {
        int r;

        assert(name);
        assert(iterator);
        assert(ret);

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_DROPIN) && !iterator->dropin_covered) {
                r = dropin_user_record_by_name(name, /* path= */ NULL, flags, ret);
                if (r >= 0)
                        return r;
        }

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_NSS) && !iterator->nss_covered) {
                /* Make sure the NSS lookup doesn't recurse back to us. */

                r = userdb_iterator_block_nss_systemd(iterator);
                if (r >= 0) {
                        /* Client-side NSS fallback */
                        r = nss_user_record_by_name(name, !FLAGS_SET(flags, USERDB_SUPPRESS_SHADOW), ret);
                        if (r >= 0)
                                return r;
                }
        }

        if (!FLAGS_SET(flags, USERDB_DONT_SYNTHESIZE_INTRINSIC)) {
                if (streq(name, "root"))
                        return synthetic_root_user_build(ret);

                if (streq(name, NOBODY_USER_NAME) && synthesize_nobody())
                        return synthetic_nobody_user_build(ret);
        }

        if (!FLAGS_SET(flags, USERDB_DONT_SYNTHESIZE_FOREIGN)) {
                uid_t foreign_uid;
                r = user_name_foreign_extract_uid(name, &foreign_uid);
                if (r < 0)
                        return r;
                if (r > 0)
                        return synthetic_foreign_user_build(foreign_uid, ret);
        }

        return -ESRCH;
}

int userdb_by_name(const char *name, const UserDBMatch *match, UserDBFlags flags, UserRecord **ret) {
        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *query = NULL;
        int r;

        /* Well known errors this returns:
         *         -EINVAL    → user name is not valid
         *         -ESRCH     → no such user
         *         -ENOEXEC   → found a user by request UID or name, but it does not match filter
         *         -EHOSTDOWN → service failed for some reason
         *         -ETIMEDOUT → service timed out
         */

        assert(name);

        if (FLAGS_SET(flags, USERDB_PARSE_NUMERIC)) {
                uid_t uid;

                if (parse_uid(name, &uid) >= 0)
                        return userdb_by_uid(uid, match, flags, ret);
        }

        if (!valid_user_group_name(name, VALID_USER_RELAX))
                return -EINVAL;

        r = sd_json_buildo(&query, SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(name)));
        if (r < 0)
                return r;

        r = query_append_uid_match(&query, match);
        if (r < 0)
                return r;

        iterator = userdb_iterator_new(LOOKUP_USER, flags);
        if (!iterator)
                return -ENOMEM;

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        r = userdb_start_query(iterator, "io.systemd.UserDatabase.GetUserRecord", /* more= */ false, query, flags);
        if (r >= 0) {
                r = userdb_process(iterator, &ur, /* ret_group_record= */ NULL, /* ret_user_name= */ NULL, /* ret_group_name= */ NULL);
                if (r == -ENOEXEC) /* found a user matching UID or name, but not filter. In this case the
                                    * fallback paths below are pointless */
                        return r;
        }
        if (r < 0) { /* If the above fails for any other reason, try fallback paths */
                r = userdb_by_name_fallbacks(name, iterator, flags, &ur);
                if (r < 0)
                        return r;
        }

        /* NB: we always apply our own filtering here, explicitly, regardless if the server supported it or
         * not. It's more robust this way, we never know how carefully the server is written, and whether it
         * properly implements all details of the filtering logic. */
        r = user_record_match(ur, match);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOEXEC;

        if (ret)
                *ret = TAKE_PTR(ur);

        return 0;
}

static int userdb_by_uid_fallbacks(
                uid_t uid,
                UserDBIterator *iterator,
                UserDBFlags flags,
                UserRecord **ret) {
        int r;

        assert(uid_is_valid(uid));
        assert(iterator);
        assert(ret);

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_DROPIN) && !iterator->dropin_covered) {
                r = dropin_user_record_by_uid(uid, NULL, flags, ret);
                if (r >= 0)
                        return r;
        }

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_NSS) && !iterator->nss_covered) {
                r = userdb_iterator_block_nss_systemd(iterator);
                if (r >= 0) {
                        /* Client-side NSS fallback */
                        r = nss_user_record_by_uid(uid, !FLAGS_SET(flags, USERDB_SUPPRESS_SHADOW), ret);
                        if (r >= 0)
                                return r;
                }
        }

        if (!FLAGS_SET(flags, USERDB_DONT_SYNTHESIZE_INTRINSIC)) {
                if (uid == 0)
                        return synthetic_root_user_build(ret);

                if (uid == UID_NOBODY && synthesize_nobody())
                        return synthetic_nobody_user_build(ret);
        }

        if (!FLAGS_SET(flags, USERDB_DONT_SYNTHESIZE_FOREIGN) && uid_is_foreign(uid))
                return synthetic_foreign_user_build(uid - FOREIGN_UID_BASE, ret);

        return -ESRCH;
}

int userdb_by_uid(uid_t uid, const UserDBMatch *match, UserDBFlags flags, UserRecord **ret) {
        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *query = NULL;
        int r;

        if (!uid_is_valid(uid))
                return -EINVAL;

        r = sd_json_buildo(&query, SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(uid)));
        if (r < 0)
                return r;

        r = query_append_uid_match(&query, match);
        if (r < 0)
                return r;

        iterator = userdb_iterator_new(LOOKUP_USER, flags);
        if (!iterator)
                return -ENOMEM;

        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        r = userdb_start_query(iterator, "io.systemd.UserDatabase.GetUserRecord", /* more= */ false, query, flags);
        if (r >= 0) {
                r = userdb_process(iterator, &ur, /* ret_group_record= */ NULL, /* ret_user_name= */ NULL, /* ret_group_name= */ NULL);
                if (r == -ENOEXEC)
                        return r;
        }
        if (r < 0) {
                r = userdb_by_uid_fallbacks(uid, iterator, flags, &ur);
                if (r < 0)
                        return r;
        }

        r = user_record_match(ur, match);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOEXEC;

        if (ret)
                *ret = TAKE_PTR(ur);

        return 0;
}

int userdb_all(const UserDBMatch *match, UserDBFlags flags, UserDBIterator **ret) {
        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *query = NULL;
        int r, qr;

        assert(ret);

        r = query_append_uid_match(&query, match);
        if (r < 0)
                return r;

        iterator = userdb_iterator_new(LOOKUP_USER, flags);
        if (!iterator)
                return -ENOMEM;

        qr = userdb_start_query(iterator, "io.systemd.UserDatabase.GetUserRecord", /* more= */ true, query, flags);

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_NSS) && (qr < 0 || !iterator->nss_covered)) {
                r = userdb_iterator_block_nss_systemd(iterator);
                if (r < 0)
                        return r;

                setpwent();
                iterator->nss_iterating = true;
        }

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_DROPIN) && (qr < 0 || !iterator->dropin_covered)) {
                r = conf_files_list_nulstr(
                                &iterator->dropins,
                                ".user",
                                NULL,
                                CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED,
                                USERDB_DROPIN_DIR_NULSTR("userdb"));
                if (r < 0)
                        log_debug_errno(r, "Failed to find user drop-ins, ignoring: %m");
        }

        /* Note that we do not enumerate the foreign users, since those would be just 64K of noise */

        /* propagate IPC error, but only if there are no drop-ins */
        if (qr < 0 &&
            !iterator->nss_iterating &&
            strv_isempty(iterator->dropins))
                return qr;

        *ret = TAKE_PTR(iterator);
        return 0;
}

static int userdb_iterator_get_one(UserDBIterator *iterator, UserRecord **ret) {
        int r;

        assert(iterator);
        assert(iterator->what == LOOKUP_USER);

        if (iterator->nss_iterating) {
                struct passwd *pw;

                /* If NSS isn't covered elsewhere, let's iterate through it first, since it probably contains
                 * the more traditional sources, which are probably good to show first. */

                errno = 0;
                pw = getpwent();
                if (pw) {
                        _cleanup_free_ char *buffer = NULL;
                        bool incomplete = false;
                        struct spwd spwd;

                        if (streq_ptr(pw->pw_name, "root"))
                                iterator->synthesize_root = false;
                        if (pw->pw_uid == UID_NOBODY)
                                iterator->synthesize_nobody = false;

                        if (!FLAGS_SET(iterator->flags, USERDB_SUPPRESS_SHADOW)) {
                                r = nss_spwd_for_passwd(pw, &spwd, &buffer);
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to acquire shadow entry for user %s, ignoring: %m", pw->pw_name);
                                        incomplete = ERRNO_IS_PRIVILEGE(r);
                                }
                        } else {
                                r = -EUCLEAN;
                                incomplete = true;
                        }

                        r = nss_passwd_to_user_record(pw, r >= 0 ? &spwd : NULL, ret);
                        if (r < 0)
                                return r;

                        if (ret)
                                (*ret)->incomplete = incomplete;

                        iterator->n_found++;
                        return r;
                }

                if (errno != 0)
                        log_debug_errno(errno, "Failure to iterate NSS user database, ignoring: %m");

                iterator->nss_iterating = false;
                endpwent();
        }

        for (; iterator->dropins && iterator->dropins[iterator->current_dropin]; iterator->current_dropin++) {
                const char *i = iterator->dropins[iterator->current_dropin];
                _cleanup_free_ char *fn = NULL;
                uid_t uid;
                char *e;

                /* Next, let's add in the static drop-ins, which are quick to retrieve */

                r = path_extract_filename(i, &fn);
                if (r < 0)
                        return r;

                e = endswith(fn, ".user"); /* not actually a .user file? Then skip to next */
                if (!e)
                        continue;

                *e = 0; /* Chop off suffix */

                if (parse_uid(fn, &uid) < 0) /* not a UID .user file? Then skip to next */
                        continue;

                r = dropin_user_record_by_uid(uid, i, iterator->flags, ret);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse user record for UID " UID_FMT ", ignoring: %m", uid);
                        continue; /* If we failed to parse this record, let's suppress it from enumeration,
                                   * and continue with the next record. Maybe someone is dropping it files
                                   * and only partially wrote this one. */
                }

                iterator->current_dropin++; /* make sure on the next call of userdb_iterator_get() we continue with the next dropin */
                iterator->n_found++;
                return 0;
        }

        /* Then, let's return the users provided by varlink IPC */
        r = userdb_process(iterator, ret, /* ret_group_record= */ NULL, /* ret_user_name= */ NULL, /* ret_group_name= */ NULL);
        if (r < 0) {

                /* Finally, synthesize root + nobody if not done yet */
                if (iterator->synthesize_root) {
                        iterator->synthesize_root = false;
                        iterator->n_found++;
                        return synthetic_root_user_build(ret);
                }

                if (iterator->synthesize_nobody) {
                        iterator->synthesize_nobody = false;
                        iterator->n_found++;
                        return synthetic_nobody_user_build(ret);
                }

                /* if we found at least one entry, then ignore errors and indicate that we reached the end */
                if (iterator->n_found > 0)
                        return -ESRCH;
        }

        return r;
}

int userdb_iterator_get(UserDBIterator *iterator, const UserDBMatch *match, UserRecord **ret) {
        int r;

        assert(iterator);
        assert(iterator->what == LOOKUP_USER);

        for (;;) {
                _cleanup_(user_record_unrefp) UserRecord *ur = NULL;

                r = userdb_iterator_get_one(iterator, userdb_match_is_set(match) || ret ? &ur : NULL);
                if (r < 0)
                        return r;

                if (ur && !user_record_match(ur, match))
                        continue;

                if (ret)
                        *ret = TAKE_PTR(ur);

                return r;
        }
}

static int synthetic_root_group_build(GroupRecord **ret) {
        return group_record_build(
                        ret,
                        SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("groupName", JSON_BUILD_CONST_STRING("root")),
                                          SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(0)),
                                          SD_JSON_BUILD_PAIR("disposition", JSON_BUILD_CONST_STRING("intrinsic"))));
}

static int synthetic_nobody_group_build(GroupRecord **ret) {
        return group_record_build(
                        ret,
                        SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("groupName", JSON_BUILD_CONST_STRING(NOBODY_GROUP_NAME)),
                                          SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(GID_NOBODY)),
                                          SD_JSON_BUILD_PAIR("disposition", JSON_BUILD_CONST_STRING("intrinsic"))));
}

static int synthetic_foreign_group_build(gid_t foreign_gid, GroupRecord **ret) {
        assert(ret);

        if (!gid_is_valid(foreign_gid))
                return -ESRCH;
        if (foreign_gid > 0xFFFF)
                return -ESRCH;

        _cleanup_free_ char *gn = NULL;
        if (asprintf(&gn, "foreign-" GID_FMT, foreign_gid) < 0)
                return -ENOMEM;

        _cleanup_free_ char *d = NULL;
        if (asprintf(&d, "Foreign System Image GID " GID_FMT, foreign_gid) < 0)
                return -ENOMEM;

        return group_record_build(
                        ret,
                        SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(gn)),
                                        SD_JSON_BUILD_PAIR("description", SD_JSON_BUILD_STRING(d)),
                                        SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(FOREIGN_UID_BASE + foreign_gid)),
                                        SD_JSON_BUILD_PAIR("disposition", JSON_BUILD_CONST_STRING("foreign"))));
}

static int query_append_gid_match(sd_json_variant **query, const UserDBMatch *match) {
        int r;

        assert(query);

        if (!userdb_match_is_set(match))
                return 0;

        r = sd_json_variant_merge_objectbo(
                        query,
                        SD_JSON_BUILD_PAIR_CONDITION(!strv_isempty(match->fuzzy_names), "fuzzyNames", SD_JSON_BUILD_STRV(match->fuzzy_names)),
                        SD_JSON_BUILD_PAIR_CONDITION(match->gid_min > 0, "gidMin", SD_JSON_BUILD_UNSIGNED(match->gid_min)),
                        SD_JSON_BUILD_PAIR_CONDITION(match->gid_max < GID_INVALID-1, "gidMax", SD_JSON_BUILD_UNSIGNED(match->gid_max)));
        if (r < 0)
                return r;

        return query_append_disposition_mask(query, match->disposition_mask);
}

static int groupdb_by_name_fallbacks(
                const char *name,
                UserDBIterator *iterator,
                UserDBFlags flags,
                GroupRecord **ret) {

        int r;

        assert(name);
        assert(iterator);
        assert(ret);

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_DROPIN) && !iterator->dropin_covered) {
                r = dropin_group_record_by_name(name, NULL, flags, ret);
                if (r >= 0)
                        return r;
        }

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_NSS) && !iterator->nss_covered) {
                r = userdb_iterator_block_nss_systemd(iterator);
                if (r >= 0) {
                        r = nss_group_record_by_name(name, !FLAGS_SET(flags, USERDB_SUPPRESS_SHADOW), ret);
                        if (r >= 0)
                                return r;
                }
        }

        if (!FLAGS_SET(flags, USERDB_DONT_SYNTHESIZE_INTRINSIC)) {
                if (streq(name, "root"))
                        return synthetic_root_group_build(ret);

                if (streq(name, NOBODY_GROUP_NAME) && synthesize_nobody())
                        return synthetic_nobody_group_build(ret);
        }

        if (!FLAGS_SET(flags, USERDB_DONT_SYNTHESIZE_FOREIGN)) {
                uid_t foreign_gid;
                r = user_name_foreign_extract_uid(name, &foreign_gid); /* Same for UID + GID */
                if (r < 0)
                        return r;
                if (r > 0)
                        return synthetic_foreign_group_build(foreign_gid, ret);
        }

        return -ESRCH;
}

int groupdb_by_name(const char *name, const UserDBMatch *match, UserDBFlags flags, GroupRecord **ret) {
        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *query = NULL;
        int r;

        assert(name);

        if (FLAGS_SET(flags, USERDB_PARSE_NUMERIC)) {
                gid_t gid;

                if (parse_gid(name, &gid) >= 0)
                        return groupdb_by_gid(gid, match, flags, ret);
        }

        if (!valid_user_group_name(name, VALID_USER_RELAX))
                return -EINVAL;

        r = sd_json_buildo(&query, SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(name)));
        if (r < 0)
                return r;

        r = query_append_gid_match(&query, match);
        if (r < 0)
                return r;

        iterator = userdb_iterator_new(LOOKUP_GROUP, flags);
        if (!iterator)
                return -ENOMEM;

        _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;
        r = userdb_start_query(iterator, "io.systemd.UserDatabase.GetGroupRecord", /* more= */ false, query, flags);
        if (r >= 0) {
                r = userdb_process(iterator, /* ret_user_record= */ NULL, &gr, /* ret_user_name= */ NULL, /* ret_group_name= */ NULL);
                if (r == -ENOEXEC)
                        return r;
        }
        if (r < 0) {
                r = groupdb_by_name_fallbacks(name, iterator, flags, &gr);
                if (r < 0)
                        return r;
        }

        /* As above, we apply our own client-side filtering even if server-side filtering worked, for robustness and simplicity reasons. */
        r = group_record_match(gr, match);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOEXEC;

        if (ret)
                *ret = TAKE_PTR(gr);

        return r;
}

static int groupdb_by_gid_fallbacks(
                gid_t gid,
                UserDBIterator *iterator,
                UserDBFlags flags,
                GroupRecord **ret) {
        int r;

        assert(gid_is_valid(gid));
        assert(iterator);
        assert(ret);

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_DROPIN) && !(iterator && iterator->dropin_covered)) {
                r = dropin_group_record_by_gid(gid, NULL, flags, ret);
                if (r >= 0)
                        return r;
        }

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_NSS) && !(iterator && iterator->nss_covered)) {
                r = userdb_iterator_block_nss_systemd(iterator);
                if (r >= 0) {
                        r = nss_group_record_by_gid(gid, !FLAGS_SET(flags, USERDB_SUPPRESS_SHADOW), ret);
                        if (r >= 0)
                                return r;
                }
        }

        if (!FLAGS_SET(flags, USERDB_DONT_SYNTHESIZE_INTRINSIC)) {
                if (gid == 0)
                        return synthetic_root_group_build(ret);

                if (gid == GID_NOBODY && synthesize_nobody())
                        return synthetic_nobody_group_build(ret);
        }

        if (!FLAGS_SET(flags, USERDB_DONT_SYNTHESIZE_FOREIGN) && gid_is_foreign(gid))
                return synthetic_foreign_group_build(gid - FOREIGN_UID_BASE, ret);

        return -ESRCH;
}

int groupdb_by_gid(gid_t gid, const UserDBMatch *match, UserDBFlags flags, GroupRecord **ret) {
        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *query = NULL;
        int r;

        if (!gid_is_valid(gid))
                return -EINVAL;

        r = sd_json_buildo(&query, SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(gid)));
        if (r < 0)
                return r;

        r = query_append_gid_match(&query, match);
        if (r < 0)
                return r;

        iterator = userdb_iterator_new(LOOKUP_GROUP, flags);
        if (!iterator)
                return -ENOMEM;

        _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;
        r = userdb_start_query(iterator, "io.systemd.UserDatabase.GetGroupRecord", /* more= */ false, query, flags);
        if (r >= 0) {
                r = userdb_process(iterator, /* ret_user_record= */ NULL, &gr, /* ret_user_name= */ NULL, /* ret_group_name= */ NULL);
                if (r == -ENOEXEC)
                        return r;
        }
        if (r < 0) {
                r = groupdb_by_gid_fallbacks(gid, iterator, flags, &gr);
                if (r < 0)
                        return r;
        }

        r = group_record_match(gr, match);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOEXEC;

        if (ret)
                *ret = TAKE_PTR(gr);

        return 0;
}

int groupdb_all(const UserDBMatch *match, UserDBFlags flags, UserDBIterator **ret) {
        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *query = NULL;
        int r, qr;

        assert(ret);

        r = query_append_gid_match(&query, match);
        if (r < 0)
                return r;

        iterator = userdb_iterator_new(LOOKUP_GROUP, flags);
        if (!iterator)
                return -ENOMEM;

        qr = userdb_start_query(iterator, "io.systemd.UserDatabase.GetGroupRecord", /* more= */ true, query, flags);

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_NSS) && (qr < 0 || !iterator->nss_covered)) {
                r = userdb_iterator_block_nss_systemd(iterator);
                if (r < 0)
                        return r;

                setgrent();
                iterator->nss_iterating = true;
        }

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_DROPIN) && (qr < 0 || !iterator->dropin_covered)) {
                r = conf_files_list_nulstr(
                                &iterator->dropins,
                                ".group",
                                NULL,
                                CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED,
                                USERDB_DROPIN_DIR_NULSTR("userdb"));
                if (r < 0)
                        log_debug_errno(r, "Failed to find group drop-ins, ignoring: %m");
        }

        if (qr < 0 &&
            !iterator->nss_iterating &&
            strv_isempty(iterator->dropins))
                return qr;

        *ret = TAKE_PTR(iterator);
        return 0;
}

static int groupdb_iterator_get_one(UserDBIterator *iterator, GroupRecord **ret) {
        int r;

        assert(iterator);
        assert(iterator->what == LOOKUP_GROUP);

        if (iterator->nss_iterating) {
                struct group *gr;

                errno = 0;
                gr = getgrent();
                if (gr) {
                        _cleanup_free_ char *buffer = NULL;
                        bool incomplete = false;
                        struct sgrp sgrp;

                        if (streq_ptr(gr->gr_name, "root"))
                                iterator->synthesize_root = false;
                        if (gr->gr_gid == GID_NOBODY)
                                iterator->synthesize_nobody = false;

                        if (!FLAGS_SET(iterator->flags, USERDB_SUPPRESS_SHADOW)) {
                                r = nss_sgrp_for_group(gr, &sgrp, &buffer);
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to acquire shadow entry for group %s, ignoring: %m", gr->gr_name);
                                        incomplete = ERRNO_IS_PRIVILEGE(r);
                                }
                        } else {
                                r = -EUCLEAN;
                                incomplete = true;
                        }

                        r = nss_group_to_group_record(gr, r >= 0 ? &sgrp : NULL, ret);
                        if (r < 0)
                                return r;

                        if (ret)
                                (*ret)->incomplete = incomplete;

                        iterator->n_found++;
                        return r;
                }

                if (errno != 0)
                        log_debug_errno(errno, "Failure to iterate NSS group database, ignoring: %m");

                iterator->nss_iterating = false;
                endgrent();
        }

        for (; iterator->dropins && iterator->dropins[iterator->current_dropin]; iterator->current_dropin++) {
                const char *i = iterator->dropins[iterator->current_dropin];
                _cleanup_free_ char *fn = NULL;
                gid_t gid;
                char *e;

                r = path_extract_filename(i, &fn);
                if (r < 0)
                        return r;

                e = endswith(fn, ".group");
                if (!e)
                        continue;

                *e = 0; /* Chop off suffix */

                if (parse_gid(fn, &gid) < 0)
                        continue;

                r = dropin_group_record_by_gid(gid, i, iterator->flags, ret);
                if (r < 0) {
                        log_debug_errno(r, "Failed to parse group record for GID " GID_FMT ", ignoring: %m", gid);
                        continue;
                }

                iterator->current_dropin++;
                iterator->n_found++;
                return 0;
        }

        r = userdb_process(iterator, NULL, ret, NULL, NULL);
        if (r < 0) {
                if (iterator->synthesize_root) {
                        iterator->synthesize_root = false;
                        iterator->n_found++;
                        return synthetic_root_group_build(ret);
                }

                if (iterator->synthesize_nobody) {
                        iterator->synthesize_nobody = false;
                        iterator->n_found++;
                        return synthetic_nobody_group_build(ret);
                }

                /* if we found at least one entry, then ignore errors and indicate that we reached the end */
                if (iterator->n_found > 0)
                        return -ESRCH;
        }

        return r;
}

int groupdb_iterator_get(UserDBIterator *iterator, const UserDBMatch *match, GroupRecord **ret) {
        int r;

        assert(iterator);
        assert(iterator->what == LOOKUP_GROUP);

        for (;;) {
                _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;

                r = groupdb_iterator_get_one(iterator, userdb_match_is_set(match) || ret ? &gr : NULL);
                if (r < 0)
                        return r;

                if (gr && !group_record_match(gr, match))
                        continue;

                if (ret)
                        *ret = TAKE_PTR(gr);

                return r;
        }
}

static void discover_membership_dropins(UserDBIterator *i, UserDBFlags flags) {
        int r;

        r = conf_files_list_nulstr(
                        &i->dropins,
                        ".membership",
                        NULL,
                        CONF_FILES_REGULAR|CONF_FILES_BASENAME|CONF_FILES_FILTER_MASKED,
                        USERDB_DROPIN_DIR_NULSTR("userdb"));
        if (r < 0)
                log_debug_errno(r, "Failed to find membership drop-ins, ignoring: %m");
}

int membershipdb_by_user(const char *name, UserDBFlags flags, UserDBIterator **ret) {
        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *query = NULL;
        int r, qr;

        assert(ret);

        if (!valid_user_group_name(name, VALID_USER_RELAX))
                return -EINVAL;

        r = sd_json_buildo(&query, SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(name)));
        if (r < 0)
                return r;

        iterator = userdb_iterator_new(LOOKUP_MEMBERSHIP, flags);
        if (!iterator)
                return -ENOMEM;

        iterator->filter_user_name = strdup(name);
        if (!iterator->filter_user_name)
                return -ENOMEM;

        qr = userdb_start_query(iterator, "io.systemd.UserDatabase.GetMemberships", true, query, flags);

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_NSS) && (qr < 0 || !iterator->nss_covered)) {
                r = userdb_iterator_block_nss_systemd(iterator);
                if (r < 0)
                        return r;

                setgrent();
                iterator->nss_iterating = true;
        }

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_DROPIN) && (qr < 0 || !iterator->dropin_covered))
                discover_membership_dropins(iterator, flags);

        if (qr < 0 &&
            !iterator->nss_iterating &&
            strv_isempty(iterator->dropins))
                return qr;

        *ret = TAKE_PTR(iterator);
        return 0;
}

int membershipdb_by_group(const char *name, UserDBFlags flags, UserDBIterator **ret) {
        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *query = NULL;
        int r, qr;

        assert(ret);

        if (!valid_user_group_name(name, VALID_USER_RELAX))
                return -EINVAL;

        r = sd_json_buildo(&query, SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(name)));
        if (r < 0)
                return r;

        iterator = userdb_iterator_new(LOOKUP_MEMBERSHIP, flags);
        if (!iterator)
                return -ENOMEM;

        iterator->filter_group_name = strdup(name);
        if (!iterator->filter_group_name)
                return -ENOMEM;

        qr = userdb_start_query(iterator, "io.systemd.UserDatabase.GetMemberships", true, query, flags);

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_NSS) && (qr < 0 || !iterator->nss_covered)) {
                _cleanup_(group_record_unrefp) GroupRecord *gr = NULL;

                r = userdb_iterator_block_nss_systemd(iterator);
                if (r < 0)
                        return r;

                /* We ignore all errors here, since the group might be defined by a userdb native service, and we queried them already above. */
                (void) nss_group_record_by_name(name, false, &gr);
                if (gr) {
                        iterator->members_of_group = strv_copy(gr->members);
                        if (!iterator->members_of_group)
                                return -ENOMEM;

                        iterator->index_members_of_group = 0;

                        iterator->found_group_name = strdup(name);
                        if (!iterator->found_group_name)
                                return -ENOMEM;
                }
        }

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_DROPIN) && (qr < 0 || !iterator->dropin_covered))
                discover_membership_dropins(iterator, flags);

        if (qr < 0 &&
            strv_isempty(iterator->members_of_group) &&
            strv_isempty(iterator->dropins))
                return qr;

        *ret = TAKE_PTR(iterator);
        return 0;
}

int membershipdb_all(UserDBFlags flags, UserDBIterator **ret) {
        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        int r, qr;

        assert(ret);

        iterator = userdb_iterator_new(LOOKUP_MEMBERSHIP, flags);
        if (!iterator)
                return -ENOMEM;

        qr = userdb_start_query(iterator, "io.systemd.UserDatabase.GetMemberships", true, NULL, flags);

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_NSS) && (qr < 0 || !iterator->nss_covered)) {
                r = userdb_iterator_block_nss_systemd(iterator);
                if (r < 0)
                        return r;

                setgrent();
                iterator->nss_iterating = true;
        }

        if (!FLAGS_SET(flags, USERDB_EXCLUDE_DROPIN) && (qr < 0 || !iterator->dropin_covered))
                discover_membership_dropins(iterator, flags);

        if (qr < 0 &&
            !iterator->nss_iterating &&
            strv_isempty(iterator->dropins))
                return qr;

        *ret = TAKE_PTR(iterator);
        return 0;
}

int membershipdb_iterator_get(
                UserDBIterator *iterator,
                char **ret_user,
                char **ret_group) {

        int r;

        assert(iterator);

        for (;;) {
                /* If we are iterating through NSS acquire a new group entry if we haven't acquired one yet. */
                if (!iterator->members_of_group) {
                        struct group *g;

                        if (!iterator->nss_iterating)
                                break;

                        assert(!iterator->found_user_name);
                        do {
                                errno = 0;
                                g = getgrent();
                                if (!g) {
                                        if (errno != 0)
                                                log_debug_errno(errno, "Failure during NSS group iteration, ignoring: %m");
                                        break;
                                }

                        } while (iterator->filter_user_name ? !strv_contains(g->gr_mem, iterator->filter_user_name) :
                                                              strv_isempty(g->gr_mem));

                        if (g) {
                                r = free_and_strdup(&iterator->found_group_name, g->gr_name);
                                if (r < 0)
                                        return r;

                                if (iterator->filter_user_name)
                                        iterator->members_of_group = strv_new(iterator->filter_user_name);
                                else
                                        iterator->members_of_group = strv_copy(g->gr_mem);
                                if (!iterator->members_of_group)
                                        return -ENOMEM;

                                iterator->index_members_of_group = 0;
                        } else {
                                iterator->nss_iterating = false;
                                endgrent();
                                break;
                        }
                }

                assert(iterator->found_group_name);
                assert(iterator->members_of_group);
                assert(!iterator->found_user_name);

                if (iterator->members_of_group[iterator->index_members_of_group]) {
                        _cleanup_free_ char *cu = NULL, *cg = NULL;

                        if (ret_user) {
                                cu = strdup(iterator->members_of_group[iterator->index_members_of_group]);
                                if (!cu)
                                        return -ENOMEM;
                        }

                        if (ret_group) {
                                cg = strdup(iterator->found_group_name);
                                if (!cg)
                                        return -ENOMEM;
                        }

                        if (ret_user)
                                *ret_user = TAKE_PTR(cu);

                        if (ret_group)
                                *ret_group = TAKE_PTR(cg);

                        iterator->index_members_of_group++;
                        return 0;
                }

                iterator->members_of_group = strv_free(iterator->members_of_group);
                iterator->found_group_name = mfree(iterator->found_group_name);
        }

        for (; iterator->dropins && iterator->dropins[iterator->current_dropin]; iterator->current_dropin++) {
                const char *i = iterator->dropins[iterator->current_dropin], *e, *c;
                _cleanup_free_ char *un = NULL, *gn = NULL;

                e = endswith(i, ".membership");
                if (!e)
                        continue;

                c = memchr(i, ':', e - i);
                if (!c)
                        continue;

                un = strndup(i, c - i);
                if (!un)
                        return -ENOMEM;
                if (iterator->filter_user_name) {
                        if (!streq(un, iterator->filter_user_name))
                                continue;
                } else if (!valid_user_group_name(un, VALID_USER_RELAX))
                        continue;

                c++; /* skip over ':' */
                gn = strndup(c, e - c);
                if (!gn)
                        return -ENOMEM;
                if (iterator->filter_group_name) {
                        if (!streq(gn, iterator->filter_group_name))
                                continue;
                } else if (!valid_user_group_name(gn, VALID_USER_RELAX))
                        continue;

                iterator->current_dropin++;
                iterator->n_found++;

                if (ret_user)
                        *ret_user = TAKE_PTR(un);
                if (ret_group)
                        *ret_group = TAKE_PTR(gn);

                return 0;
        }

        r = userdb_process(iterator, NULL, NULL, ret_user, ret_group);
        if (r < 0 && iterator->n_found > 0)
                return -ESRCH;

        return r;
}

int membershipdb_by_group_strv(const char *name, UserDBFlags flags, char ***ret) {
        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        _cleanup_strv_free_ char **members = NULL;
        int r;

        assert(name);
        assert(ret);

        r = membershipdb_by_group(name, flags, &iterator);
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *user_name = NULL;

                r = membershipdb_iterator_get(iterator, &user_name, NULL);
                if (r == -ESRCH)
                        break;
                if (r < 0)
                        return r;

                r = strv_consume(&members, TAKE_PTR(user_name));
                if (r < 0)
                        return r;
        }

        strv_sort_uniq(members);

        *ret = TAKE_PTR(members);
        return 0;
}

int userdb_block_nss_systemd(int b) {
        _cleanup_(dlclosep) void *dl = NULL;
        int (*call)(bool b);

        /* Note that we might be called from libnss_systemd.so.2 itself, but that should be fine, really. */

        dl = dlopen(LIBDIR "/libnss_systemd.so.2", RTLD_NOW|RTLD_NODELETE);
        if (!dl) {
                /* If the file isn't installed, don't complain loudly */
                log_debug("Failed to dlopen(libnss_systemd.so.2), ignoring: %s", dlerror());
                return 0;
        }

        log_debug("Loaded '%s' via dlopen()", LIBDIR "/libnss_systemd.so.2");

        call = dlsym(dl, "_nss_systemd_block");
        if (!call)
                /* If the file is installed but lacks the symbol we expect, things are weird, let's complain */
                return log_debug_errno(SYNTHETIC_ERRNO(ELIBBAD),
                                       "Unable to find symbol _nss_systemd_block in libnss_systemd.so.2: %s", dlerror());

        return call(b);
}
