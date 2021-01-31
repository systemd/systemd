/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <sys/wait.h>

#include "sd-daemon.h"

#include "env-util.h"
#include "fd-util.h"
#include "group-record.h"
#include "io-util.h"
#include "main-func.h"
#include "process-util.h"
#include "strv.h"
#include "time-util.h"
#include "user-record-nss.h"
#include "user-record.h"
#include "user-util.h"
#include "userdb.h"
#include "varlink.h"

#define ITERATIONS_MAX 64U
#define RUNTIME_MAX_USEC (5 * USEC_PER_MINUTE)
#define PRESSURE_SLEEP_TIME_USEC (50 * USEC_PER_MSEC)
#define CONNECTION_IDLE_USEC (15 * USEC_PER_SEC)
#define LISTEN_IDLE_USEC (90 * USEC_PER_SEC)

typedef struct LookupParameters {
        const char *user_name;
        const char *group_name;
        union {
                uid_t uid;
                gid_t gid;
        };
        const char *service;
} LookupParameters;

static int add_nss_service(JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *status = NULL, *z = NULL;
        char buf[SD_ID128_STRING_MAX];
        sd_id128_t mid;
        int r;

        assert(v);

        /* Patch in service field if it's missing. The assumption here is that this field is unset only for
         * NSS records */

        if (json_variant_by_key(*v, "service"))
                return 0;

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return r;

        status = json_variant_ref(json_variant_by_key(*v, "status"));
        z = json_variant_ref(json_variant_by_key(status, sd_id128_to_string(mid, buf)));

        if (json_variant_by_key(z, "service"))
                return 0;

        r = json_variant_set_field_string(&z, "service", "io.systemd.NameServiceSwitch");
        if (r < 0)
                return r;

        r = json_variant_set_field(&status, buf, z);
        if (r < 0)
                return r;

        return json_variant_set_field(v, "status", status);
}

static int build_user_json(Varlink *link, UserRecord *ur, JsonVariant **ret) {
        _cleanup_(user_record_unrefp) UserRecord *stripped = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        UserRecordLoadFlags flags;
        uid_t peer_uid;
        bool trusted;
        int r;

        assert(ur);
        assert(ret);

        r = varlink_get_peer_uid(link, &peer_uid);
        if (r < 0) {
                log_debug_errno(r, "Unable to query peer UID, ignoring: %m");
                trusted = false;
        } else
                trusted = peer_uid == 0 || peer_uid == ur->uid;

        flags = USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_BINDING|USER_RECORD_STRIP_SECRET|USER_RECORD_ALLOW_STATUS|USER_RECORD_ALLOW_SIGNATURE;
        if (trusted)
                flags |= USER_RECORD_ALLOW_PRIVILEGED;
        else
                flags |= USER_RECORD_STRIP_PRIVILEGED;

        r = user_record_clone(ur, flags, &stripped);
        if (r < 0)
                return r;

        stripped->incomplete =
                ur->incomplete ||
                (FLAGS_SET(ur->mask, USER_RECORD_PRIVILEGED) &&
                 !FLAGS_SET(stripped->mask, USER_RECORD_PRIVILEGED));

        v = json_variant_ref(stripped->json);
        r = add_nss_service(&v);
        if (r < 0)
                return r;

        return json_build(ret, JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("record", JSON_BUILD_VARIANT(v)),
                                          JSON_BUILD_PAIR("incomplete", JSON_BUILD_BOOLEAN(stripped->incomplete))));
}

static int vl_method_get_user_record(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "uid",      JSON_VARIANT_UNSIGNED, json_dispatch_uid_gid,      offsetof(LookupParameters, uid),       0 },
                { "userName", JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(LookupParameters, user_name), 0 },
                { "service",  JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(LookupParameters, service),   0 },
                {}
        };

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        LookupParameters p = {
                .uid = UID_INVALID,
        };
        int r;

        assert(parameters);

        r = json_dispatch(parameters, dispatch_table, NULL, 0, &p);
        if (r < 0)
                return r;

        if (streq_ptr(p.service, "io.systemd.NameServiceSwitch")) {
                if (uid_is_valid(p.uid))
                        r = nss_user_record_by_uid(p.uid, true, &hr);
                else if (p.user_name)
                        r = nss_user_record_by_name(p.user_name, true, &hr);
                else {
                        _cleanup_(json_variant_unrefp) JsonVariant *last = NULL;

                        setpwent();

                        for (;;) {
                                _cleanup_(user_record_unrefp) UserRecord *z = NULL;
                                _cleanup_free_ char *sbuf = NULL;
                                struct passwd *pw;
                                struct spwd spwd;

                                errno = 0;
                                pw = getpwent();
                                if (!pw) {
                                        if (errno != 0)
                                                log_debug_errno(errno, "Failure while iterating through NSS user database, ignoring: %m");

                                        break;
                                }

                                r = nss_spwd_for_passwd(pw, &spwd, &sbuf);
                                if (r < 0)
                                        log_debug_errno(r, "Failed to acquire shadow entry for user %s, ignoring: %m", pw->pw_name);

                                r = nss_passwd_to_user_record(pw, NULL, &z);
                                if (r < 0) {
                                        endpwent();
                                        return r;
                                }

                                if (last) {
                                        r = varlink_notify(link, last);
                                        if (r < 0) {
                                                endpwent();
                                                return r;
                                        }

                                        last = json_variant_unref(last);
                                }

                                r = build_user_json(link, z, &last);
                                if (r < 0) {
                                        endpwent();
                                        return r;
                                }
                        }

                        endpwent();

                        if (!last)
                                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

                        return varlink_reply(link, last);
                }

        } else if (streq_ptr(p.service, "io.systemd.Multiplexer")) {

                if (uid_is_valid(p.uid))
                        r = userdb_by_uid(p.uid, USERDB_AVOID_MULTIPLEXER, &hr);
                else if (p.user_name)
                        r = userdb_by_name(p.user_name, USERDB_AVOID_MULTIPLEXER, &hr);
                else {
                        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
                        _cleanup_(json_variant_unrefp) JsonVariant *last = NULL;

                        r = userdb_all(USERDB_AVOID_MULTIPLEXER, &iterator);
                        if (r < 0)
                                return r;

                        for (;;) {
                                _cleanup_(user_record_unrefp) UserRecord *z = NULL;

                                r = userdb_iterator_get(iterator, &z);
                                if (r == -ESRCH)
                                        break;
                                if (r < 0)
                                        return r;

                                if (last) {
                                        r = varlink_notify(link, last);
                                        if (r < 0)
                                                return r;

                                        last = json_variant_unref(last);
                                }

                                r = build_user_json(link, z, &last);
                                if (r < 0)
                                        return r;
                        }

                        if (!last)
                                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

                        return varlink_reply(link, last);
                }
        } else
                return varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);
        if (r == -ESRCH)
                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
        if (r < 0) {
                log_debug_errno(r, "User lookup failed abnormally: %m");
                return varlink_error(link, "io.systemd.UserDatabase.ServiceNotAvailable", NULL);
        }

        if ((uid_is_valid(p.uid) && hr->uid != p.uid) ||
            (p.user_name && !streq(hr->user_name, p.user_name)))
                return varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        r = build_user_json(link, hr, &v);
        if (r < 0)
                return r;

        return varlink_reply(link, v);
}

static int build_group_json(Varlink *link, GroupRecord *gr, JsonVariant **ret) {
        _cleanup_(group_record_unrefp) GroupRecord *stripped = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        UserRecordLoadFlags flags;
        uid_t peer_uid;
        bool trusted;
        int r;

        assert(gr);
        assert(ret);

        r = varlink_get_peer_uid(link, &peer_uid);
        if (r < 0) {
                log_debug_errno(r, "Unable to query peer UID, ignoring: %m");
                trusted = false;
        } else
                trusted = peer_uid == 0;

        flags = USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_BINDING|USER_RECORD_STRIP_SECRET|USER_RECORD_ALLOW_STATUS|USER_RECORD_ALLOW_SIGNATURE;
        if (trusted)
                flags |= USER_RECORD_ALLOW_PRIVILEGED;
        else
                flags |= USER_RECORD_STRIP_PRIVILEGED;

        r = group_record_clone(gr, flags, &stripped);
        if (r < 0)
                return r;

        stripped->incomplete =
                gr->incomplete ||
                (FLAGS_SET(gr->mask, USER_RECORD_PRIVILEGED) &&
                 !FLAGS_SET(stripped->mask, USER_RECORD_PRIVILEGED));

        v = json_variant_ref(gr->json);
        r = add_nss_service(&v);
        if (r < 0)
                return r;

        return json_build(ret, JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("record", JSON_BUILD_VARIANT(v)),
                                          JSON_BUILD_PAIR("incomplete", JSON_BUILD_BOOLEAN(stripped->incomplete))));
}

static int vl_method_get_group_record(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "gid",       JSON_VARIANT_UNSIGNED, json_dispatch_uid_gid,      offsetof(LookupParameters, gid),        0 },
                { "groupName", JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(LookupParameters, group_name), 0 },
                { "service",   JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(LookupParameters, service),    0 },
                {}
        };

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;
        LookupParameters p = {
                .gid = GID_INVALID,
        };
        int r;

        assert(parameters);

        r = json_dispatch(parameters, dispatch_table, NULL, 0, &p);
        if (r < 0)
                return r;

        if (streq_ptr(p.service, "io.systemd.NameServiceSwitch")) {

                if (gid_is_valid(p.gid))
                        r = nss_group_record_by_gid(p.gid, true, &g);
                else if (p.group_name)
                        r = nss_group_record_by_name(p.group_name, true, &g);
                else {
                        _cleanup_(json_variant_unrefp) JsonVariant *last = NULL;

                        setgrent();

                        for (;;) {
                                _cleanup_(group_record_unrefp) GroupRecord *z = NULL;
                                _cleanup_free_ char *sbuf = NULL;
                                struct group *grp;
                                struct sgrp sgrp;

                                errno = 0;
                                grp = getgrent();
                                if (!grp) {
                                        if (errno != 0)
                                                log_debug_errno(errno, "Failure while iterating through NSS group database, ignoring: %m");

                                        break;
                                }

                                r = nss_sgrp_for_group(grp, &sgrp, &sbuf);
                                if (r < 0)
                                        log_debug_errno(r, "Failed to acquire shadow entry for group %s, ignoring: %m", grp->gr_name);

                                r = nss_group_to_group_record(grp, r >= 0 ? &sgrp : NULL, &z);
                                if (r < 0) {
                                        endgrent();
                                        return r;
                                }

                                if (last) {
                                        r = varlink_notify(link, last);
                                        if (r < 0) {
                                                endgrent();
                                                return r;
                                        }

                                        last = json_variant_unref(last);
                                }

                                r = build_group_json(link, z, &last);
                                if (r < 0) {
                                        endgrent();
                                        return r;
                                }
                        }

                        endgrent();

                        if (!last)
                                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

                        return varlink_reply(link, last);
                }

        } else if (streq_ptr(p.service, "io.systemd.Multiplexer")) {

                if (gid_is_valid(p.gid))
                        r = groupdb_by_gid(p.gid, USERDB_AVOID_MULTIPLEXER, &g);
                else if (p.group_name)
                        r = groupdb_by_name(p.group_name, USERDB_AVOID_MULTIPLEXER, &g);
                else {
                        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
                        _cleanup_(json_variant_unrefp) JsonVariant *last = NULL;

                        r = groupdb_all(USERDB_AVOID_MULTIPLEXER, &iterator);
                        if (r < 0)
                                return r;

                        for (;;) {
                                _cleanup_(group_record_unrefp) GroupRecord *z = NULL;

                                r = groupdb_iterator_get(iterator, &z);
                                if (r == -ESRCH)
                                        break;
                                if (r < 0)
                                        return r;

                                if (last) {
                                        r = varlink_notify(link, last);
                                        if (r < 0)
                                                return r;

                                        last = json_variant_unref(last);
                                }

                                r = build_group_json(link, z, &last);
                                if (r < 0)
                                        return r;
                        }

                        if (!last)
                                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

                        return varlink_reply(link, last);
                }
        } else
                return varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);
        if (r == -ESRCH)
                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
        if (r < 0) {
                log_debug_errno(r, "Group lookup failed abnormally: %m");
                return varlink_error(link, "io.systemd.UserDatabase.ServiceNotAvailable", NULL);
        }

        if ((uid_is_valid(p.gid) && g->gid != p.gid) ||
            (p.group_name && !streq(g->group_name, p.group_name)))
                return varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        r = build_group_json(link, g, &v);
        if (r < 0)
                return r;

        return varlink_reply(link, v);
}

static int vl_method_get_memberships(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        static const JsonDispatch dispatch_table[] = {
                { "userName",  JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, user_name), 0 },
                { "groupName", JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, group_name), 0 },
                { "service",   JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, service),   0 },
                {}
        };

        LookupParameters p = {};
        int r;

        assert(parameters);

        r = json_dispatch(parameters, dispatch_table, NULL, 0, &p);
        if (r < 0)
                return r;

        if (streq_ptr(p.service, "io.systemd.NameServiceSwitch")) {

                if (p.group_name) {
                        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;
                        const char *last = NULL;
                        char **i;

                        r = nss_group_record_by_name(p.group_name, true, &g);
                        if (r == -ESRCH)
                                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
                        if (r < 0)
                                return r;

                        STRV_FOREACH(i, g->members) {

                                if (p.user_name && !streq_ptr(p.user_name, *i))
                                        continue;

                                if (last) {
                                        r = varlink_notifyb(link, JSON_BUILD_OBJECT(
                                                                            JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(last)),
                                                                            JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(g->group_name))));
                                        if (r < 0)
                                                return r;
                                }

                                last = *i;
                        }

                        if (!last)
                                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);

                        return varlink_replyb(link, JSON_BUILD_OBJECT(
                                                              JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(last)),
                                                              JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(g->group_name))));
                } else {
                        _cleanup_free_ char *last_user_name = NULL, *last_group_name = NULL;

                        setgrent();

                        for (;;) {
                                struct group *grp;
                                const char* two[2], **users, **i;

                                errno = 0;
                                grp = getgrent();
                                if (!grp) {
                                        if (errno != 0)
                                                log_debug_errno(errno, "Failure while iterating through NSS group database, ignoring: %m");

                                        break;
                                }

                                if (p.user_name) {
                                        if (!strv_contains(grp->gr_mem, p.user_name))
                                                continue;

                                        two[0] = p.user_name;
                                        two[1] = NULL;

                                        users = two;
                                } else
                                        users = (const char**) grp->gr_mem;

                                STRV_FOREACH(i, users) {

                                        if (last_user_name) {
                                                assert(last_group_name);

                                                r = varlink_notifyb(link, JSON_BUILD_OBJECT(
                                                                                    JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(last_user_name)),
                                                                                    JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(last_group_name))));
                                                if (r < 0) {
                                                        endgrent();
                                                        return r;
                                                }

                                                free(last_user_name);
                                                free(last_group_name);
                                        }

                                        last_user_name = strdup(*i);
                                        last_group_name = strdup(grp->gr_name);
                                        if (!last_user_name || !last_group_name) {
                                                endgrent();
                                                return -ENOMEM;
                                        }
                                }
                        }

                        endgrent();

                        if (!last_user_name) {
                                assert(!last_group_name);
                                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
                        }

                        assert(last_group_name);

                        return varlink_replyb(link, JSON_BUILD_OBJECT(
                                                              JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(last_user_name)),
                                                              JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(last_group_name))));
                }

        } else if (streq_ptr(p.service, "io.systemd.Multiplexer")) {

                _cleanup_free_ char *last_user_name = NULL, *last_group_name = NULL;
                _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;

                if (p.group_name)
                        r = membershipdb_by_group(p.group_name, USERDB_AVOID_MULTIPLEXER, &iterator);
                else if (p.user_name)
                        r = membershipdb_by_user(p.user_name, USERDB_AVOID_MULTIPLEXER, &iterator);
                else
                        r = membershipdb_all(USERDB_AVOID_MULTIPLEXER, &iterator);
                if (r < 0)
                        return r;

                for (;;) {
                        _cleanup_free_ char *user_name = NULL, *group_name = NULL;

                        r = membershipdb_iterator_get(iterator, &user_name, &group_name);
                        if (r == -ESRCH)
                                break;
                        if (r < 0)
                                return r;

                        /* If both group + user are specified do a-posteriori filtering */
                        if (p.group_name && p.user_name && !streq(group_name, p.group_name))
                                continue;

                        if (last_user_name) {
                                assert(last_group_name);

                                r = varlink_notifyb(link, JSON_BUILD_OBJECT(
                                                                    JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(last_user_name)),
                                                                    JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(last_group_name))));
                                if (r < 0)
                                        return r;

                                free(last_user_name);
                                free(last_group_name);
                        }

                        last_user_name = TAKE_PTR(user_name);
                        last_group_name = TAKE_PTR(group_name);
                }

                if (!last_user_name) {
                        assert(!last_group_name);
                        return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
                }

                assert(last_group_name);

                return varlink_replyb(link, JSON_BUILD_OBJECT(
                                                      JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(last_user_name)),
                                                      JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(last_group_name))));
        }

        return varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);
}

static int process_connection(VarlinkServer *server, int fd) {
        _cleanup_(varlink_close_unrefp) Varlink *vl = NULL;
        int r;

        r = varlink_server_add_connection(server, fd, &vl);
        if (r < 0) {
                fd = safe_close(fd);
                return log_error_errno(r, "Failed to add connection: %m");
        }

        vl = varlink_ref(vl);

        for (;;) {
                r = varlink_process(vl);
                if (r == -ENOTCONN) {
                        log_debug("Connection terminated.");
                        break;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to process connection: %m");
                if (r > 0)
                        continue;

                r = varlink_wait(vl, CONNECTION_IDLE_USEC);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for connection events: %m");
                if (r == 0)
                        break;
        }

        return 0;
}

static int run(int argc, char *argv[]) {
        usec_t start_time, listen_idle_usec, last_busy_usec = USEC_INFINITY;
        _cleanup_(varlink_server_unrefp) VarlinkServer *server = NULL;
        unsigned n_iterations = 0;
        int m, listen_fd, r;

        log_setup();

        m = sd_listen_fds(false);
        if (m < 0)
                return log_error_errno(m, "Failed to determine number of listening fds: %m");
        if (m == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No socket to listen on received.");
        if (m > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Worker can only listen on a single socket at a time.");

        listen_fd = SD_LISTEN_FDS_START;

        r = fd_nonblock(listen_fd, false);
        if (r < 0)
                return log_error_errno(r, "Failed to turn off non-blocking mode for listening socket: %m");

        r = varlink_server_new(&server, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate server: %m");

        r = varlink_server_bind_method_many(
                        server,
                        "io.systemd.UserDatabase.GetUserRecord",  vl_method_get_user_record,
                        "io.systemd.UserDatabase.GetGroupRecord", vl_method_get_group_record,
                        "io.systemd.UserDatabase.GetMemberships", vl_method_get_memberships);
        if (r < 0)
                return log_error_errno(r, "Failed to bind methods: %m");

        r = getenv_bool("USERDB_FIXED_WORKER");
        if (r < 0)
                return log_error_errno(r, "Failed to parse USERDB_FIXED_WORKER: %m");
        listen_idle_usec = r ? USEC_INFINITY : LISTEN_IDLE_USEC;

        r = userdb_block_nss_systemd(true);
        if (r < 0)
                return log_error_errno(r, "Failed to disable userdb NSS compatibility: %m");

        start_time = now(CLOCK_MONOTONIC);

        for (;;) {
                _cleanup_close_ int fd = -1;
                usec_t n;

                /* Exit the worker in regular intervals, to flush out all memory use */
                if (n_iterations++ > ITERATIONS_MAX) {
                        log_debug("Exiting worker, processed %u iterations, that's enough.", n_iterations);
                        break;
                }

                n = now(CLOCK_MONOTONIC);
                if (n >= usec_add(start_time, RUNTIME_MAX_USEC)) {
                        char buf[FORMAT_TIMESPAN_MAX];
                        log_debug("Exiting worker, ran for %s, that's enough.",
                                  format_timespan(buf, sizeof(buf), usec_sub_unsigned(n, start_time), 0));
                        break;
                }

                if (last_busy_usec == USEC_INFINITY)
                        last_busy_usec = n;
                else if (listen_idle_usec != USEC_INFINITY && n >= usec_add(last_busy_usec, listen_idle_usec)) {
                        char buf[FORMAT_TIMESPAN_MAX];
                        log_debug("Exiting worker, been idle for %s.",
                                  format_timespan(buf, sizeof(buf), usec_sub_unsigned(n, last_busy_usec), 0));
                        break;
                }

                (void) rename_process("systemd-userwork: waiting...");

                fd = accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
                if (fd < 0)
                        fd = -errno;

                (void) rename_process("systemd-userwork: processing...");

                if (fd == -EAGAIN)
                        continue; /* The listening socket has SO_RECVTIMEO set, hence a timeout is expected
                                   * after a while, let's check if it's time to exit though. */
                if (fd == -EINTR)
                        continue; /* Might be that somebody attached via strace, let's just continue in that
                                   * case */
                if (fd < 0)
                        return log_error_errno(fd, "Failed to accept() from listening socket: %m");

                if (now(CLOCK_MONOTONIC) <= usec_add(n, PRESSURE_SLEEP_TIME_USEC)) {
                        /* We only slept a very short time? If so, let's see if there are more sockets
                         * pending, and if so, let's ask our parent for more workers */

                        r = fd_wait_for_event(listen_fd, POLLIN, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to test for POLLIN on listening socket: %m");

                        if (FLAGS_SET(r, POLLIN)) {
                                pid_t parent;

                                parent = getppid();
                                if (parent <= 1)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Parent already died?");

                                if (kill(parent, SIGUSR2) < 0)
                                        return log_error_errno(errno, "Failed to kill our own parent.");
                        }
                }

                (void) process_connection(server, TAKE_FD(fd));
                last_busy_usec = USEC_INFINITY;
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
