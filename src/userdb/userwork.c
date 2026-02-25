/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>

#include "sd-daemon.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "argv-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "group-record.h"
#include "io-util.h"
#include "json-util.h"
#include "main-func.h"
#include "pidref.h"
#include "string-util.h"
#include "time-util.h"
#include "user-record.h"
#include "user-util.h"
#include "userdb.h"
#include "varlink-io.systemd.UserDatabase.h"
#include "varlink-util.h"

#define ITERATIONS_MAX 64U
#define RUNTIME_MAX_USEC (5 * USEC_PER_MINUTE)
#define PRESSURE_SLEEP_TIME_USEC (50 * USEC_PER_MSEC)
#define CONNECTION_IDLE_USEC (15 * USEC_PER_SEC)
#define LISTEN_IDLE_USEC (90 * USEC_PER_SEC)

typedef struct LookupParameters {
        const char *name;
        union {
                uid_t uid;
                gid_t gid;
        };
        const char *service;
        UserDBMatch match;
} LookupParameters;

static void lookup_parameters_done(LookupParameters *p) {
        assert(p);

        userdb_match_done(&p->match);
}

static int add_nss_service(sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *status = NULL, *z = NULL;
        sd_id128_t mid;
        int r;

        assert(v);

        /* Patch in service field if it's missing. The assumption here is that this field is unset only for
         * NSS records */

        if (sd_json_variant_by_key(*v, "service"))
                return 0;

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return r;

        status = sd_json_variant_ref(sd_json_variant_by_key(*v, "status"));
        z = sd_json_variant_ref(sd_json_variant_by_key(status, SD_ID128_TO_STRING(mid)));

        if (sd_json_variant_by_key(z, "service"))
                return 0;

        r = sd_json_variant_set_field_string(&z, "service", "io.systemd.NameServiceSwitch");
        if (r < 0)
                return r;

        r = sd_json_variant_set_field(&status, SD_ID128_TO_STRING(mid), z);
        if (r < 0)
                return r;

        return sd_json_variant_set_field(v, "status", status);
}

static int build_user_json(sd_varlink *link, UserRecord *ur, sd_json_variant **ret) {
        _cleanup_(user_record_unrefp) UserRecord *stripped = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        UserRecordLoadFlags flags;
        uid_t peer_uid;
        bool trusted;
        int r;

        assert(ur);
        assert(ret);

        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0) {
                log_debug_errno(r, "Unable to query peer UID, ignoring: %m");
                trusted = false;
        } else
                trusted = peer_uid == 0 || peer_uid == ur->uid;

        flags = USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_BINDING|USER_RECORD_STRIP_SECRET|USER_RECORD_ALLOW_STATUS|USER_RECORD_ALLOW_SIGNATURE|USER_RECORD_PERMISSIVE;
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

        v = sd_json_variant_ref(stripped->json);
        r = add_nss_service(&v);
        if (r < 0)
                return r;

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_VARIANT("record", v),
                        SD_JSON_BUILD_PAIR_BOOLEAN("incomplete", stripped->incomplete));
}

static int userdb_flags_from_service(sd_varlink *link, const char *service, UserDBFlags *ret) {
        assert(link);
        assert(ret);

        if (streq_ptr(service, "io.systemd.NameServiceSwitch"))
                *ret = USERDB_NSS_ONLY|USERDB_AVOID_MULTIPLEXER;
        else if (streq_ptr(service, "io.systemd.DropIn"))
                *ret = USERDB_DROPIN_ONLY|USERDB_AVOID_MULTIPLEXER;
        else if (streq_ptr(service, "io.systemd.Multiplexer"))
                *ret = USERDB_AVOID_MULTIPLEXER;
        else
                return sd_varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        return 0;
}

static int vl_method_get_user_record(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "uid",             _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,            offsetof(LookupParameters, uid),                    0             },
                { "userName",        SD_JSON_VARIANT_STRING,        json_dispatch_const_user_group_name, offsetof(LookupParameters, name),                   SD_JSON_RELAX },
                { "service",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,       offsetof(LookupParameters, service),                0             },
                { "fuzzyNames",      SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,               offsetof(LookupParameters, match.fuzzy_names),      0             },
                { "dispositionMask", SD_JSON_VARIANT_ARRAY,         json_dispatch_dispositions_mask,     offsetof(LookupParameters, match.disposition_mask), 0             },
                { "uidMin",          _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,            offsetof(LookupParameters, match.uid_min),          0             },
                { "uidMax",          _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,            offsetof(LookupParameters, match.uid_max),          0             },
                { "uuid",            SD_JSON_VARIANT_STRING,        sd_json_dispatch_id128,              offsetof(LookupParameters, match.uuid),             0             },
                {}
        };

        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        _cleanup_(lookup_parameters_done) LookupParameters p = {
                .uid = UID_INVALID,
                .match = USERDB_MATCH_NULL,
        };
        UserDBFlags userdb_flags;
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = userdb_flags_from_service(link, p.service, &userdb_flags);
        if (r != 0) /* return value of < 0 means error (as usual); > 0 means 'already processed and replied,
                     * we are done'; == 0 means 'not processed, caller should process now' */
                return r;

        r = varlink_set_sentinel(link, "io.systemd.UserDatabase.NoRecordFound");
        if (r < 0)
                return r;

        if (uid_is_valid(p.uid))
                r = userdb_by_uid(p.uid, &p.match, userdb_flags, &hr);
        else if (p.name)
                r = userdb_by_name(p.name, &p.match, userdb_flags, &hr);
        else {
                _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;

                r = userdb_all(&p.match, userdb_flags, &iterator);
                if (IN_SET(r, -ESRCH, -ENOLINK))
                        /* We turn off Varlink lookups in various cases (e.g. in case we only enable DropIn
                         * backend) — this might make userdb_all return ENOLINK (which indicates that varlink
                         * was off and no other suitable source or entries were found). Let's hide this
                         * implementation detail and always return NoRecordFound in this case, since from a
                         * client's perspective it's irrelevant if there was no entry at all or just not on
                         * the service that the query was limited to. */
                        return 0;
                if (r < 0)
                        return r;

                for (;;) {
                        _cleanup_(user_record_unrefp) UserRecord *z = NULL;

                        r = userdb_iterator_get(iterator, &p.match, &z);
                        if (r == -ESRCH)
                                break;
                        if (r < 0)
                                return r;

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                        r = build_user_json(link, z, &v);
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
        if (r == -ENOEXEC)
                return sd_varlink_error(link, "io.systemd.UserDatabase.NonMatchingRecordFound", NULL);
        if (r < 0) {
                log_debug_errno(r, "User lookup failed abnormally: %m");
                return sd_varlink_error(link, "io.systemd.UserDatabase.ServiceNotAvailable", NULL);
        }

        if ((uid_is_valid(p.uid) && hr->uid != p.uid) ||
            (p.name && !user_record_matches_user_name(hr, p.name)))
                return sd_varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = build_user_json(link, hr, &v);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, v);
}

static int build_group_json(sd_varlink *link, GroupRecord *gr, sd_json_variant **ret) {
        _cleanup_(group_record_unrefp) GroupRecord *stripped = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        UserRecordLoadFlags flags;
        uid_t peer_uid;
        bool trusted;
        int r;

        assert(gr);
        assert(ret);

        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0) {
                log_debug_errno(r, "Unable to query peer UID, ignoring: %m");
                trusted = false;
        } else
                trusted = peer_uid == 0;

        flags = USER_RECORD_REQUIRE_REGULAR|USER_RECORD_ALLOW_PER_MACHINE|USER_RECORD_ALLOW_BINDING|USER_RECORD_STRIP_SECRET|USER_RECORD_ALLOW_STATUS|USER_RECORD_ALLOW_SIGNATURE|USER_RECORD_PERMISSIVE;
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

        v = sd_json_variant_ref(stripped->json);
        r = add_nss_service(&v);
        if (r < 0)
                return r;

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_VARIANT("record", v),
                        SD_JSON_BUILD_PAIR_BOOLEAN("incomplete", stripped->incomplete));
}

static int vl_method_get_group_record(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "gid",             _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,            offsetof(LookupParameters, gid),                    0             },
                { "groupName",       SD_JSON_VARIANT_STRING,        json_dispatch_const_user_group_name, offsetof(LookupParameters, name),                   SD_JSON_RELAX },
                { "service",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,       offsetof(LookupParameters, service),                0             },
                { "fuzzyNames",      SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,               offsetof(LookupParameters, match.fuzzy_names),      0             },
                { "dispositionMask", SD_JSON_VARIANT_ARRAY,         json_dispatch_dispositions_mask,     offsetof(LookupParameters, match.disposition_mask), 0             },
                { "gidMin",          _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,            offsetof(LookupParameters, match.gid_min),          0             },
                { "gidMax",          _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,            offsetof(LookupParameters, match.gid_max),          0             },
                { "uuid",            SD_JSON_VARIANT_STRING,        sd_json_dispatch_id128,              offsetof(LookupParameters, match.uuid),             0             },
                {}
        };

        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;
        _cleanup_(lookup_parameters_done) LookupParameters p = {
                .gid = GID_INVALID,
                .match = USERDB_MATCH_NULL,
        };
        UserDBFlags userdb_flags;
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = userdb_flags_from_service(link, p.service, &userdb_flags);
        if (r != 0)
                return r;

        r = varlink_set_sentinel(link, "io.systemd.UserDatabase.NoRecordFound");
        if (r < 0)
                return r;

        if (gid_is_valid(p.gid))
                r = groupdb_by_gid(p.gid, &p.match, userdb_flags, &g);
        else if (p.name)
                r = groupdb_by_name(p.name, &p.match, userdb_flags, &g);
        else {
                _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;

                r = groupdb_all(&p.match, userdb_flags, &iterator);
                if (IN_SET(r, -ESRCH, -ENOLINK))
                        return 0;
                if (r < 0)
                        return r;

                for (;;) {
                        _cleanup_(group_record_unrefp) GroupRecord *z = NULL;

                        r = groupdb_iterator_get(iterator, &p.match, &z);
                        if (r == -ESRCH)
                                break;
                        if (r < 0)
                                return r;

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                        r = build_group_json(link, z, &v);
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
        if (r == -ENOEXEC)
                return sd_varlink_error(link, "io.systemd.UserDatabase.NonMatchingRecordFound", NULL);
        if (r < 0) {
                log_debug_errno(r, "Group lookup failed abnormally: %m");
                return sd_varlink_error(link, "io.systemd.UserDatabase.ServiceNotAvailable", NULL);
        }

        if ((uid_is_valid(p.gid) && g->gid != p.gid) ||
            (p.name && !group_record_matches_group_name(g, p.name)))
                return sd_varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = build_group_json(link, g, &v);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, v);
}

typedef struct MembershipLookupParameters {
        const char *user_name;
        const char *group_name;
        const char *service;
} MembershipLookupParameters;

static int vl_method_get_memberships(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "userName",  SD_JSON_VARIANT_STRING, json_dispatch_const_user_group_name, offsetof(MembershipLookupParameters, user_name),  SD_JSON_RELAX },
                { "groupName", SD_JSON_VARIANT_STRING, json_dispatch_const_user_group_name, offsetof(MembershipLookupParameters, group_name), SD_JSON_RELAX },
                { "service",   SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,       offsetof(MembershipLookupParameters, service),    0             },
                {}
        };

        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        MembershipLookupParameters p = {};
        UserDBFlags userdb_flags;
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = userdb_flags_from_service(link, p.service, &userdb_flags);
        if (r != 0)
                return r;

        r = varlink_set_sentinel(link, "io.systemd.UserDatabase.NoRecordFound");
        if (r < 0)
                return r;

        if (p.group_name)
                r = membershipdb_by_group(p.group_name, userdb_flags, &iterator);
        else if (p.user_name)
                r = membershipdb_by_user(p.user_name, userdb_flags, &iterator);
        else
                r = membershipdb_all(userdb_flags, &iterator);
        if (IN_SET(r, -ESRCH, -ENOLINK))
                return 0;
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

                r = sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("userName", user_name),
                                SD_JSON_BUILD_PAIR_STRING("groupName", group_name));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int process_connection(sd_varlink_server *server, int _fd) {
        _cleanup_close_ int fd = TAKE_FD(_fd); /* always take possession */
        _cleanup_(sd_varlink_close_unrefp) sd_varlink *vl = NULL;
        int r;

        assert(server);
        assert(fd >= 0);

        r = sd_varlink_server_add_connection(server, fd, &vl);
        if (r < 0)
                return log_error_errno(r, "Failed to add connection: %m");

        TAKE_FD(fd);
        vl = sd_varlink_ref(vl);

        for (;;) {
                r = sd_varlink_process(vl);
                if (r == -ENOTCONN) {
                        log_debug("Connection terminated.");
                        break;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to process connection: %m");
                if (r > 0)
                        continue;

                r = sd_varlink_wait(vl, CONNECTION_IDLE_USEC);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for connection events: %m");
                if (r == 0)
                        break;
        }

        return 0;
}

static int run(int argc, char *argv[]) {
        usec_t start_time, listen_idle_usec, last_busy_usec = USEC_INFINITY;
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        _cleanup_(pidref_done) PidRef parent = PIDREF_NULL;
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

        r = varlink_server_new(&server, 0, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server: %m");

        r = sd_varlink_server_add_interface(server, &vl_interface_io_systemd_UserDatabase);
        if (r < 0)
                return log_error_errno(r, "Failed to add UserDatabase interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
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

        r = pidref_set_parent(&parent);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire pidfd of parent process: %m");
        if (parent.pid == 1) /* We got reparented away from userdbd? */
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "Parent already died, exiting.");

        start_time = now(CLOCK_MONOTONIC);

        for (;;) {
                _cleanup_close_ int fd = -EBADF;
                usec_t n;

                /* Exit the worker in regular intervals, to flush out all memory use */
                if (n_iterations++ > ITERATIONS_MAX) {
                        log_debug("Exiting worker, processed %u iterations, that's enough.", n_iterations);
                        break;
                }

                n = now(CLOCK_MONOTONIC);
                if (n >= usec_add(start_time, RUNTIME_MAX_USEC)) {
                        log_debug("Exiting worker, ran for %s, that's enough.",
                                  FORMAT_TIMESPAN(usec_sub_unsigned(n, start_time), 0));
                        break;
                }

                if (last_busy_usec == USEC_INFINITY)
                        last_busy_usec = n;
                else if (listen_idle_usec != USEC_INFINITY && n >= usec_add(last_busy_usec, listen_idle_usec)) {
                        log_debug("Exiting worker, been idle for %s.",
                                  FORMAT_TIMESPAN(usec_sub_unsigned(n, last_busy_usec), 0));
                        break;
                }

                (void) rename_process("systemd-userwork: waiting...");
                fd = RET_NERRNO(accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC));
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
                                r = pidref_kill(&parent, SIGUSR2);
                                if (r == -ESRCH)
                                        return log_error_errno(r, "Parent already died?");
                                if (r < 0)
                                        return log_error_errno(r, "Failed to send SIGUSR2 signal to parent: %m");
                        }
                }

                (void) process_connection(server, TAKE_FD(fd));
                last_busy_usec = USEC_INFINITY;
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
