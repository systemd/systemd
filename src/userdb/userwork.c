/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "sd-daemon.h"

#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "group-record.h"
#include "io-util.h"
#include "lock-util.h"
#include "main-func.h"
#include "missing_mount.h"
#include "missing_syscall.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "process-util.h"
#include "random-util.h"
#include "stat-util.h"
#include "strv.h"
#include "time-util.h"
#include "uid-range.h"
#include "user-record-nss.h"
#include "user-record.h"
#include "user-util.h"
#include "userdb.h"
#include "userns-restrict.h"
#include "userns-util.h"
#include "varlink.h"
#include "varlink-io.systemd.UserDatabase.h"
#include "varlink-io.systemd.UserRegistry.h"

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
        z = json_variant_ref(json_variant_by_key(status, SD_ID128_TO_STRING(mid)));

        if (json_variant_by_key(z, "service"))
                return 0;

        r = json_variant_set_field_string(&z, "service", "io.systemd.NameServiceSwitch");
        if (r < 0)
                return r;

        r = json_variant_set_field(&status, SD_ID128_TO_STRING(mid), z);
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

        v = json_variant_ref(stripped->json);
        r = add_nss_service(&v);
        if (r < 0)
                return r;

        return json_build(ret, JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("record", JSON_BUILD_VARIANT(v)),
                                          JSON_BUILD_PAIR("incomplete", JSON_BUILD_BOOLEAN(stripped->incomplete))));
}

static int userdb_flags_from_service(Varlink *link, const char *service, UserDBFlags *ret) {
        assert(link);
        assert(ret);

        if (streq_ptr(service, "io.systemd.NameServiceSwitch"))
                *ret = USERDB_NSS_ONLY|USERDB_AVOID_MULTIPLEXER;
        else if (streq_ptr(service, "io.systemd.DropIn"))
                *ret = USERDB_DROPIN_ONLY|USERDB_AVOID_MULTIPLEXER;
        else if (streq_ptr(service, "io.systemd.Multiplexer"))
                *ret = USERDB_AVOID_MULTIPLEXER;
        else
                return varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        return 0;
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
        UserDBFlags userdb_flags;
        int r;

        assert(parameters);

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = userdb_flags_from_service(link, p.service, &userdb_flags);
        if (r != 0) /* return value of < 0 means error (as usual); > 0 means 'already processed and replied,
                     * we are done'; == 0 means 'not processed, caller should process now' */
                return r;

        if (uid_is_valid(p.uid))
                r = userdb_by_uid(p.uid, userdb_flags, &hr);
        else if (p.user_name)
                r = userdb_by_name(p.user_name, userdb_flags, &hr);
        else {
                _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
                _cleanup_(json_variant_unrefp) JsonVariant *last = NULL;

                r = userdb_all(userdb_flags, &iterator);
                if (IN_SET(r, -ESRCH, -ENOLINK))
                        /* We turn off Varlink lookups in various cases (e.g. in case we only enable DropIn
                         * backend) — this might make userdb_all return ENOLINK (which indicates that varlink
                         * was off and no other suitable source or entries were found). Let's hide this
                         * implementation detail and always return NoRecordFound in this case, since from a
                         * client's perspective it's irrelevant if there was no entry at all or just not on
                         * the service that the query was limited to. */
                        return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
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
        UserDBFlags userdb_flags;
        int r;

        assert(parameters);

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = userdb_flags_from_service(link, p.service, &userdb_flags);
        if (r != 0)
                return r;

        if (gid_is_valid(p.gid))
                r = groupdb_by_gid(p.gid, userdb_flags, &g);
        else if (p.group_name)
                r = groupdb_by_name(p.group_name, userdb_flags, &g);
        else {
                _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
                _cleanup_(json_variant_unrefp) JsonVariant *last = NULL;

                r = groupdb_all(userdb_flags, &iterator);
                if (IN_SET(r, -ESRCH, -ENOLINK))
                        return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
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
                { "userName",  JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, user_name),  0 },
                { "groupName", JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, group_name), 0 },
                { "service",   JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, service),    0 },
                {}
        };

        _cleanup_free_ char *last_user_name = NULL, *last_group_name = NULL;
        _cleanup_(userdb_iterator_freep) UserDBIterator *iterator = NULL;
        LookupParameters p = {};
        UserDBFlags userdb_flags;
        int r;

        assert(parameters);

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = userdb_flags_from_service(link, p.service, &userdb_flags);
        if (r != 0)
                return r;

        if (p.group_name)
                r = membershipdb_by_group(p.group_name, userdb_flags, &iterator);
        else if (p.user_name)
                r = membershipdb_by_user(p.user_name, userdb_flags, &iterator);
        else
                r = membershipdb_all(userdb_flags, &iterator);
        if (IN_SET(r, -ESRCH, -ENOLINK))
                return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
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
                }

                free_and_replace(last_user_name, user_name);
                free_and_replace(last_group_name, group_name);
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

static int uid_is_available(
                int registry_dir_fd,
                uid_t candidate) {

        _cleanup_free_ char *fn = NULL;
        int r;

        assert(registry_dir_fd >= 0);

        log_debug("Checking if UID " UID_FMT " is available.", candidate);

        if (asprintf(&fn, "u" UID_FMT ".userns", candidate) < 0)
                return -ENOMEM;

        if (faccessat(registry_dir_fd, fn, F_OK, AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno != ENOENT)
                        return -errno;
        } else
                return false;

        r = userdb_by_uid(candidate, USERDB_AVOID_MULTIPLEXER, NULL);
        if (r >= 0)
                return false;
        if (r != -ESRCH)
                return r;

        r = groupdb_by_gid(candidate, USERDB_AVOID_MULTIPLEXER, NULL);
        if (r >= 0)
                return false;
        if (r != -ESRCH)
                return r;

        log_debug("UID " UID_FMT " is available.", candidate);

        return true;
}

static int allocate_now(
                int registry_dir_fd,
                const char *name,
                uid_t size,
                uid_t *ret_start,
                LockFile *ret_lock_file) {

        static const uint8_t hash_key[16] = {
                0xd4, 0xd7, 0x33, 0xa7, 0x4d, 0xd3, 0x42, 0xcd,
                0xaa, 0xe9, 0x45, 0xd0, 0xfb, 0xec, 0x79, 0xee,
        };

        _cleanup_(uid_range_freep) UidRange *valid_range = NULL;
        uid_t candidate, uidmin, uidmax, uidmask;
        unsigned n_tries = 100;
        int r;

        assert(registry_dir_fd >= 0);
        assert(name);

        switch (size) {

        case 0x10000U:
                uidmin = CONTAINER_UID_BASE_MIN;
                uidmax = CONTAINER_UID_BASE_MAX;
                uidmask = (uid_t) UINT32_C(0xFFFF0000);
                break;

        case 1U:
                uidmin = DYNAMIC_UID_MIN;
                uidmax = DYNAMIC_UID_MAX;
                uidmask = (uid_t) UINT32_C(0xFFFFFFFF);
                break;

        default:
                assert_not_reached();
        }

        r = uid_range_load_userns(&valid_range, /* path= */ NULL, UID_RANGE_USERNS_INSIDE);
        if (r < 0)
                return r;

        /* Check early whether we have any chance at all given our own uid range */
        if (!uid_range_overlaps(valid_range, uidmin, uidmax))
                return log_debug_errno(SYNTHETIC_ERRNO(EHOSTDOWN), "Relevant UID range not delegated, can't allocate.");

        (void) mkdir("/run/systemd/userdbd/lock/", 0755);

        for (candidate = siphash24_string(name, hash_key) & UINT32_MAX;; /* Start from a hash of the input name */
             candidate = random_u32()) {                                 /* Use random values afterwards */
                _cleanup_free_ char *lock_path = NULL;
                _cleanup_(release_lock_file) LockFile lf = LOCK_FILE_INIT;

                if (--n_tries <= 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBUSY), "Try limit hit, no UIDs available.");

                candidate = (candidate % (uidmax - uidmin)) + uidmin;
                candidate &= uidmask;

                if (!uid_range_covers(valid_range, candidate, size))
                        continue;

                if (asprintf(&lock_path, "/run/systemd/userdbd/lock/" UID_FMT ".lock", candidate) < 0)
                        return -ENOMEM;

                r = make_lock_file(lock_path, LOCK_EX|LOCK_NB, &lf);
                if (r == -EBUSY) /* Being checked by some other worker or other process, let's not bother */
                        continue;
                if (r < 0)
                        return r;

                /* We only check the base UID for each range (!) */
                r = uid_is_available(registry_dir_fd, candidate);
                if (r < 0)
                        return log_debug_errno(r, "Can't determine if UID range " UID_FMT " is available: %m", candidate);
                if (r > 0) {
                        if (ret_lock_file) {
                                *ret_lock_file = lf;
                                lf = (struct LockFile) LOCK_FILE_INIT;
                        }
                        if (ret_start)
                                *ret_start = candidate;

                        log_debug("Allocating UID range " UID_FMT "…" UID_FMT, candidate, candidate + size - 1);
                        return 0;
                }

                log_debug("UID range " UID_FMT " already taken.", candidate);
        }
}

static int write_userns(int usernsfd, uid_t target, uid_t start, uid_t size) {
        _cleanup_(sigkill_waitp) pid_t pid = 0;
        _cleanup_close_ int efd = -EBADF;
        uint64_t u;
        int r;

        assert(usernsfd >= 0);
        assert(uid_is_valid(target));
        assert(uid_is_valid(start));
        assert(size > 0);
        assert(size <= UINT32_MAX - start);

        efd = eventfd(0, EFD_CLOEXEC);
        if (efd < 0)
                return log_error_errno(errno, "Failed to allocate eventfd(): %m");

        r = safe_fork("(sd-userns)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* child */

                if (setns(usernsfd, CLONE_NEWUSER) < 0) {
                        log_error_errno(errno, "Failed to join user namespace: %m");
                        goto child_fail;
                }

                if (eventfd_write(efd, 1) < 0) {
                        log_error_errno(errno, "Failed to ping event fd: %m");
                        goto child_fail;
                }

                freeze();

        child_fail:
                _exit(EXIT_FAILURE);
        }

        /* Wait until child joined the user namespace */
        if (eventfd_read(efd, &u) < 0)
                return log_error_errno(errno, "Failed to wait for event fd: %m");

        /* Now write mapping */

        _cleanup_free_ char *pmap = NULL;

        if (asprintf(&pmap, "/proc/" PID_FMT "/uid_map", pid) < 0)
                return log_oom();

        r = write_string_filef(pmap, 0, UID_FMT " " UID_FMT " " UID_FMT "\n", target, start, size);
        if (r < 0)
                return log_error_errno(r, "Failed to write 'uid_map' file of user namespace: %m");

        pmap = mfree(pmap);
        if (asprintf(&pmap, "/proc/" PID_FMT "/gid_map", pid) < 0)
                return log_oom();

        r = write_string_filef(pmap, 0, GID_FMT " " GID_FMT " " GID_FMT "\n", (gid_t) target, (gid_t) start, (gid_t) size);
        if (r < 0)
                return log_error_errno(r, "Failed to write 'gid_map' file of user namespace: %m");

        /* We are done! */

        log_debug("Successfully configured user namespace.");
        return 0;
}

typedef struct AllocateParameters {
        const char *name;
        unsigned size;
        unsigned target;
        unsigned userns_fd_idx;
} AllocateParameters;

static int vl_method_allocate_user_range(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "name",                        JSON_VARIANT_STRING,        json_dispatch_const_string, offsetof(AllocateParameters, name),          JSON_MANDATORY },
                { "size",                        _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint,         offsetof(AllocateParameters, size),          JSON_MANDATORY },
                { "target",                      _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint,         offsetof(AllocateParameters, target),        0              },
                { "userNamespaceFileDescriptor", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint,         offsetof(AllocateParameters, userns_fd_idx), JSON_MANDATORY },
                {}
        };

        _cleanup_(userns_restrict_bpf_freep) struct userns_restrict_bpf *bpf = NULL;
        _cleanup_free_ char *def_buf = NULL, *reg_fn = NULL, *link_fn = NULL;
        _cleanup_close_ int userns_fd = -EBADF, registry_dir_fd = -EBADF;
        _cleanup_(release_lock_file) LockFile lf = LOCK_FILE_INIT;
        _cleanup_(json_variant_unrefp) JsonVariant *def = NULL;
        bool written = false, linked = false;
        struct stat st;
        uid_t start;
        AllocateParameters p = {
                .size = UINT_MAX,
                .userns_fd_idx = UINT_MAX,
        };
        int r;

        assert(link);
        assert(parameters);

        r = getenv_bool("USERDB_USERNS_API");
        if (r < 0)
                return log_error_errno(r, "Failed to parse $USERDB_USERNS_API: %m");
        if (r == 0)
                return varlink_error(link, "io.systemd.UserDatabase.UserNamespaceInterfaceNotSupported", NULL);

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r < 0)
                return r;

        userns_fd = varlink_take_fd(link, p.userns_fd_idx);
        if (userns_fd < 0)
                return userns_fd;

        if (!valid_user_group_name(p.name, 0))
                return varlink_error_invalid_parameter_name(link, "name");

        if (!IN_SET(p.size, 1U, 0x10000))
                return varlink_error_invalid_parameter_name(link, "size");

        if (!uid_is_valid(p.target) || p.target > UINT32_MAX - p.size)
                return varlink_error_invalid_parameter_name(link, "target");

        /* Validate this is actually a valid user namespace fd */
        r = fd_is_ns(userns_fd, CLONE_NEWUSER);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if user namespace fd actually refers to user name space: %m");
        if (r == 0)
                return varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        r = is_our_namespace(userns_fd, NAMESPACE_USER);
        if (r < 0)
                return r;
        if (r > 0)
                return varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        if (fstat(userns_fd, &st) < 0)
                return log_debug_errno(errno, "Failed to fstat() user namespace fd: %m");

        r = userns_restrict_install(/* pin= */ true, &bpf);
        if (r < 0)
                return r;

        registry_dir_fd = userns_open_registry_fd();
        if (registry_dir_fd < 0)
                return registry_dir_fd;

        r = allocate_now(registry_dir_fd, p.name, p.size, &start, &lf);
        if (r == -EHOSTDOWN) /* The needed UID range is not delegated to us */
                return varlink_error(link, "io.systemd.UserDatabase.DynamicRangeUnavailable", NULL);
        if (r == -EBUSY)     /* All used up */
                return varlink_error(link, "io.systemd.UserDatabase.NoDynamicRange", NULL);
        if (r < 0)
                return r;

        r = json_build(&def, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("name", JSON_BUILD_STRING(p.name)),
                                       JSON_BUILD_PAIR("userns", JSON_BUILD_UNSIGNED(st.st_ino)),
                                       JSON_BUILD_PAIR("start", JSON_BUILD_UNSIGNED(start)),
                                       JSON_BUILD_PAIR("size", JSON_BUILD_UNSIGNED(p.size)),
                                       JSON_BUILD_PAIR("target", JSON_BUILD_UNSIGNED(p.target))));
        if (r < 0)
                return log_debug_errno(r, "Failed to build userns JSON object: %m");

        r = json_variant_format(def, 0, &def_buf);
        if (r < 0)
                return log_debug_errno(r, "Failed to format userns JSON object: %m");

        if (asprintf(&reg_fn, "n" INO_FMT ".userns", st.st_ino) < 0)
                return log_oom_debug();
        if (asprintf(&link_fn, "u" UID_FMT ".userns", start) < 0)
                return log_oom_debug();

        r = write_string_file_at(registry_dir_fd, reg_fn, def_buf, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
        if (r < 0)
                return log_error_errno(r, "Failed to write UID range data to '%s' in registry: %m", reg_fn);

        written = true;

        r = RET_NERRNO(linkat(registry_dir_fd, reg_fn, registry_dir_fd, link_fn, 0));
        if (r < 0) {
                log_error_errno(r, "Failed to link UID range data to to '%s' in registry: %m", link_fn);
                goto fail;
        }

        linked = true;

        /* Register the userns in the BPF map with an empty allowlist */
        r = userns_restrict_put_by_fd(
                        bpf,
                        userns_fd,
                        /* replace= */ true,
                        /* mount_fds= */ NULL,
                        /* n_mount_fds= */ 0);
        if (r < 0)
                goto fail;

        r = write_userns(userns_fd, p.target, start, p.size);
        if (r < 0)
                goto fail;

        /* Send user namespace and process fd to our manager process, which will watch the process and user namespace */
        r = sd_pid_notifyf_with_fds(
                        /* pid= */ 0,
                        /* unset_environment= */ false,
                        &userns_fd, 1,
                        "FDSTORE=1\n"
                        "FDNAME=userns-" INO_FMT "\n", st.st_ino);
        if (r < 0)
                goto fail;

        /* Note, we'll not return UID values from the host, since the child might not run in the same
         * user namespace as us. If they want to know the ranges they should read them off the userns fd, so
         * that they are translated into their PoV */

        return varlink_replyb(link, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("start", JSON_BUILD_UNSIGNED(start))));

fail:
        if (written)
                (void) unlinkat(ASSERT_FD(registry_dir_fd), ASSERT_PTR(reg_fn), 0);

        if (linked)
                (void) unlinkat(ASSERT_FD(registry_dir_fd), ASSERT_PTR(link_fn), 0);

        /* Note: we don't have to clean-up the BPF maps in the error path: the bpf map type used will
         * automatically do that once the userns inode goes away */
        return r;
}

typedef struct RegisterParameters {
        const char *name;
        unsigned userns_fd_idx;
} RegisterParameters;

static int vl_method_register_user_namespace(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "name",                        JSON_VARIANT_STRING,        json_dispatch_const_string, offsetof(RegisterParameters, name),          JSON_MANDATORY },
                { "userNamespaceFileDescriptor", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint,         offsetof(RegisterParameters, userns_fd_idx), JSON_MANDATORY },
                {}
        };

        _cleanup_(userns_restrict_bpf_freep) struct userns_restrict_bpf *bpf = NULL;
        _cleanup_free_ char *def_buf = NULL, *reg_fn = NULL;
        _cleanup_close_ int userns_fd = -EBADF, registry_dir_fd = -EBADF;
        _cleanup_(json_variant_unrefp) JsonVariant *def = NULL;
        bool written = false;
        struct stat st;
        RegisterParameters p = {
                .userns_fd_idx = UINT_MAX,
        };
        int r;

        assert(link);
        assert(parameters);

        r = getenv_bool("USERDB_USERNS_API");
        if (r < 0)
                return log_error_errno(r, "Failed to parse $USERDB_USERNS_API: %m");
        if (r == 0)
                return varlink_error(link, "io.systemd.UserDatabase.UserNamespaceInterfaceNotSupported", NULL);

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r < 0)
                return r;

        userns_fd = varlink_take_fd(link, p.userns_fd_idx);
        if (userns_fd < 0)
                return userns_fd;

        /* Validate this is actually a valid user namespace fd */
        r = fd_is_ns(userns_fd, CLONE_NEWUSER);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if user namespace fd actually refers to user name space: %m");
        if (r == 0)
                return varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        r = is_our_namespace(userns_fd, NAMESPACE_USER);
        if (r < 0)
                return r;
        if (r > 0)
                return varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        if (fstat(userns_fd, &st) < 0)
                return log_debug_errno(errno, "Failed to fstat() user namespace fd: %m");

        r = userns_restrict_install(/* pin= */ true, &bpf);
        if (r < 0)
                return r;

        registry_dir_fd = userns_open_registry_fd();
        if (registry_dir_fd < 0)
                return registry_dir_fd;

        r = json_build(&def, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("name", JSON_BUILD_STRING(p.name)),
                                       JSON_BUILD_PAIR("userns", JSON_BUILD_UNSIGNED(st.st_ino))));
        if (r < 0)
                return log_debug_errno(r, "Failed to build userns JSON object: %m");

        r = json_variant_format(def, 0, &def_buf);
        if (r < 0)
                return log_debug_errno(r, "Failed to format userns JSON object: %m");

        if (asprintf(&reg_fn, "n" INO_FMT ".userns", st.st_ino) < 0)
                return log_oom_debug();

        r = write_string_file_at(registry_dir_fd, reg_fn, def_buf, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
        if (r < 0)
                return log_error_errno(r, "Failed to write UID range data to '%s' in registry: %m", reg_fn);

        written = true;

        /* Register the userns in the BPF map with an empty allowlist */
        r = userns_restrict_put_by_fd(
                        bpf,
                        userns_fd,
                        /* replace= */ true,
                        /* mount_fds= */ NULL,
                        /* n_mount_fds= */ 0);
        if (r < 0)
                goto fail;

        /* Send user namespace and process fd to our manager process, which will watch the process and user namespace */
        r = sd_pid_notifyf_with_fds(
                        /* pid= */ 0,
                        /* unset_environment= */ false,
                        &userns_fd, 1,
                        "FDSTORE=1\n"
                        "FDNAME=userns-" INO_FMT "\n", st.st_ino);
        if (r < 0)
                goto fail;

        return varlink_replyb(link, JSON_BUILD_EMPTY_OBJECT);

fail:
        if (written)
                (void) unlinkat(ASSERT_FD(registry_dir_fd), ASSERT_PTR(reg_fn), 0);

        /* Note: we don't have to clean-up the BPF maps in the error path: the bpf map type used will
         * automatically do that once the userns inode goes away */
        return r;
}

typedef struct AddMountParameters {
        unsigned userns_fd_idx;
        unsigned mount_fd_idx;
} AddMountParameters;

static int vl_method_add_mount_to_user_namespace(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const JsonDispatch parameter_dispatch_table[] = {
                { "userNamespaceFileDescriptor", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint, offsetof(AddMountParameters, userns_fd_idx), JSON_MANDATORY },
                { "mountFileDescriptor",         _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint, offsetof(AddMountParameters, mount_fd_idx),  JSON_MANDATORY },
                {}
        };

        _cleanup_(userns_restrict_bpf_freep) struct userns_restrict_bpf *bpf = NULL;
        _cleanup_close_ int userns_fd = -EBADF, mount_fd = -EBADF;
        AddMountParameters p = {
                .userns_fd_idx = UINT_MAX,
                .mount_fd_idx = UINT_MAX,
        };
        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        int r, mnt_id = 0;
        struct stat st;
        uid_t peer_uid;

        assert(link);
        assert(parameters);

        r = getenv_bool("USERDB_USERNS_API");
        if (r < 0)
                return r;
        if (r == 0)
                return varlink_error(link, "io.systemd.UserDatabase.UserNamespaceInterfaceNotSupported", NULL);

        /* Allowlisting arbitrary mounts is a privileged operation */
        r = varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;
        if (peer_uid != 0)
                return varlink_error(link, VARLINK_ERROR_PERMISSION_DENIED, NULL);

        r = varlink_dispatch(link, parameters, parameter_dispatch_table, &p);
        if (r < 0)
                return r;

        userns_fd = varlink_take_fd(link, p.userns_fd_idx);
        if (userns_fd < 0)
                return userns_fd;

        mount_fd = varlink_take_fd(link, p.mount_fd_idx);
        if (mount_fd < 0)
                return mount_fd;

        /* Validate this is actually a valid user namespace fd */
        r = fd_is_ns(userns_fd, CLONE_NEWUSER);
        if (r < 0)
                return r;
        if (r == 0)
                return varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        r = is_our_namespace(userns_fd, NAMESPACE_USER);
        if (r < 0)
                return r;
        if (r > 0)
                return varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        if (fstat(userns_fd, &st) < 0)
                return -errno;

        r = fd_verify_directory(mount_fd);
        if (r < 0)
                return r;

        r = path_get_mnt_id_at(mount_fd, NULL, &mnt_id);
        if (r < 0)
                return r;

        r = userns_load_json_by_userns_inode(
                        /* dir_fd= */ -EBADF,
                        st.st_ino,
                        &userns_info);
        if (r == -ENOENT)
                return varlink_error(link, "io.systemd.UserRegistry.UserNamespaceNotRegistered", NULL);
        if (r < 0)
                return r;

        r = userns_restrict_install(/* pin= */ true, &bpf);
        if (r < 0)
                return r;

        /* Pin the mount fd */
        r = sd_pid_notifyf_with_fds(
                        /* pid= */ 0,
                        /* unset_environment= */ false,
                        &mount_fd, 1,
                        "FDSTORE=1\n"
                        "FDNAME=userns-" INO_FMT "\n", st.st_ino);
        if (r < 0)
                return r;

        /* Add this mount to the user namespace's BPF map allowlist entry. */
        r = userns_restrict_put_by_fd(
                        bpf,
                        userns_fd,
                        /* replace= */ false,
                        &mount_fd,
                        1);
        if (r < 0)
                return r;

        log_debug("Allowing access to mount %i to user namespace " INO_FMT " ('%s' @ UID " UID_FMT ")",
                  mnt_id, st.st_ino, userns_info->name, userns_info->start);

        return varlink_replyb(link, JSON_BUILD_EMPTY_OBJECT);
}

static int process_connection(VarlinkServer *server, int _fd) {
        _cleanup_close_ int fd = TAKE_FD(_fd); /* always take possesion */
        _cleanup_(varlink_close_unrefp) Varlink *vl = NULL;
        int r;

        r = varlink_server_add_connection(server, fd, &vl);
        if (r < 0)
                return log_error_errno(r, "Failed to add connection: %m");

        TAKE_FD(fd);
        vl = varlink_ref(vl);

        r = varlink_set_allow_fd_passing_input(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable fd passing for read: %m");

        r = varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable fd passing for write: %m");

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

        r = varlink_server_new(&server, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate server: %m");

        r = varlink_server_add_interface_many(
                        server,
                        &vl_interface_io_systemd_UserDatabase,
                        &vl_interface_io_systemd_UserRegistry);
        if (r < 0)
                return log_error_errno(r, "Failed to add UserDatabase and UserRegistry interface to varlink server: %m");

        r = varlink_server_bind_method_many(
                        server,
                        "io.systemd.UserDatabase.GetUserRecord",           vl_method_get_user_record,
                        "io.systemd.UserDatabase.GetGroupRecord",          vl_method_get_group_record,
                        "io.systemd.UserDatabase.GetMemberships",          vl_method_get_memberships,
                        "io.systemd.UserRegistry.AllocateUserRange",       vl_method_allocate_user_range,
                        "io.systemd.UserRegistry.RegisterUserNamespace",   vl_method_register_user_namespace,
                        "io.systemd.UserRegistry.AddMountToUserNamespace", vl_method_add_mount_to_user_namespace);
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
                                        return log_error_errno(r, "Failed to send SIGUSR2 signal to parent. %m");
                        }
                }

                (void) process_connection(server, TAKE_FD(fd));
                last_busy_usec = USEC_INFINITY;
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
