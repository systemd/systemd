/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/nsfs.h>
#include <linux/veth.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "sd-daemon.h"
#include "sd-netlink.h"

#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "group-record.h"
#include "io-util.h"
#include "lock-util.h"
#include "main-func.h"
#include "missing_magic.h"
#include "missing_mount.h"
#include "missing_syscall.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "netlink-util.h"
#include "process-util.h"
#include "random-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "strv.h"
#include "time-util.h"
#include "uid-alloc-range.h"
#include "uid-range.h"
#include "user-record.h"
#include "user-record-nss.h"
#include "user-util.h"
#include "userdb.h"
#include "userns-registry.h"
#include "userns-restrict.h"
#include "varlink-io.systemd.NamespaceResource.h"
#include "varlink-io.systemd.UserDatabase.h"
#include "varlink.h"

#define ITERATIONS_MAX 64U
#define RUNTIME_MAX_USEC (5 * USEC_PER_MINUTE)
#define PRESSURE_SLEEP_TIME_USEC (50 * USEC_PER_MSEC)
#define CONNECTION_IDLE_USEC (15 * USEC_PER_SEC)
#define LISTEN_IDLE_USEC (90 * USEC_PER_SEC)
#define USERNS_PER_UID 256

typedef struct LookupParameters {
        const char *user_name;
        const char *group_name;
        union {
                uid_t uid;
                gid_t gid;
        };
        const char *service;
} LookupParameters;

static int build_user_json(UserNamespaceInfo *userns_info, uid_t offset, JsonVariant **ret) {
        _cleanup_free_ char *name = NULL, *realname = NULL;
        UserDisposition disposition;
        int r;

        assert(userns_info);
        assert(offset < userns_info->size);

        if (asprintf(&name, "ns-%s-" UID_FMT, userns_info->name, offset) < 0)
                return -ENOMEM;

        if (userns_info->size > 1) {
                disposition = USER_CONTAINER;
                r = asprintf(&realname, "User " UID_FMT " of Allocated Namespace %s", offset, userns_info->name);
        } else {
                disposition = USER_DYNAMIC;
                r = asprintf(&realname, "Allocated Namespace %s", userns_info->name);
        }
        if (r < 0)
                return -ENOMEM;

        return json_build(ret, JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("userName", JSON_BUILD_STRING(name)),
                                          JSON_BUILD_PAIR("uid", JSON_BUILD_UNSIGNED(userns_info->start + offset)),
                                          JSON_BUILD_PAIR("gid", JSON_BUILD_UNSIGNED(GID_NOBODY)),
                                          JSON_BUILD_PAIR("realName", JSON_BUILD_STRING(realname)),
                                          JSON_BUILD_PAIR("homeDirectory", JSON_BUILD_CONST_STRING("/")),
                                          JSON_BUILD_PAIR("shell", JSON_BUILD_STRING(NOLOGIN)),
                                          JSON_BUILD_PAIR("locked", JSON_BUILD_BOOLEAN(true)),
                                          JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.NamespaceResource")),
                                          JSON_BUILD_PAIR("disposition", JSON_BUILD_STRING(user_disposition_to_string(disposition)))));
}

static int vl_method_get_user_record(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "uid",      JSON_VARIANT_UNSIGNED, json_dispatch_uid_gid,      offsetof(LookupParameters, uid),       0 },
                { "userName", JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(LookupParameters, user_name), 0 },
                { "service",  JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(LookupParameters, service),   0 },
                {}
        };

        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        LookupParameters p = {
                .uid = UID_INVALID,
        };
        uid_t offset;
        int r;

        assert(parameters);

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, "io.systemd.NamespaceResource"))
                return varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        if (p.user_name) {
                _cleanup_free_ char *n = NULL;
                const char *e, *f;

                e = startswith(p.user_name, "ns-");
                if (!e)
                        goto not_found;

                f = strrchr(e, '-');
                if (!f)
                        goto not_found;

                if (parse_uid(f+1, &offset) < 0)
                        goto not_found;

                n = strndup(e, f - e);
                if (!n)
                        return log_oom();

                r = userns_registry_load_by_name(
                                /* registry_fd= */ -EBADF,
                                n,
                                &userns_info);
                if (r == -ENOENT)
                        goto not_found;
                if (r < 0)
                        return r;

                if (offset >= userns_info->size) /* Outside of range? */
                        goto not_found;

                if (uid_is_valid(p.uid) && p.uid != userns_info->start + offset)
                        return varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        } else if (uid_is_valid(p.uid)) {
                uid_t start, uidmask;

                if (uid_is_container(p.uid))
                        uidmask = (uid_t) UINT32_C(0xFFFF0000);
                else if (uid_is_dynamic(p.uid))
                        uidmask = (uid_t) UINT32_C(0xFFFFFFFF);
                else
                        goto not_found;

                start = p.uid & uidmask;
                offset = p.uid - start;

                r = userns_registry_load_by_start_uid(
                                /* registry_fd= */ -EBADF,
                                start,
                                &userns_info);
                if (r == -ENOENT)
                        goto not_found;
                if (r < 0)
                        return r;

                if (offset >= userns_info->size) /* Outside of range? */
                        goto not_found;
        } else
                return varlink_error(link, "io.systemd.UserDatabase.EnumerationNotSupported", NULL);

        r = build_user_json(userns_info, offset, &v);
        if (r < 0)
                return r;

        return varlink_replyb(link, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("record", JSON_BUILD_VARIANT(v))));

not_found:
        return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
}

static int build_group_json(UserNamespaceInfo *userns_info, gid_t offset, JsonVariant **ret) {
        _cleanup_free_ char *name = NULL, *description = NULL;
        UserDisposition disposition;
        int r;

        assert(userns_info);
        assert(offset < userns_info->size);

        if (asprintf(&name, "ns-%s-" GID_FMT, userns_info->name, offset) < 0)
                return -ENOMEM;

        if (userns_info->size > 1) {
                disposition = USER_CONTAINER;
                r = asprintf(&description, "Group " GID_FMT " of Allocated Namespace %s", offset, userns_info->name);
        } else {
                disposition = USER_DYNAMIC;
                r = asprintf(&description, "Allocated Namespace %s", userns_info->name);
        }
        if (r < 0)
                return -ENOMEM;

        return json_build(ret, JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("groupName", JSON_BUILD_STRING(name)),
                                          JSON_BUILD_PAIR("gid", JSON_BUILD_UNSIGNED(userns_info->start + offset)),
                                          JSON_BUILD_PAIR("description", JSON_BUILD_STRING(description)),
                                          JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.NamespaceResource")),
                                          JSON_BUILD_PAIR("disposition", JSON_BUILD_STRING(user_disposition_to_string(disposition)))));
}

static int vl_method_get_group_record(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "gid",       JSON_VARIANT_UNSIGNED, json_dispatch_uid_gid,      offsetof(LookupParameters, gid),        0 },
                { "groupName", JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(LookupParameters, group_name), 0 },
                { "service",   JSON_VARIANT_STRING,   json_dispatch_const_string, offsetof(LookupParameters, service),    0 },
                {}
        };

        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        LookupParameters p = {
                .gid = GID_INVALID,
        };
        gid_t offset;
        int r;

        assert(parameters);

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, "io.systemd.NamespaceResource"))
                return varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        if (p.group_name) {
                _cleanup_free_ char *n = NULL;
                const char *e, *f;

                e = startswith(p.group_name, "ns-");
                if (!e)
                        goto not_found;

                f = strrchr(e, '-');
                if (!f)
                        goto not_found;

                if (parse_gid(f+1, &offset) < 0)
                        goto not_found;

                n = strndup(e, f - e);
                if (!n)
                        return log_oom();

                r = userns_registry_load_by_name(
                                /* registry_fd= */ -EBADF,
                                n,
                                &userns_info);
                if (r == -ENOENT)
                        goto not_found;
                if (r < 0)
                        return r;

                if (offset >= userns_info->size) /* Outside of range? */
                        goto not_found;

                if (gid_is_valid(p.gid) && p.uid != userns_info->start + offset)
                        return varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

        } else if (gid_is_valid(p.gid)) {
                gid_t start, gidmask;

                if (gid_is_container(p.gid))
                        gidmask = (gid_t) UINT32_C(0xFFFF0000);
                else if (gid_is_dynamic(p.gid))
                        gidmask = (gid_t) UINT32_C(0xFFFFFFFF);
                else
                        goto not_found;

                start = p.gid & gidmask;
                offset = p.gid - start;

                r = userns_registry_load_by_start_uid(
                                /* registry_fd= */ -EBADF,
                                (uid_t) start,
                                &userns_info);
                if (r == -ENOENT)
                        goto not_found;
                if (r < 0)
                        return r;

                if (offset >= userns_info->size) /* Outside of range? */
                        goto not_found;
        } else
                return varlink_error(link, "io.systemd.UserDatabase.EnumerationNotSupported", NULL);

        r = build_group_json(userns_info, offset, &v);
        if (r < 0)
                return r;

        return varlink_replyb(link, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("record", JSON_BUILD_VARIANT(v))));

not_found:
        return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
}

static int vl_method_get_memberships(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        static const JsonDispatch dispatch_table[] = {
                { "userName",  JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, user_name),  0 },
                { "groupName", JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, group_name), 0 },
                { "service",   JSON_VARIANT_STRING, json_dispatch_const_string, offsetof(LookupParameters, service),    0 },
                {}
        };

        LookupParameters p = {};
        int r;

        assert(parameters);

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, "io.systemd.NamespaceResource"))
                return varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        /* We don't support auxiliary groups for namespace allocations */
        return varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
}

static int uid_is_available(
                int registry_dir_fd,
                uid_t candidate) {

        int r;

        assert(registry_dir_fd >= 0);

        log_debug("Checking if UID " UID_FMT " is available.", candidate);

        r = userns_registry_uid_exists(registry_dir_fd, candidate);
        if (r < 0)
                return r;
        if (r > 0)
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

static int name_is_available(
                int registry_dir_fd,
                const char *name) {

        _cleanup_free_ char *user_name = NULL;
        int r;

        assert(registry_dir_fd >= 0);
        assert(name);

        r = userns_registry_name_exists(registry_dir_fd, name);
        if (r < 0)
                return r;
        if (r > 0)
                return false;

        user_name = strjoin("ns-", name, "-0");
        if (!user_name)
                return -ENOMEM;

        r = userdb_by_name(user_name, USERDB_AVOID_MULTIPLEXER, NULL);
        if (r >= 0)
                return false;
        if (r != -ESRCH)
                return r;

        r = groupdb_by_name(user_name, USERDB_AVOID_MULTIPLEXER, NULL);
        if (r >= 0)
                return false;
        if (r != -ESRCH)
                return r;

        log_debug("Namespace name '%s' is available.", name);

        return true;
}

static int allocate_now(
                int registry_dir_fd,
                UserNamespaceInfo *info,
                int *ret_lock_fd) {

        static const uint8_t hash_key[16] = {
                0xd4, 0xd7, 0x33, 0xa7, 0x4d, 0xd3, 0x42, 0xcd,
                0xaa, 0xe9, 0x45, 0xd0, 0xfb, 0xec, 0x79, 0xee,
        };

        _cleanup_(uid_range_freep) UidRange *valid_range = NULL;
        uid_t candidate, uidmin, uidmax, uidmask;
        unsigned n_tries = 100;
        int r;

        /* Returns the following error codes:
         *
         * EBUSY   → all UID candidates we checked are already taken
         * EEXIST  → the name for the userns already exists
         * EDEADLK → the userns is already registered in the registry
         */

        assert(registry_dir_fd >= 0);
        assert(info);

        switch (info->size) {

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

        _cleanup_close_ int lock_fd = -EBADF;
        lock_fd = userns_registry_lock(registry_dir_fd);
        if (lock_fd < 0)
                return log_debug_errno(lock_fd, "Failed to open nsresource registry lock file: %m");

        /* Enforce limit on user namespaces per UID */
        r = userns_registry_per_uid(registry_dir_fd, info->owner);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine number of currently registered user namespaces per UID " UID_FMT ": %m", info->owner);
        if (r >= USERNS_PER_UID)
                return log_debug_errno(SYNTHETIC_ERRNO(EUSERS), "User already registered %i user namespaces, refusing.", r);

        r = userns_registry_inode_exists(registry_dir_fd, info->userns_inode);
        if (r < 0)
                return r;
        if (r > 0)
                return -EDEADLK;

        r = name_is_available(registry_dir_fd, info->name);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        for (candidate = siphash24_string(info->name, hash_key) & UINT32_MAX;; /* Start from a hash of the input name */
             candidate = random_u32()) {                                 /* Use random values afterwards */

                if (--n_tries <= 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBUSY), "Try limit hit, no UIDs available.");

                candidate = (candidate % (uidmax - uidmin)) + uidmin;
                candidate &= uidmask;

                if (!uid_range_covers(valid_range, candidate, info->size))
                        continue;

                /* We only check the base UID for each range (!) */
                r = uid_is_available(registry_dir_fd, candidate);
                if (r < 0)
                        return log_debug_errno(r, "Can't determine if UID range " UID_FMT " is available: %m", candidate);
                if (r > 0) {
                        info->start = candidate;

                        log_debug("Allocating UID range " UID_FMT "…" UID_FMT, candidate, candidate + info->size - 1);

                        if (ret_lock_fd)
                                *ret_lock_fd = TAKE_FD(lock_fd);

                        return 0;
                }

                log_debug("UID range " UID_FMT " already taken.", candidate);
        }
}

static int write_userns(int usernsfd, const UserNamespaceInfo *userns_info) {
        _cleanup_(sigkill_waitp) pid_t pid = 0;
        _cleanup_close_ int efd = -EBADF;
        uint64_t u;
        int r;

        assert(usernsfd >= 0);
        assert(userns_info);
        assert(uid_is_valid(userns_info->target));
        assert(uid_is_valid(userns_info->start));
        assert(userns_info->size > 0);
        assert(userns_info->size <= UINT32_MAX - userns_info->start);

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

        r = write_string_filef(pmap, 0, UID_FMT " " UID_FMT " " UID_FMT "\n", userns_info->target, userns_info->start, userns_info->size);
        if (r < 0)
                return log_error_errno(r, "Failed to write 'uid_map' file of user namespace: %m");

        pmap = mfree(pmap);
        if (asprintf(&pmap, "/proc/" PID_FMT "/gid_map", pid) < 0)
                return log_oom();

        r = write_string_filef(pmap, 0, GID_FMT " " GID_FMT " " GID_FMT "\n", (gid_t) userns_info->target, (gid_t) userns_info->start, (gid_t) userns_info->size);
        if (r < 0)
                return log_error_errno(r, "Failed to write 'gid_map' file of user namespace: %m");

        /* We are done! */

        log_debug("Successfully configured user namespace.");
        return 0;
}

static int test_userns_api_support(Varlink *link) {
        int r;

        assert(link);

        r = getenv_bool("NSRESOURCE_API");
        if (r < 0)
                return log_error_errno(r, "Failed to parse $NSRESOURCE_API: %m");
        if (r == 0)
                return varlink_error(link, "io.systemd.NamespaceResource.UserNamespaceInterfaceNotSupported", NULL);

        return 0;
}

static int validate_userns(Varlink *link, int userns_fd) {
        int r;

        assert(link);
        assert(userns_fd >= 0);

        /* Validate this is actually a valid user namespace fd */
        r = fd_is_ns(userns_fd, CLONE_NEWUSER);
        if (r < 0)
                return r;
        if (r == 0)
                return varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        /* And refuse the thing if it is our own */
        r = is_our_namespace(userns_fd, NAMESPACE_USER);
        if (r < 0)
                return r;
        if (r > 0)
                return varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        uid_t peer_uid;
        r = varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;

        if (peer_uid != 0) {
                /* Refuse if the userns is not actually owned by our client. */
                uid_t owner_uid;
                if (ioctl(userns_fd, NS_GET_OWNER_UID, &owner_uid) < 0)
                        return -errno;

                if (owner_uid != peer_uid)
                        return varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");
        }

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
        _cleanup_close_ int userns_fd = -EBADF, registry_dir_fd = -EBADF, lock_fd = -EBADF;
        uid_t peer_uid;
        struct stat userns_st;
        AllocateParameters p = {
                .size = UINT_MAX,
                .userns_fd_idx = UINT_MAX,
        };
        int r;

        assert(link);
        assert(parameters);

        r = test_userns_api_support(link);
        if (r < 0)
                return r;

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r < 0)
                return r;

        if (!valid_user_group_name(p.name, 0))
                return varlink_error_invalid_parameter_name(link, "name");

        if (!IN_SET(p.size, 1U, 0x10000))
                return varlink_error_invalid_parameter_name(link, "size");

        if (!uid_is_valid(p.target) || p.target > UINT32_MAX - p.size)
                return varlink_error_invalid_parameter_name(link, "target");

        userns_fd = varlink_take_fd(link, p.userns_fd_idx);
        if (userns_fd < 0)
                return userns_fd;

        r = validate_userns(link, userns_fd);
        if (r < 0)
                return r;

        if (fstat(userns_fd, &userns_st) < 0)
                return log_debug_errno(errno, "Failed to fstat() user namespace fd: %m");

        r = varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;

        r = userns_restrict_install(/* pin= */ true, &bpf);
        if (r < 0)
                return r;

        registry_dir_fd = userns_registry_open_fd();
        if (registry_dir_fd < 0)
                return registry_dir_fd;

        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = userns_info_new();
        if (!userns_info)
                return -ENOMEM;

        userns_info->name = strdup(p.name);
        if (!userns_info->name)
                return -ENOMEM;

        userns_info->owner = peer_uid;
        userns_info->userns_inode = userns_st.st_ino;
        userns_info->size = p.size;
        userns_info->target = p.target;

        r = allocate_now(registry_dir_fd, userns_info, &lock_fd);
        if (r == -EHOSTDOWN) /* The needed UID range is not delegated to us */
                return varlink_error(link, "io.systemd.NamespaceResource.DynamicRangeUnavailable", NULL);
        if (r == -EBUSY)     /* All used up */
                return varlink_error(link, "io.systemd.NamespaceResource.NoDynamicRange", NULL);
        if (r == -EDEADLK)
                return varlink_error(link, "io.systemd.NamespaceResource.UserNamespaceExists", NULL);
        if (r == -EEXIST)
                return varlink_error(link, "io.systemd.NamespaceResource.NameExists", NULL);
        if (r < 0)
                return r;

        r = userns_registry_store(registry_dir_fd, userns_info);
        if (r < 0)
                return r;

        /* Register the userns in the BPF map with an empty allowlist */
        r = userns_restrict_put_by_fd(
                        bpf,
                        userns_fd,
                        /* replace= */ true,
                        /* mount_fds= */ NULL,
                        /* n_mount_fds= */ 0);
        if (r < 0)
                goto fail;

        r = write_userns(userns_fd, userns_info);
        if (r < 0)
                goto fail;

        lock_fd = safe_close(lock_fd);

        /* Send user namespace and process fd to our manager process, which will watch the process and user namespace */
        r = sd_pid_notifyf_with_fds(
                        /* pid= */ 0,
                        /* unset_environment= */ false,
                        &userns_fd, 1,
                        "FDSTORE=1\n"
                        "FDNAME=userns-" INO_FMT "\n", userns_info->userns_inode);
        if (r < 0)
                goto fail;

        /* Note, we'll not return UID values from the host, since the child might not run in the same
         * user namespace as us. If they want to know the ranges they should read them off the userns fd, so
         * that they are translated into their PoV */
        return varlink_replyb(link, JSON_BUILD_EMPTY_OBJECT);

fail:
        /* Note: we don't have to clean-up the BPF maps in the error path: the bpf map type used will
         * automatically do that once the userns inode goes away */
        userns_registry_remove(registry_dir_fd, userns_info);
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
        _cleanup_close_ int userns_fd = -EBADF, registry_dir_fd = -EBADF;
        uid_t peer_uid;
        struct stat userns_st;
        RegisterParameters p = {
                .userns_fd_idx = UINT_MAX,
        };
        int r;

        assert(link);
        assert(parameters);

        r = test_userns_api_support(link);
        if (r < 0)
                return r;

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r < 0)
                return r;

        if (!valid_user_group_name(p.name, 0))
                return varlink_error_invalid_parameter_name(link, "name");

        userns_fd = varlink_take_fd(link, p.userns_fd_idx);
        if (userns_fd < 0)
                return userns_fd;

        r = validate_userns(link, userns_fd);
        if (r < 0)
                return r;

        if (fstat(userns_fd, &userns_st) < 0)
                return log_debug_errno(errno, "Failed to fstat() user namespace fd: %m");

        r = varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;

        r = userns_restrict_install(/* pin= */ true, &bpf);
        if (r < 0)
                return r;

        registry_dir_fd = userns_registry_open_fd();
        if (registry_dir_fd < 0)
                return registry_dir_fd;

        _cleanup_close_ int lock_fd = -EBADF;
        lock_fd = userns_registry_lock(registry_dir_fd);
        if (lock_fd < 0)
                return log_debug_errno(lock_fd, "Failed to open nsresource registry lock file: %m");

        r = userns_registry_inode_exists(registry_dir_fd, userns_st.st_ino);
        if (r < 0)
                return r;
        if (r > 0)
                return varlink_error(link, "io.systemd.NamespaceResource.UserNamespaceExists", NULL);

        r = name_is_available(registry_dir_fd, p.name);
        if (r < 0)
                return r;
        if (r == 0)
                return varlink_error(link, "io.systemd.NamespaceResource.NameExists", NULL);

        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = userns_info_new();
        if (!userns_info)
                return -ENOMEM;

        userns_info->name = strdup(p.name);
        if (!userns_info->name)
                return -ENOMEM;

        userns_info->owner = peer_uid;
        userns_info->userns_inode = userns_st.st_ino;

        r = userns_registry_store(registry_dir_fd, userns_info);
        if (r < 0)
                return log_debug_errno(r, "Failed to update userns registry: %m");

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
                        "FDNAME=userns-" INO_FMT "\n", userns_info->userns_inode);
        if (r < 0)
                goto fail;

        return varlink_replyb(link, JSON_BUILD_EMPTY_OBJECT);

fail:
        userns_registry_remove(registry_dir_fd, userns_info);
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

        _cleanup_close_ int userns_fd = -EBADF, mount_fd = -EBADF, registry_dir_fd = -EBADF;
        _cleanup_(userns_restrict_bpf_freep) struct userns_restrict_bpf *bpf = NULL;
        AddMountParameters p = {
                .userns_fd_idx = UINT_MAX,
                .mount_fd_idx = UINT_MAX,
        };
        int r, mnt_id = 0;
        struct stat userns_st;
        uid_t peer_uid;

        assert(link);
        assert(parameters);

        r = test_userns_api_support(link);
        if (r < 0)
                return r;

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

        r = validate_userns(link, userns_fd);
        if (r < 0)
                return r;

        if (fstat(userns_fd, &userns_st) < 0)
                return -errno;

        mount_fd = varlink_take_fd(link, p.mount_fd_idx);
        if (mount_fd < 0)
                return mount_fd;

        r = fd_verify_directory(mount_fd);
        if (r < 0)
                return r;

        r = path_get_mnt_id_at(mount_fd, NULL, &mnt_id);
        if (r < 0)
                return r;

        registry_dir_fd = userns_registry_open_fd();
        if (registry_dir_fd < 0)
                return registry_dir_fd;

        _cleanup_close_ int lock_fd = -EBADF;
        lock_fd = userns_registry_lock(registry_dir_fd);
        if (lock_fd < 0)
                return log_debug_errno(lock_fd, "Failed to open nsresource registry lock file: %m");

        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        r = userns_registry_load_by_userns_inode(
                        registry_dir_fd,
                        userns_st.st_ino,
                        &userns_info);
        if (r == -ENOENT)
                return varlink_error(link, "io.systemd.NamespaceResource.UserNamespaceNotRegistered", NULL);
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
                        "FDNAME=userns-" INO_FMT "\n", userns_st.st_ino);
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

        if (userns_info->size > 0)
                log_debug("Granting access to mount %i to user namespace " INO_FMT " ('%s' @ UID " UID_FMT ")",
                          mnt_id, userns_st.st_ino, userns_info->name, userns_info->start);
        else
                log_debug("Granting access to mount %i to user namespace " INO_FMT " ('%s')",
                          mnt_id, userns_st.st_ino, userns_info->name);

        return varlink_replyb(link, JSON_BUILD_EMPTY_OBJECT);
}

static int validate_cgroup(Varlink *link, int fd, uint64_t *ret_cgroup_id) {
        int r;

        assert(link);
        assert(fd >= 0);
        assert(ret_cgroup_id);

        r = fd_verify_directory(fd);
        if (r < 0)
                return r;

        r = fd_is_fs_type(fd, CGROUP2_SUPER_MAGIC);
        if (r < 0)
                return r;
        if (r == 0)
                return varlink_error_invalid_parameter_name(link, "controlGroupFileDescriptor");

        return cg_fd_get_cgroupid(fd, ret_cgroup_id);
}

typedef struct AddCGroupParameters {
        unsigned userns_fd_idx;
        unsigned cgroup_fd_idx;
} AddCGroupParameters;

static int vl_method_add_cgroup_to_user_namespace(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        static const JsonDispatch parameter_dispatch_table[] = {
                { "userNamespaceFileDescriptor", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint, offsetof(AddCGroupParameters, userns_fd_idx), JSON_MANDATORY },
                { "controlGroupFileDescriptor",  _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint, offsetof(AddCGroupParameters, cgroup_fd_idx), JSON_MANDATORY },
                {}
        };

        _cleanup_close_ int userns_fd = -EBADF, cgroup_fd = -EBADF, registry_dir_fd = -EBADF;
        AddCGroupParameters p = {
                .userns_fd_idx = UINT_MAX,
                .cgroup_fd_idx = UINT_MAX,
        };
        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        struct stat userns_st, cgroup_st;
        uid_t peer_uid;
        int r;

        assert(link);
        assert(parameters);

        r = test_userns_api_support(link);
        if (r < 0)
                return r;

        r = varlink_dispatch(link, parameters, parameter_dispatch_table, &p);
        if (r < 0)
                return r;

        userns_fd = varlink_take_fd(link, p.userns_fd_idx);
        if (userns_fd < 0)
                return userns_fd;

        r = validate_userns(link, userns_fd);
        if (r < 0)
                return r;

        if (fstat(userns_fd, &userns_st) < 0)
                return -errno;

        cgroup_fd = varlink_take_fd(link, p.cgroup_fd_idx);
        if (cgroup_fd < 0)
                return cgroup_fd;

        uint64_t cgroup_id;
        r = validate_cgroup(link, cgroup_fd, &cgroup_id);
        if (r < 0)
                return r;

        if (fstat(cgroup_fd, &cgroup_st) < 0)
                return -errno;

        registry_dir_fd = userns_registry_open_fd();
        if (registry_dir_fd < 0)
                return registry_dir_fd;

        _cleanup_close_ int lock_fd = -EBADF;
        lock_fd = userns_registry_lock(registry_dir_fd);
        if (lock_fd < 0)
                return log_debug_errno(lock_fd, "Failed to open nsresource registry lock file: %m");

        r = userns_registry_load_by_userns_inode(
                        registry_dir_fd,
                        userns_st.st_ino,
                        &userns_info);
        if (r == -ENOENT)
                return varlink_error(link, "io.systemd.NamespaceResource.UserNamespaceNotRegistered", NULL);
        if (r < 0)
                return r;

        /* The user namespace must have a user assigned */
        if (userns_info->size == 0)
                return varlink_error(link, "io.systemd.NamespaceResource.UserNamespaceWithoutUserRange", NULL);
        if (userns_info_has_cgroup(userns_info, cgroup_id))
                return varlink_error(link, "io.systemd.NamespaceResource.ControlGroupAlreadyAdded", NULL);
        if (userns_info->n_cgroups > USER_NAMESPACE_CGROUPS_DELEGATE_MAX)
                return varlink_error(link, "io.systemd.NamespaceResource.TooManyControlGroups", NULL);

        /* Registering a cgroup for this client is only allowed for the root or the owner of a userns */
        r = varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;
        if (peer_uid != 0) {
                if (peer_uid != userns_info->owner)
                        return varlink_error(link, VARLINK_ERROR_PERMISSION_DENIED, NULL);

                /* The cgroup must be owned by the owner of the userns */
                if (cgroup_st.st_uid != userns_info->owner)
                        return varlink_error(link, VARLINK_ERROR_PERMISSION_DENIED, NULL);
        }

        r = userns_info_add_cgroup(userns_info, cgroup_id);
        if (r < 0)
                return r;

        r = userns_registry_store(registry_dir_fd, userns_info);
        if (r < 0)
                return r;

        if (fchown(cgroup_fd, userns_info->start, userns_info->start) < 0)
                return -errno;

        if (fchmod(cgroup_fd, 0755) < 0)
                return -errno;

        FOREACH_STRING(attr, "cgroup.procs", "cgroup.subtree_control", "cgroup.threads") {
                (void) fchmodat(cgroup_fd, attr, 0644, AT_SYMLINK_NOFOLLOW);
                (void) fchownat(cgroup_fd, attr, userns_info->start, userns_info->start, AT_SYMLINK_NOFOLLOW);
        }

        log_debug("Granting ownership to cgroup %" PRIu64 " to userns " INO_FMT " ('%s' @ UID " UID_FMT ")",
                  cgroup_id, userns_st.st_ino, userns_info->name, userns_info->start);

        return varlink_replyb(link, JSON_BUILD_EMPTY_OBJECT);
}

static uint64_t hash_ifname_id(UserNamespaceInfo *userns_info, const char *ifname) {
        struct siphash state;

        assert(userns_info);

        siphash24_init(&state, (const uint8_t[]) { 0xc4, 0x6c, 0x96, 0xe8, 0xad, 0x37, 0x4d, 0x5f, 0xa1, 0xae, 0xfe, 0x70, 0x40, 0xed, 0x41, 0x5f });
        siphash24_compress_string(userns_info->name, &state);
        siphash24_compress_byte(0, &state); /* separator */
        siphash24_compress_string(strempty(ifname), &state);

        return siphash24_finalize(&state);
}

static void hash_ether_addr(UserNamespaceInfo *userns_info, const char *ifname, uint64_t n, struct ether_addr *ret) {
        struct siphash state;
        uint64_t h;

        assert(userns_info);
        assert(ret);

        siphash24_init(&state, (const uint8_t[]) { 0x36, 0xaa, 0xd1, 0x69, 0xc7, 0xe5, 0x4c, 0xaa, 0x1e, 0xb2, 0x9e, 0xb3, 0x3a, 0x6b, 0xd4, 0x71 });
        siphash24_compress_string(userns_info->name, &state);
        siphash24_compress_byte(0, &state); /* separator */
        siphash24_compress_string(strempty(ifname), &state);
        siphash24_compress_byte(0, &state); /* separator */
        n = htole64(n); /* add the 'index' to the mix in an endianess-independent fashion */
        siphash24_compress(&n, sizeof(n), &state);

        h = htole64(siphash24_finalize(&state));

        assert(sizeof(h) >= sizeof_field(struct ether_addr, ether_addr_octet));

        memcpy(ret->ether_addr_octet, &h, sizeof_field(struct ether_addr, ether_addr_octet));
        ether_addr_mark_random(ret);
}

static int create_veth(
                int netns_fd,
                const char *ifname_host,
                const char *altifname_host,
                struct ether_addr *mac_host,
                const char *ifname_namespace,
                struct ether_addr *mac_namespace) {

        int r;

        assert(netns_fd >= 0);
        assert(ifname_host);
        assert(mac_host);
        assert(ifname_namespace);
        assert(mac_namespace);

        log_debug("Creating veth link on host %s (%s) with address %s to container as %s with address %s",
                  ifname_host, strna(altifname_host), ETHER_ADDR_TO_STR(mac_host),
                  ifname_namespace, ETHER_ADDR_TO_STR(mac_namespace));

        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return r;

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        r = sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate netlink message: %m");

        r = sd_netlink_message_append_string(m, IFLA_IFNAME, ifname_host);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink interface name: %m");

        r = sd_netlink_message_append_ether_addr(m, IFLA_ADDRESS, mac_host);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink MAC address: %m");

        r = sd_netlink_message_open_container(m, IFLA_LINKINFO);
        if (r < 0)
                return log_error_errno(r, "Failed to open netlink container: %m");

        r = sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, "veth");
        if (r < 0)
                return log_error_errno(r, "Failed to open netlink container: %m");

        r = sd_netlink_message_open_container(m, VETH_INFO_PEER);
        if (r < 0)
                return log_error_errno(r, "Failed to open netlink container: %m");

        r = sd_netlink_message_append_string(m, IFLA_IFNAME, ifname_namespace);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink interface name: %m");

        r = sd_netlink_message_append_ether_addr(m, IFLA_ADDRESS, mac_namespace);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink MAC address: %m");

        r = sd_netlink_message_append_u32(m, IFLA_NET_NS_FD, netns_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink namespace field: %m");

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_error_errno(r, "Failed to close netlink container: %m");

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_error_errno(r, "Failed to close netlink container: %m");

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_error_errno(r, "Failed to close netlink container: %m");

        r = sd_netlink_call(rtnl, m, 0, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add new veth interfaces (%s:%s): %m", ifname_host, ifname_namespace);

        r = rtnl_set_link_alternative_names_by_ifname(&rtnl, ifname_host, STRV_MAKE(altifname_host));
        if (r < 0)
                log_warning_errno(r, "Failed to set alternative interface name to '%s', ignoring: %m", altifname_host);

        return 0;
}

static int validate_netns(Varlink *link, int userns_fd, int netns_fd) {
        int r;

        assert(link);
        assert(userns_fd >= 0);
        assert(netns_fd >= 0);

        /* Validate this is actually a valid network namespace fd */
        r = fd_is_ns(netns_fd, CLONE_NEWNET);
        if (r < 0)
                return r;
        if (r == 0)
                return varlink_error_invalid_parameter_name(link, "networkNamespaceFileDescriptor");

        /* And refuse the thing if it is our own */
        r = is_our_namespace(netns_fd, NAMESPACE_NET);
        if (r < 0)
                return r;
        if (r > 0)
                return varlink_error_invalid_parameter_name(link, "networkNamespaceFileDescriptor");

        /* Check if the netns actually belongs to the userns */
        _cleanup_close_ int owner_userns_fd = -EBADF;
        owner_userns_fd = ioctl(netns_fd, NS_GET_USERNS);
        if (owner_userns_fd < 0)
                return -errno;

        r = inode_same_at(owner_userns_fd, /* path_a= */ NULL, userns_fd, /* path_b= */ NULL, AT_EMPTY_PATH);
        if (r < 0)
                return r;
        if (r == 0)
                return varlink_error_invalid_parameter_name(link, "networkNamespaceFileDescriptor");

        uid_t peer_uid;
        r = varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;

        if (peer_uid != 0) {
                /* Refuse if the netns is not actually owned by our client. */

                uid_t owner_uid;
                if (ioctl(owner_userns_fd, NS_GET_OWNER_UID, &owner_uid) < 0)
                        return -errno;

                if (owner_uid != peer_uid)
                        return varlink_error_invalid_parameter_name(link, "networkNamespaceFileDescriptor");
        }

        return 0;
}

typedef struct AddNetworkParameters {
        unsigned userns_fd_idx;
        unsigned netns_fd_idx;
        const char *ifname;
        const char *mode;
} AddNetworkParameters;

static int vl_method_add_netif_to_user_namespace(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        static const JsonDispatch parameter_dispatch_table[] = {
                { "userNamespaceFileDescriptor",    _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint,         offsetof(AddNetworkParameters, userns_fd_idx), JSON_MANDATORY },
                { "networkNamespaceFileDescriptor", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint,         offsetof(AddNetworkParameters, netns_fd_idx),  JSON_MANDATORY },
                { "namespaceInterfaceName",         JSON_VARIANT_STRING,        json_dispatch_const_string, offsetof(AddNetworkParameters, ifname),        0              },
                { "mode",                           JSON_VARIANT_STRING,        json_dispatch_const_string, offsetof(AddNetworkParameters, mode),          JSON_MANDATORY },
                {}
        };

        _cleanup_close_ int userns_fd = -EBADF, netns_fd = -EBADF, registry_dir_fd = -EBADF;
        AddNetworkParameters p = {
                .userns_fd_idx = UINT_MAX,
        };
        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        struct stat userns_st;
        uid_t peer_uid;
        int r;

        assert(link);
        assert(parameters);

        r = test_userns_api_support(link);
        if (r < 0)
                return r;

        r = varlink_dispatch(link, parameters, parameter_dispatch_table, &p);
        if (r < 0)
                return r;

        userns_fd = varlink_take_fd(link, p.userns_fd_idx);
        if (userns_fd < 0)
                return userns_fd;

        r = validate_userns(link, userns_fd);
        if (r < 0)
                return r;

        if (fstat(userns_fd, &userns_st) < 0)
                return -errno;

        netns_fd = varlink_take_fd(link, p.netns_fd_idx);
        if (netns_fd < 0)
                return netns_fd;

        r = validate_netns(link, userns_fd, netns_fd);
        if (r < 0)
                return r;

        if (!streq_ptr(p.mode, "veth"))
                return varlink_error_invalid_parameter_name(link, "mode");

        if (p.ifname && !ifname_valid(p.ifname))
                return varlink_error_invalid_parameter_name(link, "interfaceName");

        registry_dir_fd = userns_registry_open_fd();
        if (registry_dir_fd < 0)
                return registry_dir_fd;

        _cleanup_close_ int lock_fd = -EBADF;
        lock_fd = userns_registry_lock(registry_dir_fd);
        if (lock_fd < 0)
                return log_debug_errno(lock_fd, "Failed to open nsresource registry lock file: %m");

        r = userns_registry_load_by_userns_inode(
                        registry_dir_fd,
                        userns_st.st_ino,
                        &userns_info);
        if (r == -ENOENT)
                return varlink_error(link, "io.systemd.NamespaceResource.UserNamespaceNotRegistered", NULL);
        if (r < 0)
                return r;

        /* Registering a network interface for this client is only allowed for the root or the owner of a userns */
        r = varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;
        if (peer_uid != 0 && peer_uid != userns_info->owner)
                return varlink_error(link, VARLINK_ERROR_PERMISSION_DENIED, NULL);

        _cleanup_free_ char *ifname_host = NULL, *altifname_host = NULL;
        const char *ifname_namespace = p.ifname ?: "host0";

        /* The short ifname is just too short to generate readable and unique names where unprivileged users
         * can't take each others names. Hence just hash it. The alternative name however contains more useful
         * information. */
        if (asprintf(&ifname_host, "ns-%08" PRIx64, hash_ifname_id(userns_info, p.ifname)) < 0)
                return -ENOMEM;
        strshorten(ifname_host, IFNAMSIZ-1);

        if (p.ifname)
                r = asprintf(&altifname_host, "ns-" UID_FMT "-%s-%s", userns_info->owner, userns_info->name, p.ifname);
        else
                r = asprintf(&altifname_host, "ns-" UID_FMT "-%s", userns_info->owner, userns_info->name);
        if (r < 0)
                return -ENOMEM;

        struct ether_addr ether_addr_host, ether_addr_namespace;

        hash_ether_addr(userns_info, p.ifname, 0, &ether_addr_host);
        hash_ether_addr(userns_info, p.ifname, 1, &ether_addr_namespace);

        r = create_veth(netns_fd,
                        ifname_host, altifname_host, &ether_addr_host,
                        ifname_namespace, &ether_addr_namespace);
        if (r < 0)
                return r;

        log_debug("Adding veth tunnel %s from host to userns " INO_FMT " ('%s' @ UID " UID_FMT ", interface %s).",
                  ifname_host, userns_st.st_ino, userns_info->name, userns_info->start, ifname_namespace);

        return varlink_replyb(link, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("hostInterfaceName", JSON_BUILD_STRING(ifname_host)),
                                                      JSON_BUILD_PAIR("namespaceInterfaceName", JSON_BUILD_STRING(ifname_namespace))));
}

static int process_connection(VarlinkServer *server, int _fd) {
        _cleanup_close_ int fd = TAKE_FD(_fd); /* always take possession */
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
                        &vl_interface_io_systemd_NamespaceResource,
                        &vl_interface_io_systemd_UserDatabase);
        if (r < 0)
                return log_error_errno(r, "Failed to add UserDatabase and NamespaceResource interface to varlink server: %m");

        r = varlink_server_bind_method_many(
                        server,
                        "io.systemd.NamespaceResource.AllocateUserRange",              vl_method_allocate_user_range,
                        "io.systemd.NamespaceResource.RegisterUserNamespace",          vl_method_register_user_namespace,
                        "io.systemd.NamespaceResource.AddMountToUserNamespace",        vl_method_add_mount_to_user_namespace,
                        "io.systemd.NamespaceResource.AddControlGroupToUserNamespace", vl_method_add_cgroup_to_user_namespace,
                        "io.systemd.NamespaceResource.AddNetworkToUserNamespace",      vl_method_add_netif_to_user_namespace,
                        "io.systemd.UserDatabase.GetUserRecord",                       vl_method_get_user_record,
                        "io.systemd.UserDatabase.GetGroupRecord",                      vl_method_get_group_record,
                        "io.systemd.UserDatabase.GetMemberships",                      vl_method_get_memberships);
        if (r < 0)
                return log_error_errno(r, "Failed to bind methods: %m");

        r = getenv_bool("NSRESOURCE_FIXED_WORKER");
        if (r < 0)
                return log_error_errno(r, "Failed to parse NSRESOURCE_FIXED_WORKER: %m");
        listen_idle_usec = r ? USEC_INFINITY : LISTEN_IDLE_USEC;

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

                (void) rename_process("systemd-nsresourcework: waiting...");
                fd = RET_NERRNO(accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC));
                (void) rename_process("systemd-nsresourcework: processing...");

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
