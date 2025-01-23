/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/nsfs.h>
#include <linux/veth.h>
#include <net/if.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <utmpx.h>

#include "sd-daemon.h"
#include "sd-netlink.h"
#include "sd-varlink.h"

#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "group-record.h"
#include "io-util.h"
#include "json-util.h"
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
#include "uid-classification.h"
#include "uid-range.h"
#include "user-record-nss.h"
#include "user-record.h"
#include "user-util.h"
#include "userdb.h"
#include "userns-registry.h"
#include "userns-restrict.h"
#include "varlink-io.systemd.NamespaceResource.h"
#include "varlink-io.systemd.UserDatabase.h"
#include "varlink-util.h"

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

static int build_user_json(UserNamespaceInfo *userns_info, uid_t offset, sd_json_variant **ret) {
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

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR("userName", SD_JSON_BUILD_STRING(name)),
                        SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(userns_info->start + offset)),
                        SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(GID_NOBODY)),
                        SD_JSON_BUILD_PAIR("realName", SD_JSON_BUILD_STRING(realname)),
                        SD_JSON_BUILD_PAIR("homeDirectory", JSON_BUILD_CONST_STRING("/")),
                        SD_JSON_BUILD_PAIR("shell", SD_JSON_BUILD_STRING(NOLOGIN)),
                        SD_JSON_BUILD_PAIR("locked", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.NamespaceResource")),
                        SD_JSON_BUILD_PAIR("disposition", SD_JSON_BUILD_STRING(user_disposition_to_string(disposition))));
}

static int vl_method_get_user_record(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "uid",      SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uid_gid,            offsetof(LookupParameters, uid),       0             },
                { "userName", SD_JSON_VARIANT_STRING,   json_dispatch_const_user_group_name, offsetof(LookupParameters, user_name), SD_JSON_RELAX },
                { "service",  SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string,       offsetof(LookupParameters, service),   0             },
                {}
        };

        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        LookupParameters p = {
                .uid = UID_INVALID,
        };
        uid_t offset;
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, "io.systemd.NamespaceResource"))
                return sd_varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

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
                        return sd_varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

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
                return sd_varlink_error(link, "io.systemd.UserDatabase.EnumerationNotSupported", NULL);

        r = build_user_json(userns_info, offset, &v);
        if (r < 0)
                return r;

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR("record", SD_JSON_BUILD_VARIANT(v)));

not_found:
        return sd_varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
}

static int build_group_json(UserNamespaceInfo *userns_info, gid_t offset, sd_json_variant **ret) {
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

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR("groupName", SD_JSON_BUILD_STRING(name)),
                        SD_JSON_BUILD_PAIR("gid", SD_JSON_BUILD_UNSIGNED(userns_info->start + offset)),
                        SD_JSON_BUILD_PAIR("description", SD_JSON_BUILD_STRING(description)),
                        SD_JSON_BUILD_PAIR("service", JSON_BUILD_CONST_STRING("io.systemd.NamespaceResource")),
                        SD_JSON_BUILD_PAIR("disposition", SD_JSON_BUILD_STRING(user_disposition_to_string(disposition))));
}

static int vl_method_get_group_record(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "gid",       SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uid_gid,            offsetof(LookupParameters, gid),        0             },
                { "groupName", SD_JSON_VARIANT_STRING,   json_dispatch_const_user_group_name, offsetof(LookupParameters, group_name), SD_JSON_RELAX },
                { "service",   SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string,       offsetof(LookupParameters, service),    0             },
                {}
        };

        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        LookupParameters p = {
                .gid = GID_INVALID,
        };
        gid_t offset;
        int r;

        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!streq_ptr(p.service, "io.systemd.NamespaceResource"))
                return sd_varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

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
                        return sd_varlink_error(link, "io.systemd.UserDatabase.ConflictingRecordFound", NULL);

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
                return sd_varlink_error(link, "io.systemd.UserDatabase.EnumerationNotSupported", NULL);

        r = build_group_json(userns_info, offset, &v);
        if (r < 0)
                return r;

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR("record", SD_JSON_BUILD_VARIANT(v)));

not_found:
        return sd_varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
}

static int vl_method_get_memberships(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
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

        if (!streq_ptr(p.service, "io.systemd.NamespaceResource"))
                return sd_varlink_error(link, "io.systemd.UserDatabase.BadService", NULL);

        /* We don't support auxiliary groups for namespace allocations */
        return sd_varlink_error(link, "io.systemd.UserDatabase.NoRecordFound", NULL);
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

        r = userdb_by_uid(candidate, /* match= */ NULL, USERDB_AVOID_MULTIPLEXER, /* ret_record= */ NULL);
        if (r >= 0)
                return false;
        if (r != -ESRCH)
                return r;

        r = groupdb_by_gid(candidate, /* match= */ NULL, USERDB_AVOID_MULTIPLEXER, /* ret_record= */ NULL);
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

        r = userdb_by_name(user_name, /* match= */ NULL, USERDB_AVOID_MULTIPLEXER, /* ret_record= */ NULL);
        if (r >= 0)
                return false;
        if (r != -ESRCH)
                return r;

        r = groupdb_by_name(user_name, /* match= */ NULL, USERDB_AVOID_MULTIPLEXER, /* ret_record= */ NULL);
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

        _cleanup_(uid_range_freep) UIDRange *valid_range = NULL;
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

        r = uid_range_load_userns(/* path= */ NULL, UID_RANGE_USERNS_INSIDE, &valid_range);
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

static int test_userns_api_support(sd_varlink *link) {
        int r;

        assert(link);

        /* We only expose the userns API if our manager daemon told us this OK to do. It will set this
         * boolean only if it managed to set up BPF correctly for itself (i.e. watches for userns going away
         * via BPF APIs). This should make very sure we don't accidentally allow any of the userns stuff to
         * go through without the BPF LSM in effect. */

        r = getenv_bool("NSRESOURCE_API");
        if (r < 0)
                return log_error_errno(r, "Failed to parse $NSRESOURCE_API: %m");
        if (r == 0)
                return sd_varlink_error(link, "io.systemd.NamespaceResource.UserNamespaceInterfaceNotSupported", NULL);

        return 0;
}

static char* random_name(void) {
        char *s = NULL;

        /* Make up a random name for this userns. Make sure the random name fits into utmpx even if prefixed
         * with "ns-", the peer's UID, "-", and suffixed by "-65535". */
        assert_cc(STRLEN("ns-65535-") + 16 + STRLEN("-65535") < sizeof_field(struct utmpx, ut_user));

        if (asprintf(&s, "%016" PRIx64, random_u64()) < 0)
                return NULL;

        return s;
}

static char *shorten_name(const char *name) {

        /* Shorten the specified name, so that it works as a userns name */

        char *n = strdup(name);
        if (!n)
                return NULL;

        /* make sure the truncated name fits into utmpx even if prefixed with "ns-" and suffixed by "-65535" */
        strshorten(n, sizeof_field(struct utmpx, ut_user) - STRLEN("ns-") - STRLEN("-65536") - 1);

        return n;
}

static int validate_name(sd_varlink *link, const char *name, bool mangle, char **ret) {
        int r;

        assert(link);
        assert(name);
        assert(ret);

        uid_t peer_uid;
        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;

        _cleanup_free_ char *un = NULL;
        if (peer_uid == 0) {
                /* If the client is root, we'll not prefix it, but we will make sure it's suitable for
                 * inclusion in a user name */
                if (userns_name_is_valid(name)) {
                        un = strdup(name);
                        if (!un)
                                return -ENOMEM;
                } else {
                        if (!mangle)
                                return sd_varlink_error_invalid_parameter_name(link, "name");

                        un = shorten_name(name);
                        if (!un)
                                return -ENOMEM;

                        /* Let's see if shortening was enough? (It might not be, for example because an empty
                         * string was provided – which no truncation would make valid.) */
                        if (!userns_name_is_valid(un)) {
                                free(un);

                                /* if not, make up a random name */
                                un = random_name();
                                if (!un)
                                        return -ENOMEM;
                        }
                }
        } else {
                /* If the client is not root then prefix the name with the UID of the peer, so that they live
                 * in separate namespaces and cannot interfere with each other's names. */

                if (asprintf(&un, UID_FMT "-%s", peer_uid, name) < 0)
                        return -ENOMEM;

                if (!userns_name_is_valid(un)) {
                        if (!mangle)
                                return sd_varlink_error_invalid_parameter_name(link, "name");

                        _cleanup_free_ char *c = shorten_name(un);
                        if (!c)
                                return -ENOMEM;

                        /* Let's see if shortening was enough? */
                        if (userns_name_is_valid(c))
                                free_and_replace(un, c);
                        else  {
                                free(c);
                                c = random_name();
                                if (!c)
                                        return -ENOMEM;

                                un = mfree(un);
                                if (asprintf(&un, UID_FMT "-%s", peer_uid, c) < 0)
                                        return -ENOMEM;

                                if (!userns_name_is_valid(un))
                                        return sd_varlink_error_invalid_parameter_name(link, "name");
                        }
                }
        }

        *ret = TAKE_PTR(un);
        return 0;
}

static int validate_target_and_size(sd_varlink *link, unsigned target, unsigned size) {
        assert(link);

        if (!IN_SET(size, 1U, 0x10000))
                return sd_varlink_error_invalid_parameter_name(link, "size");

        if (!uid_is_valid(target) || target > UINT32_MAX - size)
                return sd_varlink_error_invalid_parameter_name(link, "target");

        return 0;
}

static int validate_userns(sd_varlink *link, int userns_fd) {
        int r;

        assert(link);
        assert(userns_fd >= 0);

        r = fd_verify_safe_flags(userns_fd);
        if (r < 0)
                return log_debug_errno(r, "User namespace file descriptor has unsafe flags set: %m");

        /* Validate this is actually a valid user namespace fd */
        r = fd_is_namespace(userns_fd, NAMESPACE_USER);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if user namespace fd is actually a user namespace: %m");
        if (r == 0)
                return sd_varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        /* And refuse the thing if it is our own */
        r = is_our_namespace(userns_fd, NAMESPACE_USER);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if user namespace fd refers to our own user namespace: %m");
        if (r > 0)
                return sd_varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        uid_t peer_uid;
        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return log_debug_errno(r, "Failed to acquire peer UID: %m");

        if (peer_uid != 0) {
                /* Refuse if the userns is not actually owned by our client. */
                uid_t owner_uid;
                if (ioctl(userns_fd, NS_GET_OWNER_UID, &owner_uid) < 0)
                        return log_debug_errno(errno, "Failed to get owner UID of user namespace: %m");

                if (owner_uid != peer_uid)
                        return sd_varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");
        }

        return 0;
}

static int validate_userns_is_empty(sd_varlink *link, int userns_fd) {
        int r;

        assert(link);
        assert(userns_fd >= 0);

        _cleanup_(uid_range_freep) UIDRange *range = NULL;
        r = uid_range_load_userns_by_fd(userns_fd, UID_RANGE_USERNS_OUTSIDE, &range);
        if (r < 0)
                return log_debug_errno(r, "Failed to read userns UID range: %m");

        if (!uid_range_is_empty(range))
                return sd_varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        range = uid_range_free(range);
        r = uid_range_load_userns_by_fd(userns_fd, GID_RANGE_USERNS_OUTSIDE, &range);
        if (r < 0)
                return log_debug_errno(r, "Failed to read userns GID range: %m");

        if (!uid_range_is_empty(range))
                return sd_varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        return 0;
}

typedef struct AllocateParameters {
        const char *name;
        unsigned size;
        unsigned target;
        unsigned userns_fd_idx;
        bool mangle_name;
} AllocateParameters;

static int vl_method_allocate_user_range(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",                        SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(AllocateParameters, name),          SD_JSON_MANDATORY },
                { "size",                        _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         offsetof(AllocateParameters, size),          SD_JSON_MANDATORY },
                { "target",                      _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         offsetof(AllocateParameters, target),        0                 },
                { "userNamespaceFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         offsetof(AllocateParameters, userns_fd_idx), SD_JSON_MANDATORY },
                { "mangleName",                  SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,      offsetof(AllocateParameters, mangle_name),   0                 },
                {}
        };

        struct userns_restrict_bpf **bpf = ASSERT_PTR(userdata);
        _cleanup_close_ int userns_fd = -EBADF, registry_dir_fd = -EBADF, lock_fd = -EBADF;
        _cleanup_free_ char *userns_name = NULL;
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
        if (r != 0)
                return r;

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = validate_name(link, p.name, p.mangle_name, &userns_name);
        if (r != 0)
                return r;

        r = validate_target_and_size(link, p.target, p.size);
        if (r != 0)
                return r;

        userns_fd = sd_varlink_take_fd(link, p.userns_fd_idx);
        if (userns_fd < 0)
                return log_debug_errno(userns_fd, "Failed to take user namespace fd from Varlink connection: %m");

        r = validate_userns(link, userns_fd);
        if (r != 0)
                return r;

        r = validate_userns_is_empty(link, userns_fd);
        if (r != 0)
                return r;

        if (fstat(userns_fd, &userns_st) < 0)
                return log_debug_errno(errno, "Failed to fstat() user namespace fd: %m");

        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;

        if (!*bpf) {
                r = userns_restrict_install(/* pin= */ true, bpf);
                if (r < 0)
                        return r;
        }

        registry_dir_fd = userns_registry_open_fd();
        if (registry_dir_fd < 0)
                return registry_dir_fd;

        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = userns_info_new();
        if (!userns_info)
                return -ENOMEM;

        userns_info->name = TAKE_PTR(userns_name);
        if (!userns_info->name)
                return -ENOMEM;

        userns_info->owner = peer_uid;
        userns_info->userns_inode = userns_st.st_ino;
        userns_info->size = p.size;
        userns_info->target = p.target;

        r = allocate_now(registry_dir_fd, userns_info, &lock_fd);
        if (r == -EHOSTDOWN) /* The needed UID range is not delegated to us */
                return sd_varlink_error(link, "io.systemd.NamespaceResource.DynamicRangeUnavailable", NULL);
        if (r == -EBUSY)     /* All used up */
                return sd_varlink_error(link, "io.systemd.NamespaceResource.NoDynamicRange", NULL);
        if (r == -EDEADLK)
                return sd_varlink_error(link, "io.systemd.NamespaceResource.UserNamespaceExists", NULL);
        if (r == -EEXIST)
                return sd_varlink_error(link, "io.systemd.NamespaceResource.NameExists", NULL);
        if (r < 0)
                return r;

        r = userns_registry_store(registry_dir_fd, userns_info);
        if (r < 0)
                return r;

        /* Register the userns in the BPF map with an empty allowlist */
        r = userns_restrict_put_by_fd(
                        *bpf,
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
        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("name", userns_name));

fail:
        /* Note: we don't have to clean-up the BPF maps in the error path: the bpf map type used will
         * automatically do that once the userns inode goes away */
        userns_registry_remove(registry_dir_fd, userns_info);
        return r;
}

static int validate_userns_is_safe(sd_varlink *link, int userns_fd) {
        int r;

        assert(link);
        assert(userns_fd >= 0);

        /* Read the outside UID range and verify it isn't empty */
        _cleanup_(uid_range_freep) UIDRange *outside_range = NULL;
        r = uid_range_load_userns_by_fd(userns_fd, UID_RANGE_USERNS_OUTSIDE, &outside_range);
        if (r < 0)
                return log_debug_errno(r, "Failed to read userns UID range: %m");
        if (uid_range_is_empty(outside_range))
                return sd_varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        /* Read the outside GID range and check it is the same as the UID range */
        _cleanup_(uid_range_freep) UIDRange *outside_range_gid = NULL;
        r = uid_range_load_userns_by_fd(userns_fd, GID_RANGE_USERNS_OUTSIDE, &outside_range_gid);
        if (r < 0)
                return log_debug_errno(r, "Failed to read userns GID range: %m");
        if (!uid_range_equal(outside_range, outside_range_gid))
                return sd_varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        /* Read the inside UID range, and verify it matches the size of the outside UID range */
        _cleanup_(uid_range_freep) UIDRange *inside_range = NULL;
        r = uid_range_load_userns_by_fd(userns_fd, UID_RANGE_USERNS_INSIDE, &inside_range);
        if (r < 0)
                return log_debug_errno(r, "Failed to read userns contents: %m");
        if (uid_range_size(outside_range) != uid_range_size(inside_range))
                return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Uh, inside and outside UID range sizes don't match.");

        /* Read the inside GID range, and verify it matches the inside UID range */
        _cleanup_(uid_range_freep) UIDRange *inside_range_gid = NULL;
        r = uid_range_load_userns_by_fd(userns_fd, GID_RANGE_USERNS_INSIDE, &inside_range_gid);
        if (r < 0)
                return log_debug_errno(r, "Failed to read userns contents: %m");
        if (!uid_range_equal(inside_range, inside_range_gid))
                return sd_varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        uid_t peer_uid;
        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;

        uid_t peer_gid;
        r = sd_varlink_get_peer_gid(link, &peer_gid);
        if (r < 0)
                return r;

        /* Insist that the first UID/GID in the range matches the client's UID/GID */
        if (outside_range->entries[0].start != peer_uid ||
            outside_range_gid->entries[0].start != peer_gid)
                return sd_varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        /* If there are more than one UID in the range, then also insist that the first UID maps to root inside the userns */
        if (uid_range_size(outside_range) > 1 && inside_range->entries[0].start != 0)
                return sd_varlink_error_invalid_parameter_name(link, "userNamespaceFileDescriptor");

        return 0;
}

typedef struct RegisterParameters {
        const char *name;
        unsigned userns_fd_idx;
        bool mangle_name;
} RegisterParameters;

static int vl_method_register_user_namespace(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",                        SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(RegisterParameters, name),          SD_JSON_MANDATORY },
                { "userNamespaceFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         offsetof(RegisterParameters, userns_fd_idx), SD_JSON_MANDATORY },
                { "mangleName",                  SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,      offsetof(AllocateParameters, mangle_name),   0                 },
                {}
        };

        struct userns_restrict_bpf **bpf = ASSERT_PTR(userdata);
        _cleanup_close_ int userns_fd = -EBADF, registry_dir_fd = -EBADF;
        _cleanup_free_ char *userns_name = NULL;
        uid_t peer_uid;
        struct stat userns_st;
        RegisterParameters p = {
                .userns_fd_idx = UINT_MAX,
        };
        int r;

        assert(link);
        assert(parameters);

        r = test_userns_api_support(link);
        if (r != 0)
                return r;

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = validate_name(link, p.name, p.mangle_name, &userns_name);
        if (r != 0)
                return r;

        userns_fd = sd_varlink_take_fd(link, p.userns_fd_idx);
        if (userns_fd < 0)
                return userns_fd;

        r = validate_userns(link, userns_fd);
        if (r != 0)
                return r;

        r = validate_userns_is_safe(link, userns_fd);
        if (r != 0)
                return r;

        if (fstat(userns_fd, &userns_st) < 0)
                return log_debug_errno(errno, "Failed to fstat() user namespace fd: %m");

        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;

        if (!*bpf) {
                r = userns_restrict_install(/* pin= */ true, bpf);
                if (r < 0)
                        return r;
        }

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
                return sd_varlink_error(link, "io.systemd.NamespaceResource.UserNamespaceExists", NULL);

        r = name_is_available(registry_dir_fd, userns_name);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_varlink_error(link, "io.systemd.NamespaceResource.NameExists", NULL);

        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = userns_info_new();
        if (!userns_info)
                return -ENOMEM;

        userns_info->name = TAKE_PTR(userns_name);
        if (!userns_info->name)
                return -ENOMEM;

        userns_info->owner = peer_uid;
        userns_info->userns_inode = userns_st.st_ino;

        r = userns_registry_store(registry_dir_fd, userns_info);
        if (r < 0)
                return log_debug_errno(r, "Failed to update userns registry: %m");

        /* Register the userns in the BPF map with an empty allowlist */
        r = userns_restrict_put_by_fd(
                        *bpf,
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

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("name", userns_name));

fail:
        userns_registry_remove(registry_dir_fd, userns_info);
        return r;
}

typedef struct AddMountParameters {
        unsigned userns_fd_idx;
        unsigned mount_fd_idx;
} AddMountParameters;

static int vl_method_add_mount_to_user_namespace(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field parameter_dispatch_table[] = {
                { "userNamespaceFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint, offsetof(AddMountParameters, userns_fd_idx), SD_JSON_MANDATORY },
                { "mountFileDescriptor",         _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint, offsetof(AddMountParameters, mount_fd_idx),  SD_JSON_MANDATORY },
                {}
        };

        _cleanup_close_ int userns_fd = -EBADF, mount_fd = -EBADF, registry_dir_fd = -EBADF;
        struct userns_restrict_bpf **bpf = ASSERT_PTR(userdata);
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
        if (r != 0)
                return r;

        /* Allowlisting arbitrary mounts is a privileged operation */
        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;
        if (peer_uid != 0)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        r = sd_varlink_dispatch(link, parameters, parameter_dispatch_table, &p);
        if (r != 0)
                return r;

        userns_fd = sd_varlink_take_fd(link, p.userns_fd_idx);
        if (userns_fd < 0)
                return userns_fd;

        r = validate_userns(link, userns_fd);
        if (r != 0)
                return r;

        if (fstat(userns_fd, &userns_st) < 0)
                return -errno;

        mount_fd = sd_varlink_take_fd(link, p.mount_fd_idx);
        if (mount_fd < 0)
                return mount_fd;

        r = fd_verify_safe_flags_full(mount_fd, O_PATH|O_DIRECTORY);
        if (r < 0)
                return log_debug_errno(r, "Mount file descriptor has unsafe flags set: %m");

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
                return sd_varlink_error(link, "io.systemd.NamespaceResource.UserNamespaceNotRegistered", NULL);
        if (r < 0)
                return r;

        if (!*bpf) {
                r = userns_restrict_install(/* pin= */ true, bpf);
                if (r < 0)
                        return r;
        }

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
                        *bpf,
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

        return sd_varlink_replyb(link, SD_JSON_BUILD_EMPTY_OBJECT);
}

static int validate_cgroup(sd_varlink *link, int fd, uint64_t *ret_cgroup_id) {
        int r;

        assert(link);
        assert(fd >= 0);
        assert(ret_cgroup_id);

        r = fd_verify_safe_flags_full(fd, O_DIRECTORY);
        if (r < 0)
                return log_debug_errno(r, "Control group file descriptor has unsafe flags set: %m");

        r = fd_verify_directory(fd);
        if (r < 0)
                return log_debug_errno(r, "Verification that cgroup fd refers to directory failed: %m");

        r = fd_is_fs_type(fd, CGROUP2_SUPER_MAGIC);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if cgroup fd actually refers to cgroupfs: %m");
        if (r == 0)
                return sd_varlink_error_invalid_parameter_name(link, "controlGroupFileDescriptor");

        r = cg_fd_get_cgroupid(fd, ret_cgroup_id);
        if (r < 0)
                return log_debug_errno(r, "Failed to read cgroup ID from cgroupfs: %m");

        return 0;
}

typedef struct AddCGroupParameters {
        unsigned userns_fd_idx;
        unsigned cgroup_fd_idx;
} AddCGroupParameters;

static int vl_method_add_cgroup_to_user_namespace(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field parameter_dispatch_table[] = {
                { "userNamespaceFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint, offsetof(AddCGroupParameters, userns_fd_idx), SD_JSON_MANDATORY },
                { "controlGroupFileDescriptor",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint, offsetof(AddCGroupParameters, cgroup_fd_idx), SD_JSON_MANDATORY },
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
        if (r != 0)
                return r;

        r = sd_varlink_dispatch(link, parameters, parameter_dispatch_table, &p);
        if (r != 0)
                return r;

        userns_fd = sd_varlink_take_fd(link, p.userns_fd_idx);
        if (userns_fd < 0)
                return log_debug_errno(userns_fd, "Failed to take user namespace fd from Varlink connection: %m");

        r = validate_userns(link, userns_fd);
        if (r != 0)
                return r;

        if (fstat(userns_fd, &userns_st) < 0)
                return log_debug_errno(errno, "Failed to fstat() user namespace fd: %m");

        cgroup_fd = sd_varlink_take_fd(link, p.cgroup_fd_idx);
        if (cgroup_fd < 0)
                return log_debug_errno(cgroup_fd, "Failed to take cgroup fd from Varlink connection: %m");

        uint64_t cgroup_id;
        r = validate_cgroup(link, cgroup_fd, &cgroup_id);
        if (r != 0)
                return r;

        if (fstat(cgroup_fd, &cgroup_st) < 0)
                return log_debug_errno(errno, "Failed to fstat() cgroup fd: %m");

        registry_dir_fd = userns_registry_open_fd();
        if (registry_dir_fd < 0)
                return registry_dir_fd;

        _cleanup_close_ int lock_fd = -EBADF;
        lock_fd = userns_registry_lock(registry_dir_fd);
        if (lock_fd < 0)
                return lock_fd;

        r = userns_registry_load_by_userns_inode(
                        registry_dir_fd,
                        userns_st.st_ino,
                        &userns_info);
        if (r == -ENOENT)
                return sd_varlink_error(link, "io.systemd.NamespaceResource.UserNamespaceNotRegistered", NULL);
        if (r < 0)
                return r;

        /* The user namespace must have a user assigned */
        if (userns_info->size == 0)
                return sd_varlink_error(link, "io.systemd.NamespaceResource.UserNamespaceWithoutUserRange", NULL);
        if (userns_info_has_cgroup(userns_info, cgroup_id))
                return sd_varlink_error(link, "io.systemd.NamespaceResource.ControlGroupAlreadyAdded", NULL);
        if (userns_info->n_cgroups > USER_NAMESPACE_CGROUPS_DELEGATE_MAX)
                return sd_varlink_error(link, "io.systemd.NamespaceResource.TooManyControlGroups", NULL);

        /* Registering a cgroup for this client is only allowed for the root or the owner of a userns */
        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return log_debug_errno(r, "Failed to get connection peer: %m");
        if (peer_uid != 0) {
                if (peer_uid != userns_info->owner)
                        return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

                /* The cgroup must be owned by the owner of the userns */
                if (cgroup_st.st_uid != userns_info->owner)
                        return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);
        }

        r = userns_info_add_cgroup(userns_info, cgroup_id);
        if (r < 0)
                return r;

        r = userns_registry_store(registry_dir_fd, userns_info);
        if (r < 0)
                return r;

        if (fchown(cgroup_fd, userns_info->start, userns_info->start) < 0)
                return log_debug_errno(errno, "Failed to change ownership of cgroup: %m");

        if (fchmod(cgroup_fd, 0755) < 0)
                return log_debug_errno(errno, "Failed to change access mode of cgroup: %m");

        FOREACH_STRING(attr, "cgroup.procs", "cgroup.subtree_control", "cgroup.threads") {
                (void) fchmodat(cgroup_fd, attr, 0644, AT_SYMLINK_NOFOLLOW);
                (void) fchownat(cgroup_fd, attr, userns_info->start, userns_info->start, AT_SYMLINK_NOFOLLOW);
        }

        log_debug("Granting ownership to cgroup %" PRIu64 " to userns " INO_FMT " ('%s' @ UID " UID_FMT ")",
                  cgroup_id, userns_st.st_ino, userns_info->name, userns_info->start);

        return sd_varlink_replyb(link, SD_JSON_BUILD_EMPTY_OBJECT);
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
        siphash24_compress_typesafe(n, &state);

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

static int validate_netns(sd_varlink *link, int userns_fd, int netns_fd) {
        int r;

        assert(link);
        assert(userns_fd >= 0);
        assert(netns_fd >= 0);

        r = fd_verify_safe_flags(netns_fd);
        if (r < 0)
                return log_debug_errno(r, "Network namespace file descriptor has unsafe flags set: %m");

        /* Validate this is actually a valid network namespace fd */
        r = fd_is_namespace(netns_fd, NAMESPACE_NET);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_varlink_error_invalid_parameter_name(link, "networkNamespaceFileDescriptor");

        /* And refuse the thing if it is our own */
        r = is_our_namespace(netns_fd, NAMESPACE_NET);
        if (r < 0)
                return r;
        if (r > 0)
                return sd_varlink_error_invalid_parameter_name(link, "networkNamespaceFileDescriptor");

        /* Check if the netns actually belongs to the userns */
        _cleanup_close_ int owner_userns_fd = -EBADF;
        owner_userns_fd = ioctl(netns_fd, NS_GET_USERNS);
        if (owner_userns_fd < 0)
                return -errno;

        r = inode_same_at(owner_userns_fd, /* path_a= */ NULL, userns_fd, /* path_b= */ NULL, AT_EMPTY_PATH);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_varlink_error_invalid_parameter_name(link, "networkNamespaceFileDescriptor");

        uid_t peer_uid;
        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;

        if (peer_uid != 0) {
                /* Refuse if the netns is not actually owned by our client. */

                uid_t owner_uid;
                if (ioctl(owner_userns_fd, NS_GET_OWNER_UID, &owner_uid) < 0)
                        return -errno;

                if (owner_uid != peer_uid)
                        return sd_varlink_error_invalid_parameter_name(link, "networkNamespaceFileDescriptor");
        }

        return 0;
}

typedef struct AddNetworkParameters {
        unsigned userns_fd_idx;
        unsigned netns_fd_idx;
        const char *ifname;
        const char *mode;
} AddNetworkParameters;

static int vl_method_add_netif_to_user_namespace(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field parameter_dispatch_table[] = {
                { "userNamespaceFileDescriptor",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         offsetof(AddNetworkParameters, userns_fd_idx), SD_JSON_MANDATORY },
                { "networkNamespaceFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         offsetof(AddNetworkParameters, netns_fd_idx),  SD_JSON_MANDATORY },
                { "namespaceInterfaceName",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(AddNetworkParameters, ifname),        0                 },
                { "mode",                           SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(AddNetworkParameters, mode),          SD_JSON_MANDATORY },
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
        if (r != 0)
                return r;

        r = sd_varlink_dispatch(link, parameters, parameter_dispatch_table, &p);
        if (r != 0)
                return r;

        userns_fd = sd_varlink_take_fd(link, p.userns_fd_idx);
        if (userns_fd < 0)
                return userns_fd;

        r = validate_userns(link, userns_fd);
        if (r != 0)
                return r;

        if (fstat(userns_fd, &userns_st) < 0)
                return -errno;

        netns_fd = sd_varlink_take_fd(link, p.netns_fd_idx);
        if (netns_fd < 0)
                return netns_fd;

        r = validate_netns(link, userns_fd, netns_fd);
        if (r != 0)
                return r;

        if (!streq_ptr(p.mode, "veth"))
                return sd_varlink_error_invalid_parameter_name(link, "mode");

        if (p.ifname && !ifname_valid(p.ifname))
                return sd_varlink_error_invalid_parameter_name(link, "interfaceName");

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
                return sd_varlink_error(link, "io.systemd.NamespaceResource.UserNamespaceNotRegistered", NULL);
        if (r < 0)
                return r;

        /* Registering a network interface for this client is only allowed for the root or the owner of a userns */
        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return r;
        if (peer_uid != 0 && peer_uid != userns_info->owner)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

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

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR("hostInterfaceName", SD_JSON_BUILD_STRING(ifname_host)),
                        SD_JSON_BUILD_PAIR("namespaceInterfaceName", SD_JSON_BUILD_STRING(ifname_namespace)));
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
        _cleanup_(userns_restrict_bpf_freep) struct userns_restrict_bpf *bpf = NULL;
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

        r = varlink_server_new(
                        &server,
                        SD_VARLINK_SERVER_INHERIT_USERDATA|
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT|SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT,
                        NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server: %m");

        r = sd_varlink_server_add_interface_many(
                        server,
                        &vl_interface_io_systemd_NamespaceResource,
                        &vl_interface_io_systemd_UserDatabase);
        if (r < 0)
                return log_error_errno(r, "Failed to add UserDatabase and NamespaceResource interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
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

        sd_varlink_server_set_userdata(server, &bpf);

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
