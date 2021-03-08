/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <grp.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <openssl/pem.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/quota.h>
#include <sys/stat.h>

#include "btrfs-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-log-control-api.h"
#include "bus-polkit.h"
#include "clean-ipc.h"
#include "conf-files.h"
#include "device-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "gpt.h"
#include "home-util.h"
#include "homed-conf.h"
#include "homed-home-bus.h"
#include "homed-home.h"
#include "homed-manager-bus.h"
#include "homed-manager.h"
#include "homed-varlink.h"
#include "io-util.h"
#include "mkdir.h"
#include "process-util.h"
#include "quota-util.h"
#include "random-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "udev-util.h"
#include "user-record-sign.h"
#include "user-record-util.h"
#include "user-record.h"
#include "user-util.h"

/* Where to look for private/public keys that are used to sign the user records. We are not using
 * CONF_PATHS_NULSTR() here since we want to insert /var/lib/systemd/home/ in the middle. And we insert that
 * since we want to auto-generate a persistent private/public key pair if we need to. */
#define KEY_PATHS_NULSTR                        \
        "/etc/systemd/home/\0"                  \
        "/run/systemd/home/\0"                  \
        "/var/lib/systemd/home/\0"              \
        "/usr/local/lib/systemd/home/\0"        \
        "/usr/lib/systemd/home/\0"

static bool uid_is_home(uid_t uid) {
        return uid >= HOME_UID_MIN && uid <= HOME_UID_MAX;
}
/* Takes a value generated randomly or by hashing and turns it into a UID in the right range */

#define UID_CLAMP_INTO_HOME_RANGE(rnd) (((uid_t) (rnd) % (HOME_UID_MAX - HOME_UID_MIN + 1)) + HOME_UID_MIN)

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(homes_by_uid_hash_ops, void, trivial_hash_func, trivial_compare_func, Home, home_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(homes_by_name_hash_ops, char, string_hash_func, string_compare_func, Home, home_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(homes_by_worker_pid_hash_ops, void, trivial_hash_func, trivial_compare_func, Home, home_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(homes_by_sysfs_hash_ops, char, path_hash_func, path_compare, Home, home_free);

static int on_home_inotify(sd_event_source *s, const struct inotify_event *event, void *userdata);
static int manager_gc_images(Manager *m);
static int manager_enumerate_images(Manager *m);
static int manager_assess_image(Manager *m, int dir_fd, const char *dir_path, const char *dentry_name);
static void manager_revalidate_image(Manager *m, Home *h);

static void manager_watch_home(Manager *m) {
        struct statfs sfs;
        int r;

        assert(m);

        m->inotify_event_source = sd_event_source_disable_unref(m->inotify_event_source);
        m->scan_slash_home = false;

        if (statfs("/home/", &sfs) < 0) {
                log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                               "Failed to statfs() /home/ directory, disabling automatic scanning.");
                return;
        }

        if (is_network_fs(&sfs)) {
                log_info("/home/ is a network file system, disabling automatic scanning.");
                return;
        }

        if (is_fs_type(&sfs, AUTOFS_SUPER_MAGIC)) {
                log_info("/home/ is on autofs, disabling automatic scanning.");
                return;
        }

        m->scan_slash_home = true;

        r = sd_event_add_inotify(m->event, &m->inotify_event_source, "/home/",
                                 IN_CREATE|IN_CLOSE_WRITE|IN_DELETE_SELF|IN_MOVE_SELF|IN_ONLYDIR|IN_MOVED_TO|IN_MOVED_FROM|IN_DELETE,
                                 on_home_inotify, m);
        if (r < 0)
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to create inotify watch on /home/, ignoring.");

        (void) sd_event_source_set_description(m->inotify_event_source, "home-inotify");
}

static int on_home_inotify(sd_event_source *s, const struct inotify_event *event, void *userdata) {
        Manager *m = userdata;
        const char *e, *n;

        assert(m);
        assert(event);

        if ((event->mask & (IN_Q_OVERFLOW|IN_MOVE_SELF|IN_DELETE_SELF|IN_IGNORED|IN_UNMOUNT)) != 0) {

                if (FLAGS_SET(event->mask, IN_Q_OVERFLOW))
                        log_debug("/home/ inotify queue overflow, rescanning.");
                else if (FLAGS_SET(event->mask, IN_MOVE_SELF))
                        log_info("/home/ moved or renamed, recreating watch and rescanning.");
                else if (FLAGS_SET(event->mask, IN_DELETE_SELF))
                        log_info("/home/ deleted, recreating watch and rescanning.");
                else if (FLAGS_SET(event->mask, IN_UNMOUNT))
                        log_info("/home/ unmounted, recreating watch and rescanning.");
                else if (FLAGS_SET(event->mask, IN_IGNORED))
                        log_info("/home/ watch invalidated, recreating watch and rescanning.");

                manager_watch_home(m);
                (void) manager_gc_images(m);
                (void) manager_enumerate_images(m);
                (void) bus_manager_emit_auto_login_changed(m);
                return 0;
        }

        /* For the other inotify events, let's ignore all events for file names that don't match our
         * expectations */
        if (isempty(event->name))
                return 0;
        e = endswith(event->name, FLAGS_SET(event->mask, IN_ISDIR) ? ".homedir" : ".home");
        if (!e)
                return 0;

        n = strndupa(event->name, e - event->name);
        if (!suitable_user_name(n))
                return 0;

        if ((event->mask & (IN_CREATE|IN_CLOSE_WRITE|IN_MOVED_TO)) != 0) {
                if (FLAGS_SET(event->mask, IN_CREATE))
                        log_debug("/home/%s has been created, having a look.", event->name);
                else if (FLAGS_SET(event->mask, IN_CLOSE_WRITE))
                        log_debug("/home/%s has been modified, having a look.", event->name);
                else if (FLAGS_SET(event->mask, IN_MOVED_TO))
                        log_debug("/home/%s has been moved in, having a look.", event->name);

                (void) manager_assess_image(m, -1, "/home/", event->name);
                (void) bus_manager_emit_auto_login_changed(m);
        }

        if ((event->mask & (IN_DELETE | IN_CLOSE_WRITE | IN_MOVED_FROM)) != 0) {
                Home *h;

                if (FLAGS_SET(event->mask, IN_DELETE))
                        log_debug("/home/%s has been deleted, revalidating.", event->name);
                else if (FLAGS_SET(event->mask, IN_CLOSE_WRITE))
                        log_debug("/home/%s has been closed after writing, revalidating.", event->name);
                else if (FLAGS_SET(event->mask, IN_MOVED_FROM))
                        log_debug("/home/%s has been moved away, revalidating.", event->name);

                h = hashmap_get(m->homes_by_name, n);
                if (h) {
                        manager_revalidate_image(m, h);
                        (void) bus_manager_emit_auto_login_changed(m);
                }
        }

        return 0;
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .default_storage = _USER_STORAGE_INVALID,
        };

        r = manager_parse_config_file(m);
        if (r < 0)
                return r;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return r;

        (void) sd_event_set_watchdog(m->event, true);

        m->homes_by_uid = hashmap_new(&homes_by_uid_hash_ops);
        if (!m->homes_by_uid)
                return -ENOMEM;

        m->homes_by_name = hashmap_new(&homes_by_name_hash_ops);
        if (!m->homes_by_name)
                return -ENOMEM;

        m->homes_by_worker_pid = hashmap_new(&homes_by_worker_pid_hash_ops);
        if (!m->homes_by_worker_pid)
                return -ENOMEM;

        m->homes_by_sysfs = hashmap_new(&homes_by_sysfs_hash_ops);
        if (!m->homes_by_sysfs)
                return -ENOMEM;

        *ret = TAKE_PTR(m);
        return 0;
}

Manager* manager_free(Manager *m) {
        Home *h;

        assert(m);

        HASHMAP_FOREACH(h, m->homes_by_worker_pid)
                (void) home_wait_for_worker(h);

        sd_bus_flush_close_unref(m->bus);
        bus_verify_polkit_async_registry_free(m->polkit_registry);

        m->device_monitor = sd_device_monitor_unref(m->device_monitor);

        m->inotify_event_source = sd_event_source_unref(m->inotify_event_source);
        m->notify_socket_event_source = sd_event_source_unref(m->notify_socket_event_source);
        m->deferred_rescan_event_source = sd_event_source_unref(m->deferred_rescan_event_source);
        m->deferred_gc_event_source = sd_event_source_unref(m->deferred_gc_event_source);
        m->deferred_auto_login_event_source = sd_event_source_unref(m->deferred_auto_login_event_source);

        sd_event_unref(m->event);

        hashmap_free(m->homes_by_uid);
        hashmap_free(m->homes_by_name);
        hashmap_free(m->homes_by_worker_pid);
        hashmap_free(m->homes_by_sysfs);

        if (m->private_key)
                EVP_PKEY_free(m->private_key);

        hashmap_free(m->public_keys);

        varlink_server_unref(m->varlink_server);
        free(m->userdb_service);

        free(m->default_file_system_type);

        return mfree(m);
}

int manager_verify_user_record(Manager *m, UserRecord *hr) {
        EVP_PKEY *pkey;
        int r;

        assert(m);
        assert(hr);

        if (!m->private_key && hashmap_isempty(m->public_keys)) {
                r = user_record_has_signature(hr);
                if (r < 0)
                        return r;

                return r ? -ENOKEY : USER_RECORD_UNSIGNED;
        }

        /* Is it our own? */
        if (m->private_key) {
                r = user_record_verify(hr, m->private_key);
                switch (r) {

                case USER_RECORD_FOREIGN:
                        /* This record is not signed by this key, but let's see below */
                        break;

                case USER_RECORD_SIGNED:               /* Signed by us, but also by others, let's propagate that */
                case USER_RECORD_SIGNED_EXCLUSIVE:     /* Signed by us, and nothing else, ditto */
                case USER_RECORD_UNSIGNED:             /* Not signed at all, ditto  */
                default:
                        return r;
                }
        }

        HASHMAP_FOREACH(pkey, m->public_keys) {
                r = user_record_verify(hr, pkey);
                switch (r) {

                case USER_RECORD_FOREIGN:
                        /* This record is not signed by this key, but let's see our other keys */
                        break;

                case USER_RECORD_SIGNED:            /* It's signed by this key we are happy with, but which is not our own. */
                case USER_RECORD_SIGNED_EXCLUSIVE:
                        return USER_RECORD_FOREIGN;

                case USER_RECORD_UNSIGNED: /* It's not signed at all */
                default:
                        return r;
                }
        }

        return -ENOKEY;
}

static int manager_add_home_by_record(
                Manager *m,
                const char *name,
                int dir_fd,
                const char *fname) {

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        unsigned line, column;
        int r, is_signed;
        struct stat st;
        Home *h;

        assert(m);
        assert(name);
        assert(fname);

        if (fstatat(dir_fd, fname, &st, 0) < 0)
                return log_error_errno(errno, "Failed to stat identity record %s: %m", fname);

        if (!S_ISREG(st.st_mode)) {
                log_debug("Identity record file %s is not a regular file, ignoring.", fname);
                return 0;
        }

        if (st.st_size == 0)
                goto unlink_this_file;

        r = json_parse_file_at(NULL, dir_fd, fname, JSON_PARSE_SENSITIVE, &v, &line, &column);
        if (r < 0)
                return log_error_errno(r, "Failed to parse identity record at %s:%u%u: %m", fname, line, column);

        if (json_variant_is_blank_object(v))
                goto unlink_this_file;

        hr = user_record_new();
        if (!hr)
                return log_oom();

        r = user_record_load(hr, v, USER_RECORD_LOAD_REFUSE_SECRET|USER_RECORD_LOG);
        if (r < 0)
                return r;

        if (!streq_ptr(hr->user_name, name))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Identity's user name %s does not match file name %s, refusing.",
                                       hr->user_name, name);

        is_signed = manager_verify_user_record(m, hr);
        switch (is_signed) {

        case -ENOKEY:
                return log_warning_errno(is_signed, "User record %s is not signed by any accepted key, ignoring.", fname);
        case USER_RECORD_UNSIGNED:
                return log_warning_errno(SYNTHETIC_ERRNO(EPERM), "User record %s is not signed at all, ignoring.", fname);
        case USER_RECORD_SIGNED:
                log_info("User record %s is signed by us (and others), accepting.", fname);
                break;
        case USER_RECORD_SIGNED_EXCLUSIVE:
                log_info("User record %s is signed only by us, accepting.", fname);
                break;
        case USER_RECORD_FOREIGN:
                log_info("User record %s is signed by registered key from others, accepting.", fname);
                break;
        default:
                assert(is_signed < 0);
                return log_error_errno(is_signed, "Failed to verify signature of user record in %s: %m", fname);
        }

        h = hashmap_get(m->homes_by_name, name);
        if (h) {
                r = home_set_record(h, hr);
                if (r < 0)
                        return log_error_errno(r, "Failed to update home record for %s: %m", name);

                /* If we acquired a record now for a previously unallocated entry, then reset the state. This
                 * makes sure home_get_state() will check for the availability of the image file dynamically
                 * in order to detect to distinguish HOME_INACTIVE and HOME_ABSENT. */
                if (h->state == HOME_UNFIXATED)
                        h->state = _HOME_STATE_INVALID;
        } else {
                r = home_new(m, hr, NULL, &h);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate new home object: %m");

                log_info("Added registered home for user %s.", hr->user_name);
        }

        /* Only entries we exclusively signed are writable to us, hence remember the result */
        h->signed_locally = is_signed == USER_RECORD_SIGNED_EXCLUSIVE;

        return 1;

unlink_this_file:
        /* If this is an empty file, then let's just remove it. An empty file is not useful in any case, and
         * apparently xfs likes to leave empty files around when not unmounted cleanly (see
         * https://github.com/systemd/systemd/issues/15178 for example). Note that we don't delete non-empty
         * files even if they are invalid, because that's just too risky, we might delete data the user still
         * needs. But empty files are never useful, hence let's just remove them. */

        if (unlinkat(dir_fd, fname, 0) < 0)
                return log_error_errno(errno, "Failed to remove empty user record file %s: %m", fname);

        log_notice("Discovered empty user record file /var/lib/systemd/home/%s, removed automatically.", fname);
        return 0;
}

static int manager_enumerate_records(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;

        assert(m);

        d = opendir("/var/lib/systemd/home/");
        if (!d)
                return log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_ERR, errno,
                                      "Failed to open /var/lib/systemd/home/: %m");

        FOREACH_DIRENT(de, d, return log_error_errno(errno, "Failed to read record directory: %m")) {
                _cleanup_free_ char *n = NULL;
                const char *e;

                if (!dirent_is_file(de))
                        continue;

                e = endswith(de->d_name, ".identity");
                if (!e)
                        continue;

                n = strndup(de->d_name, e - de->d_name);
                if (!n)
                        return log_oom();

                if (!suitable_user_name(n))
                        continue;

                (void) manager_add_home_by_record(m, n, dirfd(d), de->d_name);
        }

        return 0;
}

static int search_quota(uid_t uid, const char *exclude_quota_path) {
        struct stat exclude_st = {};
        dev_t previous_devno = 0;
        const char *where;
        int r;

        /* Checks whether the specified UID owns any files on the files system, but ignore any file system
         * backing the specified file. The file is used when operating on home directories, where it's OK if
         * the UID of them already owns files. */

        if (exclude_quota_path && stat(exclude_quota_path, &exclude_st) < 0) {
                if (errno != ENOENT)
                        return log_warning_errno(errno, "Failed to stat %s, ignoring: %m", exclude_quota_path);
        }

        /* Check a few usual suspects where regular users might own files. Note that this is by no means
         * comprehensive, but should cover most cases. Note that in an ideal world every user would be
         * registered in NSS and avoid our own UID range, but for all other cases, it's a good idea to be
         * paranoid and check quota if we can. */
        FOREACH_STRING(where, "/home/", "/tmp/", "/var/", "/var/mail/", "/var/tmp/", "/var/spool/") {
                struct dqblk req;
                struct stat st;

                if (stat(where, &st) < 0) {
                        log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_ERR, errno,
                                       "Failed to stat %s, ignoring: %m", where);
                        continue;
                }

                if (major(st.st_dev) == 0) {
                        log_debug("Directory %s is not on a real block device, not checking quota for UID use.", where);
                        continue;
                }

                if (st.st_dev == exclude_st.st_dev) { /* If an exclude path is specified, then ignore quota
                                                       * reported on the same block device as that path. */
                        log_debug("Directory %s is where the home directory is located, not checking quota for UID use.", where);
                        continue;
                }

                if (st.st_dev == previous_devno) { /* Does this directory have the same devno as the previous
                                                    * one we tested? If so, there's no point in testing this
                                                    * again. */
                        log_debug("Directory %s is on same device as previous tested directory, not checking quota for UID use a second time.", where);
                        continue;
                }

                previous_devno = st.st_dev;

                r = quotactl_devno(QCMD_FIXED(Q_GETQUOTA, USRQUOTA), st.st_dev, uid, &req);
                if (r < 0) {
                        if (ERRNO_IS_NOT_SUPPORTED(r))
                                log_debug_errno(r, "No UID quota support on %s, ignoring.", where);
                        else if (ERRNO_IS_PRIVILEGE(r))
                                log_debug_errno(r, "UID quota support for %s prohibited, ignoring.", where);
                        else
                                log_warning_errno(r, "Failed to query quota on %s, ignoring: %m", where);

                        continue;
                }

                if ((FLAGS_SET(req.dqb_valid, QIF_SPACE) && req.dqb_curspace > 0) ||
                    (FLAGS_SET(req.dqb_valid, QIF_INODES) && req.dqb_curinodes > 0)) {
                        log_debug_errno(errno, "Quota reports UID " UID_FMT " occupies disk space on %s.", uid, where);
                        return 1;
                }
        }

        return 0;
}

static int manager_acquire_uid(
                Manager *m,
                uid_t start_uid,
                const char *user_name,
                const char *exclude_quota_path,
                uid_t *ret) {

        static const uint8_t hash_key[] = {
                0xa3, 0xb8, 0x82, 0x69, 0x9a, 0x71, 0xf7, 0xa9,
                0xe0, 0x7c, 0xf6, 0xf1, 0x21, 0x69, 0xd2, 0x1e
        };

        enum {
                PHASE_SUGGESTED,
                PHASE_HASHED,
                PHASE_RANDOM
        } phase = PHASE_SUGGESTED;

        unsigned n_tries = 100;
        int r;

        assert(m);
        assert(ret);

        for (;;) {
                struct passwd *pw;
                struct group *gr;
                uid_t candidate;
                Home *other;

                if (--n_tries <= 0)
                        return -EBUSY;

                switch (phase) {

                case PHASE_SUGGESTED:
                        phase = PHASE_HASHED;

                        if (!uid_is_home(start_uid))
                                continue;

                        candidate = start_uid;
                        break;

                case PHASE_HASHED:
                        phase = PHASE_RANDOM;

                        if (!user_name)
                                continue;

                        candidate = UID_CLAMP_INTO_HOME_RANGE(siphash24(user_name, strlen(user_name), hash_key));
                        break;

                case PHASE_RANDOM:
                        random_bytes(&candidate, sizeof(candidate));
                        candidate = UID_CLAMP_INTO_HOME_RANGE(candidate);
                        break;

                default:
                        assert_not_reached("unknown phase");
                }

                other = hashmap_get(m->homes_by_uid, UID_TO_PTR(candidate));
                if (other) {
                        log_debug("Candidate UID " UID_FMT " already used by another home directory (%s), let's try another.",
                                  candidate, other->user_name);
                        continue;
                }

                pw = getpwuid(candidate);
                if (pw) {
                        log_debug("Candidate UID " UID_FMT " already registered by another user in NSS (%s), let's try another.",
                                  candidate, pw->pw_name);
                        continue;
                }

                gr = getgrgid((gid_t) candidate);
                if (gr) {
                        log_debug("Candidate UID " UID_FMT " already registered by another group in NSS (%s), let's try another.",
                                  candidate, gr->gr_name);
                        continue;
                }

                r = search_ipc(candidate, (gid_t) candidate);
                if (r < 0)
                        continue;
                if (r > 0) {
                        log_debug_errno(r, "Candidate UID " UID_FMT " already owns IPC objects, let's try another: %m",
                                        candidate);
                        continue;
                }

                r = search_quota(candidate, exclude_quota_path);
                if (r != 0)
                        continue;

                *ret = candidate;
                return 0;
        }
}

static int manager_add_home_by_image(
                Manager *m,
                const char *user_name,
                const char *realm,
                const char *image_path,
                const char *sysfs,
                UserStorage storage,
                uid_t start_uid) {

        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        uid_t uid;
        Home *h;
        int r;

        assert(m);

        assert(m);
        assert(user_name);
        assert(image_path);
        assert(storage >= 0);
        assert(storage < _USER_STORAGE_MAX);

        h = hashmap_get(m->homes_by_name, user_name);
        if (h) {
                bool same;

                if (h->state != HOME_UNFIXATED) {
                        log_debug("Found an image for user %s which already has a record, skipping.", user_name);
                        return 0; /* ignore images that synthesize a user we already have a record for */
                }

                same = user_record_storage(h->record) == storage;
                if (same) {
                        if (h->sysfs && sysfs)
                                same = path_equal(h->sysfs, sysfs);
                        else if (!!h->sysfs != !!sysfs)
                                same = false;
                        else {
                                const char *p;

                                p = user_record_image_path(h->record);
                                same = p && path_equal(p, image_path);
                        }
                }

                if (!same) {
                        log_debug("Found multiple images for user '%s', ignoring image '%s'.", user_name, image_path);
                        return 0;
                }
        } else {
                /* Check NSS, in case there's another user or group by this name */
                if (getpwnam(user_name) || getgrnam(user_name)) {
                        log_debug("Found an existing user or group by name '%s', ignoring image '%s'.", user_name, image_path);
                        return 0;
                }
        }

        if (h && uid_is_valid(h->uid))
                uid = h->uid;
        else {
                r = manager_acquire_uid(m, start_uid, user_name,
                                        IN_SET(storage, USER_SUBVOLUME, USER_DIRECTORY, USER_FSCRYPT) ? image_path : NULL,
                                        &uid);
                if (r < 0)
                        return log_warning_errno(r, "Failed to acquire unused UID for %s: %m", user_name);
        }

        hr = user_record_new();
        if (!hr)
                return log_oom();

        r = user_record_synthesize(hr, user_name, realm, image_path, storage, uid, (gid_t) uid);
        if (r < 0)
                return log_error_errno(r, "Failed to synthesize home record for %s (image %s): %m", user_name, image_path);

        if (h) {
                r = home_set_record(h, hr);
                if (r < 0)
                        return log_error_errno(r, "Failed to update home record for %s: %m", user_name);
        } else {
                r = home_new(m, hr, sysfs, &h);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate new home object: %m");

                h->state = HOME_UNFIXATED;

                log_info("Discovered new home for user %s through image %s.", user_name, image_path);
        }

        return 1;
}

int manager_augment_record_with_uid(
                Manager *m,
                UserRecord *hr) {

        const char *exclude_quota_path = NULL;
        uid_t start_uid = UID_INVALID, uid;
        int r;

        assert(m);
        assert(hr);

        if (uid_is_valid(hr->uid))
                return 0;

        if (IN_SET(hr->storage, USER_CLASSIC, USER_SUBVOLUME, USER_DIRECTORY, USER_FSCRYPT)) {
                const char * ip;

                ip = user_record_image_path(hr);
                if (ip) {
                        struct stat st;

                        if (stat(ip, &st) < 0) {
                                if (errno != ENOENT)
                                        log_warning_errno(errno, "Failed to stat(%s): %m", ip);
                        }  else if (uid_is_home(st.st_uid)) {
                                start_uid = st.st_uid;
                                exclude_quota_path = ip;
                        }
                }
        }

        r = manager_acquire_uid(m, start_uid, hr->user_name, exclude_quota_path, &uid);
        if (r < 0)
                return r;

        log_debug("Acquired new UID " UID_FMT " for %s.", uid, hr->user_name);

        r = user_record_add_binding(
                        hr,
                        _USER_STORAGE_INVALID,
                        NULL,
                        SD_ID128_NULL,
                        SD_ID128_NULL,
                        SD_ID128_NULL,
                        NULL,
                        NULL,
                        UINT64_MAX,
                        NULL,
                        NULL,
                        uid,
                        (gid_t) uid);
        if (r < 0)
                return r;

        return 1;
}

static int manager_assess_image(
                Manager *m,
                int dir_fd,
                const char *dir_path,
                const char *dentry_name) {

        char *luks_suffix, *directory_suffix;
        _cleanup_free_ char *path = NULL;
        struct stat st;
        int r;

        assert(m);
        assert(dir_path);
        assert(dentry_name);

        luks_suffix = endswith(dentry_name, ".home");
        if (luks_suffix)
                directory_suffix = NULL;
        else
                directory_suffix = endswith(dentry_name, ".homedir");

        /* Early filter out: by name */
        if (!luks_suffix && !directory_suffix)
                return 0;

        path = path_join(dir_path, dentry_name);
        if (!path)
                return log_oom();

        /* Follow symlinks here, to allow people to link in stuff to make them available locally. */
        if (dir_fd >= 0)
                r = fstatat(dir_fd, dentry_name, &st, 0);
        else
                r = stat(path, &st);
        if (r < 0)
                return log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                                      "Failed to stat() directory entry '%s', ignoring: %m", dentry_name);

        if (S_ISREG(st.st_mode)) {
                _cleanup_free_ char *n = NULL, *user_name = NULL, *realm = NULL;

                if (!luks_suffix)
                        return 0;

                n = strndup(dentry_name, luks_suffix - dentry_name);
                if (!n)
                        return log_oom();

                r = split_user_name_realm(n, &user_name, &realm);
                if (r == -EINVAL) /* Not the right format: ignore */
                        return 0;
                if (r < 0)
                        return log_error_errno(r, "Failed to split image name into user name/realm: %m");

                return manager_add_home_by_image(m, user_name, realm, path, NULL, USER_LUKS, UID_INVALID);
        }

        if (S_ISDIR(st.st_mode)) {
                _cleanup_free_ char *n = NULL, *user_name = NULL, *realm = NULL;
                _cleanup_close_ int fd = -1;
                UserStorage storage;

                if (!directory_suffix)
                        return 0;

                n = strndup(dentry_name, directory_suffix - dentry_name);
                if (!n)
                        return log_oom();

                r = split_user_name_realm(n, &user_name, &realm);
                if (r == -EINVAL) /* Not the right format: ignore */
                        return 0;
                if (r < 0)
                        return log_error_errno(r, "Failed to split image name into user name/realm: %m");

                if (dir_fd >= 0)
                        fd = openat(dir_fd, dentry_name, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
                else
                        fd = open(path, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                                              "Failed to open directory '%s', ignoring: %m", path);

                if (fstat(fd, &st) < 0)
                        return log_warning_errno(errno, "Failed to fstat() %s, ignoring: %m", path);

                assert(S_ISDIR(st.st_mode)); /* Must hold, we used O_DIRECTORY above */

                r = btrfs_is_subvol_fd(fd);
                if (r < 0)
                        return log_warning_errno(errno, "Failed to determine whether %s is a btrfs subvolume: %m", path);
                if (r > 0)
                        storage = USER_SUBVOLUME;
                else {
                        struct fscrypt_policy policy;

                        if (ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY, &policy) < 0) {

                                if (errno == ENODATA)
                                        log_debug_errno(errno, "Determined %s is not fscrypt encrypted.", path);
                                else if (ERRNO_IS_NOT_SUPPORTED(errno))
                                        log_debug_errno(errno, "Determined %s is not fscrypt encrypted because kernel or file system doesn't support it.", path);
                                else
                                        log_debug_errno(errno, "FS_IOC_GET_ENCRYPTION_POLICY failed with unexpected error code on %s, ignoring: %m", path);

                                storage = USER_DIRECTORY;
                        } else
                                storage = USER_FSCRYPT;
                }

                return manager_add_home_by_image(m, user_name, realm, path, NULL, storage, st.st_uid);
        }

        return 0;
}

int manager_enumerate_images(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;

        assert(m);

        if (!m->scan_slash_home)
                return 0;

        d = opendir("/home/");
        if (!d)
                return log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_ERR, errno,
                                      "Failed to open /home/: %m");

        FOREACH_DIRENT(de, d, return log_error_errno(errno, "Failed to read /home/ directory: %m"))
                (void) manager_assess_image(m, dirfd(d), "/home", de->d_name);

        return 0;
}

static int manager_connect_bus(Manager *m) {
        const char *suffix, *busname;
        int r;

        assert(m);
        assert(!m->bus);

        r = sd_bus_default_system(&m->bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = bus_add_implementation(m->bus, &manager_object, m);
        if (r < 0)
                return r;

        suffix = getenv("SYSTEMD_HOME_DEBUG_SUFFIX");
        if (suffix)
                busname = strjoina("org.freedesktop.home1.", suffix);
        else
                busname = "org.freedesktop.home1";

        r = sd_bus_request_name_async(m->bus, NULL, busname, 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        (void) sd_bus_set_exit_on_disconnect(m->bus, true);

        return 0;
}

static int manager_bind_varlink(Manager *m) {
        const char *suffix, *socket_path;
        int r;

        assert(m);
        assert(!m->varlink_server);

        r = varlink_server_new(&m->varlink_server, VARLINK_SERVER_ACCOUNT_UID|VARLINK_SERVER_INHERIT_USERDATA);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        varlink_server_set_userdata(m->varlink_server, m);

        r = varlink_server_bind_method_many(
                        m->varlink_server,
                        "io.systemd.UserDatabase.GetUserRecord",  vl_method_get_user_record,
                        "io.systemd.UserDatabase.GetGroupRecord", vl_method_get_group_record,
                        "io.systemd.UserDatabase.GetMemberships", vl_method_get_memberships);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        (void) mkdir_p("/run/systemd/userdb", 0755);

        /* To make things easier to debug, when working from a homed managed home directory, let's optionally
         * use a different varlink socket name */
        suffix = getenv("SYSTEMD_HOME_DEBUG_SUFFIX");
        if (suffix)
                socket_path = strjoina("/run/systemd/userdb/io.systemd.Home.", suffix);
        else
                socket_path = "/run/systemd/userdb/io.systemd.Home";

        r = varlink_server_listen_address(m->varlink_server, socket_path, 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket: %m");

        r = varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        assert(!m->userdb_service);
        m->userdb_service = strdup(basename(socket_path));
        if (!m->userdb_service)
                return log_oom();

        /* Avoid recursion */
        if (setenv("SYSTEMD_BYPASS_USERDB", m->userdb_service, 1) < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to set $SYSTEMD_BYPASS_USERDB: %m");

        return 0;
}

static ssize_t read_datagram(int fd, struct ucred *ret_sender, void **ret) {
        _cleanup_free_ void *buffer = NULL;
        ssize_t n, m;

        assert(fd >= 0);
        assert(ret_sender);
        assert(ret);

        n = next_datagram_size_fd(fd);
        if (n < 0)
                return n;

        buffer = malloc(n + 2);
        if (!buffer)
                return -ENOMEM;

        if (ret_sender) {
                CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control;
                bool found_ucred = false;
                struct cmsghdr *cmsg;
                struct msghdr mh;
                struct iovec iov;

                /* Pass one extra byte, as a size check */
                iov = IOVEC_MAKE(buffer, n + 1);

                mh = (struct msghdr) {
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
                        .msg_control = &control,
                        .msg_controllen = sizeof(control),
                };

                m = recvmsg_safe(fd, &mh, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
                if (m < 0)
                        return m;

                cmsg_close_all(&mh);

                /* Ensure the size matches what we determined before */
                if (m != n)
                        return -EMSGSIZE;

                CMSG_FOREACH(cmsg, &mh)
                        if (cmsg->cmsg_level == SOL_SOCKET &&
                            cmsg->cmsg_type == SCM_CREDENTIALS &&
                            cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {

                                memcpy(ret_sender, CMSG_DATA(cmsg), sizeof(struct ucred));
                                found_ucred = true;
                        }

                if (!found_ucred)
                        *ret_sender = (struct ucred) {
                                .pid = 0,
                                .uid = UID_INVALID,
                                .gid = GID_INVALID,
                        };
        } else {
                m = recv(fd, buffer, n + 1, MSG_DONTWAIT);
                if (m < 0)
                        return -errno;

                /* Ensure the size matches what we determined before */
                if (m != n)
                        return -EMSGSIZE;
        }

        /* For safety reasons: let's always NUL terminate.  */
        ((char*) buffer)[n] = 0;
        *ret = TAKE_PTR(buffer);

        return 0;
}

static int on_notify_socket(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ void *datagram = NULL;
        struct ucred sender;
        Manager *m = userdata;
        ssize_t n;
        Home *h;

        assert(s);
        assert(m);

        n = read_datagram(fd, &sender, &datagram);
        if (IN_SET(n, -EAGAIN, -EINTR))
                return 0;
        if (n < 0)
                return log_error_errno(n, "Failed to read notify datagram: %m");

        if (sender.pid <= 0) {
                log_warning("Received notify datagram without valid sender PID, ignoring.");
                return 0;
        }

        h = hashmap_get(m->homes_by_worker_pid, PID_TO_PTR(sender.pid));
        if (!h) {
                log_warning("Received notify datagram of unknown process, ignoring.");
                return 0;
        }

        l = strv_split(datagram, "\n");
        if (!l)
                return log_oom();

        home_process_notify(h, l);
        return 0;
}

static int manager_listen_notify(Manager *m) {
        _cleanup_close_ int fd = -1;
        union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/home/notify",
        };
        const char *suffix;
        int r;

        assert(m);
        assert(!m->notify_socket_event_source);

        suffix = getenv("SYSTEMD_HOME_DEBUG_SUFFIX");
        if (suffix) {
                const char *unix_path;

                unix_path = strjoina("/run/systemd/home/notify.", suffix);
                r = sockaddr_un_set_path(&sa.un, unix_path);
                if (r < 0)
                        return log_error_errno(r, "Socket path %s does not fit in sockaddr_un: %m", unix_path);
        }

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to create listening socket: %m");

        (void) mkdir_parents(sa.un.sun_path, 0755);
        (void) sockaddr_un_unlink(&sa.un);

        if (bind(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un)) < 0)
                return log_error_errno(errno, "Failed to bind to socket: %m");

        r = setsockopt_int(fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return r;

        r = sd_event_add_io(m->event, &m->notify_socket_event_source, fd, EPOLLIN, on_notify_socket, m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event source for notify socket: %m");

        (void) sd_event_source_set_description(m->notify_socket_event_source, "notify-socket");

        /* Make sure we process sd_notify() before SIGCHLD for any worker, so that we always know the error
         * number of a client before it exits. */
        r = sd_event_source_set_priority(m->notify_socket_event_source, SD_EVENT_PRIORITY_NORMAL - 5);
        if (r < 0)
                return log_error_errno(r, "Failed to alter priority of NOTIFY_SOCKET event source: %m");

        r = sd_event_source_set_io_fd_own(m->notify_socket_event_source, true);
        if (r < 0)
                return log_error_errno(r, "Failed to pass ownership of notify socket: %m");

        return TAKE_FD(fd);
}

static int manager_add_device(Manager *m, sd_device *d) {
        _cleanup_free_ char *user_name = NULL, *realm = NULL, *node = NULL;
        const char *tabletype, *parttype, *partname, *partuuid, *sysfs;
        sd_id128_t id;
        int r;

        assert(m);
        assert(d);

        r = sd_device_get_syspath(d, &sysfs);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire sysfs path of device: %m");

        r = sd_device_get_property_value(d, "ID_PART_TABLE_TYPE", &tabletype);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to acquire ID_PART_TABLE_TYPE device property, ignoring: %m");

        if (!streq(tabletype, "gpt")) {
                log_debug("Found partition (%s) on non-GPT table, ignoring.", sysfs);
                return 0;
        }

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_TYPE", &parttype);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to acquire ID_PART_ENTRY_TYPE device property, ignoring: %m");
        r = sd_id128_from_string(parttype, &id);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse ID_PART_ENTRY_TYPE field '%s', ignoring: %m", parttype);
        if (!sd_id128_equal(id, GPT_USER_HOME)) {
                log_debug("Found partition (%s) we don't care about, ignoring.", sysfs);
                return 0;
        }

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_NAME", &partname);
        if (r < 0)
                return log_warning_errno(r, "Failed to acquire ID_PART_ENTRY_NAME device property, ignoring: %m");

        r = split_user_name_realm(partname, &user_name, &realm);
        if (r == -EINVAL)
                return log_warning_errno(r, "Found partition with correct partition type but a non-parsable partition name '%s', ignoring.", partname);
        if (r < 0)
                return log_error_errno(r, "Failed to validate partition name '%s': %m", partname);

        r = sd_device_get_property_value(d, "ID_FS_UUID", &partuuid);
        if (r < 0)
                return log_warning_errno(r, "Failed to acquire ID_FS_UUID device property, ignoring: %m");

        r = sd_id128_from_string(partuuid, &id);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse ID_FS_UUID field '%s', ignoring: %m", partuuid);

        if (asprintf(&node, "/dev/disk/by-uuid/" SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(id)) < 0)
                return log_oom();

        return manager_add_home_by_image(m, user_name, realm, node, sysfs, USER_LUKS, UID_INVALID);
}

static int manager_on_device(sd_device_monitor *monitor, sd_device *d, void *userdata) {
        Manager *m = userdata;
        int r;

        assert(m);
        assert(d);

        if (device_for_action(d, SD_DEVICE_REMOVE)) {
                const char *sysfs;
                Home *h;

                r = sd_device_get_syspath(d, &sysfs);
                if (r < 0) {
                        log_warning_errno(r, "Failed to acquire sysfs path from device: %m");
                        return 0;
                }

                log_info("block device %s has been removed.", sysfs);

                /* Let's see if we previously synthesized a home record from this device, if so, let's just
                 * revalidate that. Otherwise let's revalidate them all, but asynchronously. */
                h = hashmap_get(m->homes_by_sysfs, sysfs);
                if (h)
                        manager_revalidate_image(m, h);
                else
                        manager_enqueue_gc(m, NULL);
        } else
                (void) manager_add_device(m, d);

        (void) bus_manager_emit_auto_login_changed(m);
        return 0;
}

static int manager_watch_devices(Manager *m) {
        int r;

        assert(m);
        assert(!m->device_monitor);

        r = sd_device_monitor_new(&m->device_monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate device monitor: %m");

        r = sd_device_monitor_filter_add_match_subsystem_devtype(m->device_monitor, "block", NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to configure device monitor match: %m");

        r = sd_device_monitor_attach_event(m->device_monitor, m->event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach device monitor to event loop: %m");

        r = sd_device_monitor_start(m->device_monitor, manager_on_device, m);
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        return 0;
}

static int manager_enumerate_devices(Manager *m) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *d;
        int r;

        assert(m);

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "block", true);
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d)
                (void) manager_add_device(m, d);

        return 0;
}

static int manager_load_key_pair(Manager *m) {
        _cleanup_(fclosep) FILE *f = NULL;
        struct stat st;
        int r;

        assert(m);

        if (m->private_key) {
                EVP_PKEY_free(m->private_key);
                m->private_key = NULL;
        }

        r = search_and_fopen_nulstr("local.private", "re", NULL, KEY_PATHS_NULSTR, &f);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to read private key file: %m");

        if (fstat(fileno(f), &st) < 0)
                return log_error_errno(errno, "Failed to stat private key file: %m");

        r = stat_verify_regular(&st);
        if (r < 0)
                return log_error_errno(r, "Private key file is not regular: %m");

        if (st.st_uid != 0 || (st.st_mode & 0077) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Private key file is readable by more than the root user");

        m->private_key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        if (!m->private_key)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to load private key pair");

        log_info("Successfully loaded private key pair.");

        return 1;
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_PKEY_CTX*, EVP_PKEY_CTX_free, NULL);

static int manager_generate_key_pair(Manager *m) {
        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = NULL;
        _cleanup_(unlink_and_freep) char *temp_public = NULL, *temp_private = NULL;
        _cleanup_fclose_ FILE *fpublic = NULL, *fprivate = NULL;
        int r;

        if (m->private_key) {
                EVP_PKEY_free(m->private_key);
                m->private_key = NULL;
        }

        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
        if (!ctx)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to allocate Ed25519 key generation context.");

        if (EVP_PKEY_keygen_init(ctx) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to initialize Ed25519 key generation context.");

        log_info("Generating key pair for signing local user identity records.");

        if (EVP_PKEY_keygen(ctx, &m->private_key) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to generate Ed25519 key pair");

        log_info("Successfully created Ed25519 key pair.");

        (void) mkdir_p("/var/lib/systemd/home", 0755);

        /* Write out public key (note that we only do that as a help to the user, we don't make use of this ever */
        r = fopen_temporary("/var/lib/systemd/home/local.public", &fpublic, &temp_public);
        if (r < 0)
                return log_error_errno(errno, "Failed to open key file for writing: %m");

        if (PEM_write_PUBKEY(fpublic, m->private_key) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write public key.");

        r = fflush_sync_and_check(fpublic);
        if (r < 0)
                return log_error_errno(r, "Failed to write private key: %m");

        fpublic = safe_fclose(fpublic);

        /* Write out the private key (this actually writes out both private and public, OpenSSL is confusing) */
        r = fopen_temporary("/var/lib/systemd/home/local.private", &fprivate, &temp_private);
        if (r < 0)
                return log_error_errno(errno, "Failed to open key file for writing: %m");

        if (PEM_write_PrivateKey(fprivate, m->private_key, NULL, NULL, 0, NULL, 0) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write private key pair.");

        r = fflush_sync_and_check(fprivate);
        if (r < 0)
                return log_error_errno(r, "Failed to write private key: %m");

        fprivate = safe_fclose(fprivate);

        /* Both are written now, move them into place */

        if (rename(temp_public, "/var/lib/systemd/home/local.public") < 0)
                return log_error_errno(errno, "Failed to move public key file into place: %m");
        temp_public = mfree(temp_public);

        if (rename(temp_private, "/var/lib/systemd/home/local.private") < 0) {
                (void) unlink_noerrno("/var/lib/systemd/home/local.public"); /* try to remove the file we already created */
                return log_error_errno(errno, "Failed to move private key file into place: %m");
        }
        temp_private = mfree(temp_private);

        r = fsync_path_at(AT_FDCWD, "/var/lib/systemd/home/");
        if (r < 0)
                log_warning_errno(r, "Failed to sync /var/lib/systemd/home/, ignoring: %m");

        return 1;
}

int manager_acquire_key_pair(Manager *m) {
        int r;

        assert(m);

        /* Already there? */
        if (m->private_key)
                return 1;

        /* First try to load key off disk */
        r = manager_load_key_pair(m);
        if (r != 0)
                return r;

        /* Didn't work, generate a new one */
        return manager_generate_key_pair(m);
}

int manager_sign_user_record(Manager *m, UserRecord *u, UserRecord **ret, sd_bus_error *error) {
        int r;

        assert(m);
        assert(u);
        assert(ret);

        r = manager_acquire_key_pair(m);
        if (r < 0)
                return r;
        if (r == 0)
                return sd_bus_error_setf(error, BUS_ERROR_NO_PRIVATE_KEY, "Can't sign without local key.");

        return user_record_sign(u, m->private_key, ret);
}

DEFINE_PRIVATE_HASH_OPS_FULL(public_key_hash_ops, char, string_hash_func, string_compare_func, free, EVP_PKEY, EVP_PKEY_free);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(EVP_PKEY*, EVP_PKEY_free, NULL);

static int manager_load_public_key_one(Manager *m, const char *path) {
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *fn = NULL;
        struct stat st;
        int r;

        assert(m);

        if (streq(basename(path), "local.public")) /* we already loaded the private key, which includes the public one */
                return 0;

        f = fopen(path, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open public key %s: %m", path);
        }

        if (fstat(fileno(f), &st) < 0)
                return log_error_errno(errno, "Failed to stat public key %s: %m", path);

        r = stat_verify_regular(&st);
        if (r < 0)
                return log_error_errno(r, "Public key file %s is not a regular file: %m", path);

        if (st.st_uid != 0 || (st.st_mode & 0022) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Public key file %s is writable by more than the root user, refusing.", path);

        r = hashmap_ensure_allocated(&m->public_keys, &public_key_hash_ops);
        if (r < 0)
                return log_oom();

        pkey = PEM_read_PUBKEY(f, &pkey, NULL, NULL);
        if (!pkey)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to parse public key file %s.", path);

        fn = strdup(basename(path));
        if (!fn)
                return log_oom();

        r = hashmap_put(m->public_keys, fn, pkey);
        if (r < 0)
                return log_error_errno(r, "Failed to add public key to set: %m");

        TAKE_PTR(fn);
        TAKE_PTR(pkey);

        return 0;
}

static int manager_load_public_keys(Manager *m) {
        _cleanup_strv_free_ char **files = NULL;
        char **i;
        int r;

        assert(m);

        m->public_keys = hashmap_free(m->public_keys);

        r = conf_files_list_nulstr(
                        &files,
                        ".public",
                        NULL,
                        CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED,
                        KEY_PATHS_NULSTR);
        if (r < 0)
                return log_error_errno(r, "Failed to assemble list of public key directories: %m");

        STRV_FOREACH(i, files)
                (void) manager_load_public_key_one(m, *i);

        return 0;
}

int manager_startup(Manager *m) {
        int r;

        assert(m);

        r = manager_listen_notify(m);
        if (r < 0)
                return r;

        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        r = manager_bind_varlink(m);
        if (r < 0)
                return r;

        r = manager_load_key_pair(m); /* only try to load it, don't generate any */
        if (r < 0)
                return r;

        r = manager_load_public_keys(m);
        if (r < 0)
                return r;

        manager_watch_home(m);
        (void) manager_watch_devices(m);

        (void) manager_enumerate_records(m);
        (void) manager_enumerate_images(m);
        (void) manager_enumerate_devices(m);

        /* Let's clean up home directories whose devices got removed while we were not running */
        (void) manager_enqueue_gc(m, NULL);

        return 0;
}

void manager_revalidate_image(Manager *m, Home *h) {
        int r;

        assert(m);
        assert(h);

        /* Frees an automatically discovered image, if it's synthetic and its image disappeared. Unmounts any
         * image if it's mounted but it's image vanished. */

        if (h->current_operation || !ordered_set_isempty(h->pending_operations))
                return;

        if (h->state == HOME_UNFIXATED) {
                r = user_record_test_image_path(h->record);
                if (r < 0)
                        log_warning_errno(r, "Can't determine if image of %s exists, freeing unfixated user: %m", h->user_name);
                else if (r == USER_TEST_ABSENT)
                        log_info("Image for %s disappeared, freeing unfixated user.", h->user_name);
                else
                        return;

                home_free(h);

        } else if (h->state < 0) {

                r = user_record_test_home_directory(h->record);
                if (r < 0) {
                        log_warning_errno(r, "Unable to determine state of home directory, ignoring: %m");
                        return;
                }

                if (r == USER_TEST_MOUNTED) {
                        r = user_record_test_image_path(h->record);
                        if (r < 0) {
                                log_warning_errno(r, "Unable to determine state of image path, ignoring: %m");
                                return;
                        }

                        if (r == USER_TEST_ABSENT) {
                                _cleanup_(operation_unrefp) Operation *o = NULL;

                                log_notice("Backing image disappeared while home directory %s was mounted, unmounting it forcibly.", h->user_name);
                                /* Wowza, the thing is mounted, but the device is gone? Act on it. */

                                r = home_killall(h);
                                if (r < 0)
                                        log_warning_errno(r, "Failed to kill processes of user %s, ignoring: %m", h->user_name);

                                /* We enqueue the operation here, after all the home directory might
                                 * currently already run some operation, and we can deactivate it only after
                                 * that's complete. */
                                o = operation_new(OPERATION_DEACTIVATE_FORCE, NULL);
                                if (!o) {
                                        log_oom();
                                        return;
                                }

                                r = home_schedule_operation(h, o, NULL);
                                if (r < 0)
                                        log_warning_errno(r, "Failed to enqueue forced home directory %s deactivation, ignoring: %m", h->user_name);
                        }
                }
        }
}

int manager_gc_images(Manager *m) {
        Home *h;

        assert_se(m);

        if (m->gc_focus) {
                /* Focus on a specific home */

                h = TAKE_PTR(m->gc_focus);
                manager_revalidate_image(m, h);
        } else {
                /* Gc all */

                HASHMAP_FOREACH(h, m->homes_by_name)
                        manager_revalidate_image(m, h);
        }

        return 0;
}

static int on_deferred_rescan(sd_event_source *s, void *userdata) {
        Manager *m = userdata;

        assert(m);

        m->deferred_rescan_event_source = sd_event_source_disable_unref(m->deferred_rescan_event_source);

        manager_enumerate_devices(m);
        manager_enumerate_images(m);
        return 0;
}

int manager_enqueue_rescan(Manager *m) {
        int r;

        assert(m);

        if (m->deferred_rescan_event_source)
                return 0;

        if (!m->event)
                return 0;

        if (IN_SET(sd_event_get_state(m->event), SD_EVENT_FINISHED, SD_EVENT_EXITING))
                return 0;

        r = sd_event_add_defer(m->event, &m->deferred_rescan_event_source, on_deferred_rescan, m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate rescan event source: %m");

        r = sd_event_source_set_priority(m->deferred_rescan_event_source, SD_EVENT_PRIORITY_IDLE+1);
        if (r < 0)
                log_warning_errno(r, "Failed to tweak priority of event source, ignoring: %m");

        (void) sd_event_source_set_description(m->deferred_rescan_event_source, "deferred-rescan");
        return 1;
}

static int on_deferred_gc(sd_event_source *s, void *userdata) {
        Manager *m = userdata;

        assert(m);

        m->deferred_gc_event_source = sd_event_source_disable_unref(m->deferred_gc_event_source);

        manager_gc_images(m);
        return 0;
}

int manager_enqueue_gc(Manager *m, Home *focus) {
        int r;

        assert(m);

        /* This enqueues a request to GC dead homes. It may be called with focus=NULL in which case all homes
         * will be scanned, or with the parameter set, in which case only that home is checked. */

        if (!m->event)
                return 0;

        if (IN_SET(sd_event_get_state(m->event), SD_EVENT_FINISHED, SD_EVENT_EXITING))
                return 0;

        /* If a focus home is specified, then remember to focus just on this home. Otherwise invalidate any
         * focus that might be set to look at all homes. */

        if (m->deferred_gc_event_source) {
                if (m->gc_focus != focus) /* not the same focus, then look at everything */
                        m->gc_focus = NULL;

                return 0;
        } else
                m->gc_focus = focus; /* start focused */

        r = sd_event_add_defer(m->event, &m->deferred_gc_event_source, on_deferred_gc, m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate GC event source: %m");

        r = sd_event_source_set_priority(m->deferred_gc_event_source, SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                log_warning_errno(r, "Failed to tweak priority of event source, ignoring: %m");

        (void) sd_event_source_set_description(m->deferred_gc_event_source, "deferred-gc");
        return 1;
}
