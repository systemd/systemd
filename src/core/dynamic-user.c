/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "clean-ipc.h"
#include "dynamic-user.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "iovec-util.h"
#include "lock-util.h"
#include "parse-util.h"
#include "random-util.h"
#include "serialize.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "uid-classification.h"
#include "user-util.h"

/* Takes a value generated randomly or by hashing and turns it into a UID in the right range */
#define UID_CLAMP_INTO_RANGE(rnd) (((uid_t) (rnd) % (DYNAMIC_UID_MAX - DYNAMIC_UID_MIN + 1)) + DYNAMIC_UID_MIN)

DEFINE_TRIVIAL_REF_FUNC(DynamicUser, dynamic_user);

DynamicUser* dynamic_user_free(DynamicUser *d) {
        if (!d)
                return NULL;

        if (d->manager)
                (void) hashmap_remove(d->manager->dynamic_users, d->name);

        safe_close_pair(d->storage_socket);
        return mfree(d);
}

static int dynamic_user_add(Manager *m, const char *name, int storage_socket[static 2], DynamicUser **ret) {
        DynamicUser *d;
        int r;

        assert(m || ret);
        assert(name);
        assert(storage_socket);

        if (m) { /* Might be called in sd-executor with no manager object */
                r = hashmap_ensure_allocated(&m->dynamic_users, &string_hash_ops);
                if (r < 0)
                        return r;
        }

        d = malloc0(offsetof(DynamicUser, name) + strlen(name) + 1);
        if (!d)
                return -ENOMEM;

        strcpy(d->name, name);

        d->storage_socket[0] = storage_socket[0];
        d->storage_socket[1] = storage_socket[1];

        if (m) { /* Might be called in sd-executor with no manager object */
                r = hashmap_put(m->dynamic_users, d->name, d);
                if (r < 0) {
                        free(d);
                        return r;
                }
        }

        d->manager = m;

        if (ret)
                *ret = d;

        return 0;
}

static int dynamic_user_acquire(Manager *m, const char *name, DynamicUser** ret) {
        _cleanup_close_pair_ int storage_socket[2] = EBADF_PAIR;
        DynamicUser *d;
        int r;

        assert(m);
        assert(name);

        /* Return the DynamicUser structure for a specific user name. Note that this won't actually allocate a UID for
         * it, but just prepare the data structure for it. The UID is allocated only on demand, when it's really
         * needed, and in the child process we fork off, since allocation involves NSS checks which are not OK to do
         * from PID 1. To allow the children and PID 1 share information about allocated UIDs we use an anonymous
         * AF_UNIX/SOCK_DGRAM socket (called the "storage socket") that contains at most one datagram with the
         * allocated UID number, plus an fd referencing the lock file for the UID
         * (i.e. /run/systemd/dynamic-uid/$UID). Why involve the socket pair? So that PID 1 and all its children can
         * share the same storage for the UID and lock fd, simply by inheriting the storage socket fds. The socket pair
         * may exist in three different states:
         *
         * a) no datagram stored. This is the initial state. In this case the dynamic user was never realized.
         *
         * b) a datagram containing a UID stored, but no lock fd attached to it. In this case there was already a
         *    statically assigned UID by the same name, which we are reusing.
         *
         * c) a datagram containing a UID stored, and a lock fd is attached to it. In this case we allocated a dynamic
         *    UID and locked it in the file system, using the lock fd.
         *
         * As PID 1 and various children might access the socket pair simultaneously, and pop the datagram or push it
         * back in any time, we also maintain a lock on the socket pair. Note one peculiarity regarding locking here:
         * the UID lock on disk is protected via a BSD file lock (i.e. an fd-bound lock), so that the lock is kept in
         * place as long as there's a reference to the fd open. The lock on the storage socket pair however is a POSIX
         * file lock (i.e. a process-bound lock), as all users share the same fd of this (after all it is anonymous,
         * nobody else could get any access to it except via our own fd) and we want to synchronize access between all
         * processes that have access to it. */

        d = hashmap_get(m->dynamic_users, name);
        if (d) {
                if (ret) {
                        /* We already have a structure for the dynamic user, let's increase the ref count and reuse it */
                        d->n_ref++;
                        *ret = d;
                }
                return 0;
        }

        if (!valid_user_group_name(name, VALID_USER_ALLOW_NUMERIC))
                return -EINVAL;

        if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, storage_socket) < 0)
                return -errno;

        r = dynamic_user_add(m, name, storage_socket, &d);
        if (r < 0)
                return r;

        storage_socket[0] = storage_socket[1] = -EBADF;

        if (ret) {
                d->n_ref++;
                *ret = d;
        }

        return 1;
}

static int make_uid_symlinks(uid_t uid, const char *name, bool b) {
        char path1[STRLEN("/run/systemd/dynamic-uid/direct:") + DECIMAL_STR_MAX(uid_t) + 1];
        const char *path2;
        int r = 0, k;

        /* Add direct additional symlinks for direct lookups of dynamic UIDs and their names by userspace code. The
         * only reason we have this is because dbus-daemon cannot use D-Bus for resolving users and groups (since it
         * would be its own client then). We hence keep these world-readable symlinks in place, so that the
         * unprivileged dbus user can read the mappings when it needs them via these symlinks instead of having to go
         * via the bus. Ideally, we'd use the lock files we keep for this anyway, but we can't since we use BSD locks
         * on them and as those may be taken by any user with read access we can't make them world-readable. */

        xsprintf(path1, "/run/systemd/dynamic-uid/direct:" UID_FMT, uid);
        if (unlink(path1) < 0 && errno != ENOENT)
                r = -errno;

        if (b && symlink(name, path1) < 0) {
                k = log_warning_errno(errno, "Failed to symlink \"%s\": %m", path1);
                if (r == 0)
                        r = k;
        }

        path2 = strjoina("/run/systemd/dynamic-uid/direct:", name);
        if (unlink(path2) < 0 && errno != ENOENT) {
                k = -errno;
                if (r == 0)
                        r = k;
        }

        if (b && symlink(path1 + STRLEN("/run/systemd/dynamic-uid/direct:"), path2) < 0) {
                k = log_warning_errno(errno,  "Failed to symlink \"%s\": %m", path2);
                if (r == 0)
                        r = k;
        }

        return r;
}

static int pick_uid(char **suggested_paths, const char *name, uid_t *ret_uid) {

        /* Find a suitable free UID. We use the following strategy to find a suitable UID:
         *
         * 1. Initially, we try to read the UID of a number of specified paths. If any of these UIDs works, we use
         *    them. We use in order to increase the chance of UID reuse, if StateDirectory=, CacheDirectory= or
         *    LogsDirectory= are used, as reusing the UID these directories are owned by saves us from having to
         *    recursively chown() them to new users.
         *
         * 2. If that didn't yield a currently unused UID, we hash the user name, and try to use that. This should be
         *    pretty good, as the use ris by default derived from the unit name, and hence the same service and same
         *    user should usually get the same UID as long as our hashing doesn't clash.
         *
         * 3. Finally, if that didn't work, we randomly pick UIDs, until we find one that is empty.
         *
         * Since the dynamic UID space is relatively small we'll stop trying after 100 iterations, giving up. */

        enum {
                PHASE_SUGGESTED,  /* the first phase, reusing directory ownership UIDs */
                PHASE_HASHED,     /* the second phase, deriving a UID from the username by hashing */
                PHASE_RANDOM,     /* the last phase, randomly picking UIDs */
        } phase = PHASE_SUGGESTED;

        static const uint8_t hash_key[] = {
                0x37, 0x53, 0x7e, 0x31, 0xcf, 0xce, 0x48, 0xf5,
                0x8a, 0xbb, 0x39, 0x57, 0x8d, 0xd9, 0xec, 0x59
        };

        unsigned n_tries = 100, current_suggested = 0;
        int r;

        (void) mkdir("/run/systemd/dynamic-uid", 0755);

        for (;;) {
                char lock_path[STRLEN("/run/systemd/dynamic-uid/") + DECIMAL_STR_MAX(uid_t) + 1];
                _cleanup_close_ int lock_fd = -EBADF;
                uid_t candidate;
                ssize_t l;

                if (--n_tries <= 0) /* Give up retrying eventually */
                        return -EBUSY;

                switch (phase) {

                case PHASE_SUGGESTED: {
                        struct stat st;

                        if (!suggested_paths || !suggested_paths[current_suggested]) {
                                /* We reached the end of the suggested paths list, let's try by hashing the name */
                                phase = PHASE_HASHED;
                                continue;
                        }

                        if (stat(suggested_paths[current_suggested++], &st) < 0)
                                continue; /* We can't read the UID of this path, but that doesn't matter, just try the next */

                        candidate = st.st_uid;
                        break;
                }

                case PHASE_HASHED:
                        /* A static user by this name does not exist yet. Let's find a free ID then, and use that. We
                         * start with a UID generated as hash from the user name. */
                        candidate = UID_CLAMP_INTO_RANGE(siphash24(name, strlen(name), hash_key));

                        /* If this one fails, we should proceed with random tries */
                        phase = PHASE_RANDOM;
                        break;

                case PHASE_RANDOM:

                        /* Pick another random UID, and see if that works for us. */
                        random_bytes(&candidate, sizeof(candidate));
                        candidate = UID_CLAMP_INTO_RANGE(candidate);
                        break;

                default:
                        assert_not_reached();
                }

                /* Make sure whatever we picked here actually is in the right range */
                if (!uid_is_dynamic(candidate))
                        continue;

                xsprintf(lock_path, "/run/systemd/dynamic-uid/" UID_FMT, candidate);

                for (;;) {
                        struct stat st;

                        lock_fd = open(lock_path, O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC|O_NOCTTY, 0600);
                        if (lock_fd < 0)
                                return -errno;

                        r = flock(lock_fd, LOCK_EX|LOCK_NB); /* Try to get a BSD file lock on the UID lock file */
                        if (r < 0) {
                                if (IN_SET(errno, EBUSY, EAGAIN))
                                        goto next; /* already in use */

                                return -errno;
                        }

                        if (fstat(lock_fd, &st) < 0)
                                return -errno;
                        if (st.st_nlink > 0)
                                break;

                        /* Oh, bummer, we got the lock, but the file was unlinked between the time we opened it and
                         * got the lock. Close it, and try again. */
                        lock_fd = safe_close(lock_fd);
                }

                /* Some superficial check whether this UID/GID might already be taken by some static user */
                if (getpwuid_malloc(candidate, /* ret= */ NULL) >= 0 ||
                    getgrgid_malloc((gid_t) candidate, /* ret= */ NULL) >= 0 ||
                    search_ipc(candidate, (gid_t) candidate) != 0) {
                        (void) unlink(lock_path);
                        continue;
                }

                /* Let's store the user name in the lock file, so that we can use it for looking up the username for a UID */
                l = pwritev(lock_fd,
                            (struct iovec[2]) {
                                    IOVEC_MAKE_STRING(name),
                                    IOVEC_MAKE((char[1]) { '\n' }, 1),
                            }, 2, 0);
                if (l < 0) {
                        r = -errno;
                        (void) unlink(lock_path);
                        return r;
                }

                (void) ftruncate(lock_fd, l);
                (void) make_uid_symlinks(candidate, name, true); /* also add direct lookup symlinks */

                *ret_uid = candidate;
                return TAKE_FD(lock_fd);

        next:
                ;
        }
}

static int dynamic_user_pop(DynamicUser *d, uid_t *ret_uid, int *ret_lock_fd) {
        uid_t uid = UID_INVALID;
        struct iovec iov = IOVEC_MAKE(&uid, sizeof(uid));
        int lock_fd;
        ssize_t k;

        assert(d);
        assert(ret_uid);
        assert(ret_lock_fd);

        /* Read the UID and lock fd that is stored in the storage AF_UNIX socket. This should be called with
         * the lock on the socket taken. */

        k = receive_one_fd_iov(d->storage_socket[0], &iov, 1, MSG_DONTWAIT, &lock_fd);
        if (k < 0) {
                assert(errno_is_valid(-k));
                return (int) k;
        }

        *ret_uid = uid;
        *ret_lock_fd = lock_fd;

        return 0;
}

static int dynamic_user_push(DynamicUser *d, uid_t uid, int lock_fd) {
        struct iovec iov = IOVEC_MAKE(&uid, sizeof(uid));

        assert(d);

        /* Store the UID and lock_fd in the storage socket. This should be called with the socket pair lock taken. */
        return send_one_fd_iov(d->storage_socket[1], lock_fd, &iov, 1, MSG_DONTWAIT);
}

static void unlink_uid_lock(int lock_fd, uid_t uid, const char *name) {
        char lock_path[STRLEN("/run/systemd/dynamic-uid/") + DECIMAL_STR_MAX(uid_t) + 1];

        if (lock_fd < 0)
                return;

        xsprintf(lock_path, "/run/systemd/dynamic-uid/" UID_FMT, uid);
        (void) unlink(lock_path);

        (void) make_uid_symlinks(uid, name, false); /* remove direct lookup symlinks */
}

static int dynamic_user_realize(
                DynamicUser *d,
                char **suggested_dirs,
                uid_t *ret_uid, gid_t *ret_gid,
                bool is_user) {

        _cleanup_close_ int uid_lock_fd = -EBADF;
        _cleanup_close_ int etc_passwd_lock_fd = -EBADF;
        uid_t num = UID_INVALID; /* a uid if is_user, and a gid otherwise */
        gid_t gid = GID_INVALID; /* a gid if is_user, ignored otherwise */
        int r;

        assert(d);
        assert(is_user == !!ret_uid);
        assert(ret_gid);

        /* Acquire a UID for the user name. This will allocate a UID for the user name if the user doesn't exist
         * yet. If it already exists its existing UID/GID will be reused. */

        r = posix_lock(d->storage_socket[0], LOCK_EX);
        if (r < 0)
                return r;

        CLEANUP_POSIX_UNLOCK(d->storage_socket[0]);

        r = dynamic_user_pop(d, &num, &uid_lock_fd);
        if (r < 0) {
                int new_uid_lock_fd;
                uid_t new_uid;

                if (r != -EAGAIN)
                        return r;

                /* OK, nothing stored yet, let's try to find something useful. While we are working on this release the
                 * lock however, so that nobody else blocks on our NSS lookups. */
                r = posix_lock(d->storage_socket[0], LOCK_UN);
                if (r < 0)
                        return r;

                /* Let's see if a proper, static user or group by this name exists. Try to take the lock on
                 * /etc/passwd, if that fails with EROFS then /etc is read-only. In that case it's fine if we don't
                 * take the lock, given that users can't be added there anyway in this case. */
                r = etc_passwd_lock_fd = take_etc_passwd_lock(NULL);
                if (r < 0 && r != -EROFS)
                        return r;

                /* First, let's parse this as numeric UID */
                r = parse_uid(d->name, &num);
                if (r < 0) {
                        _cleanup_free_ struct passwd *p = NULL;
                        _cleanup_free_ struct group *g = NULL;

                        if (is_user) {
                                /* OK, this is not a numeric UID. Let's see if there's a user by this name */
                                if (getpwnam_malloc(d->name, &p) >= 0) {
                                        num = p->pw_uid;
                                        gid = p->pw_gid;
                                } else {
                                        /* if the user does not exist but the group with the same name exists, refuse operation */
                                        if (getgrnam_malloc(d->name, /* ret= */ NULL) >= 0)
                                                return -EILSEQ;
                                }
                        } else {
                                /* Let's see if there's a group by this name */
                                if (getgrnam_malloc(d->name, &g) >= 0)
                                        num = (uid_t) g->gr_gid;
                                else {
                                        /* if the group does not exist but the user with the same name exists, refuse operation */
                                        if (getpwnam_malloc(d->name, /* ret= */ NULL) >= 0)
                                                return -EILSEQ;
                                }
                        }
                }

                if (num == UID_INVALID) {
                        /* No static UID assigned yet, excellent. Let's pick a new dynamic one, and lock it. */

                        uid_lock_fd = pick_uid(suggested_dirs, d->name, &num);
                        if (uid_lock_fd < 0)
                                return uid_lock_fd;
                }

                /* So, we found a working UID/lock combination. Let's see if we actually still need it. */
                r = posix_lock(d->storage_socket[0], LOCK_EX);
                if (r < 0) {
                        unlink_uid_lock(uid_lock_fd, num, d->name);
                        return r;
                }

                r = dynamic_user_pop(d, &new_uid, &new_uid_lock_fd);
                if (r < 0) {
                        if (r != -EAGAIN) {
                                /* OK, something bad happened, let's get rid of the bits we acquired. */
                                unlink_uid_lock(uid_lock_fd, num, d->name);
                                return r;
                        }
                } else {
                        /* Hmm, so as it appears there's now something stored in the storage socket.
                         * Throw away what we acquired, and use what's stored now. */

                        unlink_uid_lock(uid_lock_fd, num, d->name);
                        safe_close(uid_lock_fd);

                        num = new_uid;
                        uid_lock_fd = new_uid_lock_fd;
                }
        } else if (is_user && !uid_is_dynamic(num)) {
                _cleanup_free_ struct passwd *p = NULL;

                /* Statically allocated user may have different uid and gid. So, let's obtain the gid. */
                r = getpwuid_malloc(num, &p);
                if (r < 0)
                        return r;

                gid = p->pw_gid;
        }

        /* If the UID/GID was already allocated dynamically, push the data we popped out back in. If it was already
         * allocated statically, push the UID back too, but do not push the lock fd in. If we allocated the UID
         * dynamically right here, push that in along with the lock fd for it. */
        r = dynamic_user_push(d, num, uid_lock_fd);
        if (r < 0)
                return r;

        if (is_user) {
                *ret_uid = num;
                *ret_gid = gid != GID_INVALID ? gid : num;
        } else
                *ret_gid = num;

        return 0;
}

int dynamic_user_current(DynamicUser *d, uid_t *ret) {
        _cleanup_close_ int lock_fd = -EBADF;
        uid_t uid;
        int r;

        assert(d);

        /* Get the currently assigned UID for the user, if there's any. This simply pops the data from the
         * storage socket, and pushes it back in right-away. */

        r = posix_lock(d->storage_socket[0], LOCK_EX);
        if (r < 0)
                return r;

        CLEANUP_POSIX_UNLOCK(d->storage_socket[0]);

        r = dynamic_user_pop(d, &uid, &lock_fd);
        if (r < 0)
                return r;

        r = dynamic_user_push(d, uid, lock_fd);
        if (r < 0)
                return r;

        if (ret)
                *ret = uid;

        return 0;
}

static DynamicUser* dynamic_user_unref(DynamicUser *d) {
        if (!d)
                return NULL;

        /* Note that this doesn't actually release any resources itself. If a dynamic user should be fully
         * destroyed and its UID released, use dynamic_user_destroy() instead. NB: the dynamic user table may
         * contain entries with no references, which is commonly the case right before a daemon reload. */

        assert(d->n_ref > 0);
        d->n_ref--;

        return NULL;
}

static int dynamic_user_close(DynamicUser *d) {
        _cleanup_close_ int lock_fd = -EBADF;
        uid_t uid;
        int r;

        /* Release the user ID, by releasing the lock on it, and emptying the storage socket. After this the
         * user is unrealized again, much like it was after it the DynamicUser object was first allocated. */

        r = posix_lock(d->storage_socket[0], LOCK_EX);
        if (r < 0)
                return r;

        CLEANUP_POSIX_UNLOCK(d->storage_socket[0]);

        r = dynamic_user_pop(d, &uid, &lock_fd);
        if (r == -EAGAIN)
                /* User wasn't realized yet, nothing to do. */
                return 0;
        if (r < 0)
                return r;

        /* This dynamic user was realized and dynamically allocated. In this case, let's remove the lock file. */
        unlink_uid_lock(lock_fd, uid, d->name);

        return 1;
}

static DynamicUser* dynamic_user_destroy(DynamicUser *d) {
        if (!d)
                return NULL;

        /* Drop a reference to a DynamicUser object, and destroy the user completely if this was the last
         * reference. This is called whenever a service is shut down and wants its dynamic UID gone. Note that
         * dynamic_user_unref() is what is called whenever a service is simply freed, for example during a reload
         * cycle, where the dynamic users should not be destroyed, but our datastructures should. */

        dynamic_user_unref(d);

        if (d->n_ref > 0)
                return NULL;

        (void) dynamic_user_close(d);
        return dynamic_user_free(d);
}

int dynamic_user_serialize_one(DynamicUser *d, const char *key, FILE *f, FDSet *fds) {
        int copy0, copy1;

        assert(key);
        assert(f);
        assert(fds);

        if (!d)
                return 0;

        if (d->storage_socket[0] < 0 || d->storage_socket[1] < 0)
                return 0;

        copy0 = fdset_put_dup(fds, d->storage_socket[0]);
        if (copy0 < 0)
                return log_error_errno(copy0, "Failed to add dynamic user storage fd to serialization: %m");

        copy1 = fdset_put_dup(fds, d->storage_socket[1]);
        if (copy1 < 0)
                return log_error_errno(copy1, "Failed to add dynamic user storage fd to serialization: %m");

        (void) serialize_item_format(f, key, "%s %i %i", d->name, copy0, copy1);

        return 0;
}

int dynamic_user_serialize(Manager *m, FILE *f, FDSet *fds) {
        DynamicUser *d;

        assert(m);

        /* Dump the dynamic user database into the manager serialization, to deal with daemon reloads. */

        HASHMAP_FOREACH(d, m->dynamic_users)
                (void) dynamic_user_serialize_one(d, "dynamic-user", f, fds);

        return 0;
}

void dynamic_user_deserialize_one(Manager *m, const char *value, FDSet *fds, DynamicUser **ret) {
        _cleanup_free_ char *name = NULL, *s0 = NULL, *s1 = NULL;
        _cleanup_close_ int fd0 = -EBADF, fd1 = -EBADF;
        int r;

        assert(value);
        assert(fds);

        /* Parse the serialization again, after a daemon reload */

        r = extract_many_words(&value, NULL, 0, &name, &s0, &s1);
        if (r != 3 || !isempty(value)) {
                log_debug("Unable to parse dynamic user line.");
                return;
        }

        fd0 = deserialize_fd(fds, s0);
        if (fd0 < 0)
                return;

        fd1 = deserialize_fd(fds, s1);
        if (fd1 < 0)
                return;

        r = dynamic_user_add(m, name, (int[]) { fd0, fd1 }, ret);
        if (r < 0) {
                log_debug_errno(r, "Failed to add dynamic user: %m");
                return;
        }

        TAKE_FD(fd0);
        TAKE_FD(fd1);

        if (ret) /* If the caller uses it directly, increment the refcount */
                (*ret)->n_ref++;
}

void dynamic_user_vacuum(Manager *m, bool close_user) {
        DynamicUser *d;

        assert(m);

        /* Empty the dynamic user database, optionally cleaning up orphaned dynamic users, i.e. destroy and free users
         * to which no reference exist. This is called after a daemon reload finished, in order to destroy users which
         * might not be referenced anymore. */

        HASHMAP_FOREACH(d, m->dynamic_users) {
                if (d->n_ref > 0)
                        continue;

                if (close_user) {
                        log_debug("Removing orphaned dynamic user %s", d->name);
                        (void) dynamic_user_close(d);
                }

                dynamic_user_free(d);
        }
}

int dynamic_user_lookup_uid(Manager *m, uid_t uid, char **ret) {
        char lock_path[STRLEN("/run/systemd/dynamic-uid/") + DECIMAL_STR_MAX(uid_t) + 1];
        _cleanup_free_ char *user = NULL;
        uid_t check_uid;
        int r;

        assert(m);
        assert(ret);

        /* A friendly way to translate a dynamic user's UID into a name. */
        if (!uid_is_dynamic(uid))
                return -ESRCH;

        xsprintf(lock_path, "/run/systemd/dynamic-uid/" UID_FMT, uid);
        r = read_one_line_file(lock_path, &user);
        if (IN_SET(r, -ENOENT, 0))
                return -ESRCH;
        if (r < 0)
                return r;

        /* The lock file might be stale, hence let's verify the data before we return it */
        r = dynamic_user_lookup_name(m, user, &check_uid);
        if (r < 0)
                return r;
        if (check_uid != uid) /* lock file doesn't match our own idea */
                return -ESRCH;

        *ret = TAKE_PTR(user);

        return 0;
}

int dynamic_user_lookup_name(Manager *m, const char *name, uid_t *ret) {
        DynamicUser *d;
        int r;

        assert(m);
        assert(name);

        /* A friendly call for translating a dynamic user's name into its UID */

        d = hashmap_get(m->dynamic_users, name);
        if (!d)
                return -ESRCH;

        r = dynamic_user_current(d, ret);
        if (r == -EAGAIN) /* not realized yet? */
                return -ESRCH;

        return r;
}

int dynamic_creds_make(Manager *m, const char *user, const char *group, DynamicCreds **ret) {
        _cleanup_(dynamic_creds_unrefp) DynamicCreds *creds = NULL;
        int r;

        assert(m);
        assert(ret);

        if (!user && !group) {
                *ret = NULL;
                return 0;
        }

        creds = new0(DynamicCreds, 1);
        if (!creds)
                return -ENOMEM;

        /* A DynamicUser object encapsulates an allocation of both a UID and a GID for a specific name. However, some
         * services use different user and groups. For cases like that there's DynamicCreds containing a pair of user
         * and group. This call allocates a pair. */

        if (user) {
                r = dynamic_user_acquire(m, user, &creds->user);
                if (r < 0)
                        return r;
        }

        if (group && !streq_ptr(user, group)) {
                r = dynamic_user_acquire(m, group, &creds->group);
                if (r < 0)
                        return r;
        } else
                creds->group = ASSERT_PTR(dynamic_user_ref(creds->user));

        *ret = TAKE_PTR(creds);

        return 0;
}

int dynamic_creds_realize(DynamicCreds *creds, char **suggested_paths, uid_t *uid, gid_t *gid) {
        uid_t u = UID_INVALID;
        gid_t g = GID_INVALID;
        int r;

        assert(creds);
        assert(uid);
        assert(gid);

        /* Realize both the referenced user and group */

        if (creds->user) {
                r = dynamic_user_realize(creds->user, suggested_paths, &u, &g, true);
                if (r < 0)
                        return r;
        }

        if (creds->group && creds->group != creds->user) {
                r = dynamic_user_realize(creds->group, suggested_paths, NULL, &g, false);
                if (r < 0)
                        return r;
        }

        *uid = u;
        *gid = g;
        return 0;
}

DynamicCreds* dynamic_creds_unref(DynamicCreds *creds) {
        if (!creds)
                return NULL;

        creds->user = dynamic_user_unref(creds->user);
        creds->group = dynamic_user_unref(creds->group);

        return mfree(creds);
}

DynamicCreds* dynamic_creds_destroy(DynamicCreds *creds) {
        if (!creds)
                return NULL;

        creds->user = dynamic_user_destroy(creds->user);
        creds->group = dynamic_user_destroy(creds->group);

        return mfree(creds);
}

void dynamic_creds_done(DynamicCreds *creds) {
        if (!creds)
                return;

        if (creds->group != creds->user)
                dynamic_user_free(creds->group);
        creds->group = creds->user = dynamic_user_free(creds->user);
}

void dynamic_creds_close(DynamicCreds *creds) {
        if (!creds)
                return;

        if (creds->user)
                safe_close_pair(creds->user->storage_socket);

        if (creds->group && creds->group != creds->user)
                safe_close_pair(creds->group->storage_socket);
}
