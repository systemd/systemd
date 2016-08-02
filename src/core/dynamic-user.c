/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <grp.h>
#include <pwd.h>
#include <sys/file.h>

#include "dynamic-user.h"
#include "fd-util.h"
#include "fs-util.h"
#include "parse-util.h"
#include "random-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "user-util.h"
#include "fileio.h"

/* Let's pick a UIDs within the 16bit range, so that we are compatible with containers using 16bit user namespacing. At
 * least on Fedora normal users are allocated until UID 60000, hence do not allocate from below this. Also stay away
 * from the upper end of the range as that is often used for overflow/nobody users. */
#define UID_PICK_MIN ((uid_t) UINT32_C(0x0000EF00))
#define UID_PICK_MAX ((uid_t) UINT32_C(0x0000FFEF))

/* Takes a value generated randomly or by hashing and turns it into a UID in the right range */
#define UID_CLAMP_INTO_RANGE(rnd) (((uid_t) (rnd) % (UID_PICK_MAX - UID_PICK_MIN + 1)) + UID_PICK_MIN)

static DynamicUser* dynamic_user_free(DynamicUser *d) {
        if (!d)
                return NULL;

        if (d->manager)
                (void) hashmap_remove(d->manager->dynamic_users, d->name);

        safe_close_pair(d->storage_socket);
        free(d);

        return NULL;
}

static int dynamic_user_add(Manager *m, const char *name, int storage_socket[2], DynamicUser **ret) {
        DynamicUser *d = NULL;
        int r;

        assert(m);
        assert(name);
        assert(storage_socket);

        r = hashmap_ensure_allocated(&m->dynamic_users, &string_hash_ops);
        if (r < 0)
                return r;

        d = malloc0(offsetof(DynamicUser, name) + strlen(name) + 1);
        if (!d)
                return -ENOMEM;

        strcpy(d->name, name);

        d->storage_socket[0] = storage_socket[0];
        d->storage_socket[1] = storage_socket[1];

        r = hashmap_put(m->dynamic_users, d->name, d);
        if (r < 0) {
                free(d);
                return r;
        }

        d->manager = m;

        if (ret)
                *ret = d;

        return 0;
}

int dynamic_user_acquire(Manager *m, const char *name, DynamicUser** ret) {
        _cleanup_close_pair_ int storage_socket[2] = { -1, -1 };
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
                /* We already have a structure for the dynamic user, let's increase the ref count and reuse it */
                d->n_ref++;
                *ret = d;
                return 0;
        }

        if (!valid_user_group_name_or_id(name))
                return -EINVAL;

        if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, storage_socket) < 0)
                return -errno;

        r = dynamic_user_add(m, name, storage_socket, &d);
        if (r < 0)
                return r;

        storage_socket[0] = storage_socket[1] = -1;

        if (ret) {
                d->n_ref++;
                *ret = d;
        }

        return 1;
}

static int make_uid_symlinks(uid_t uid, const char *name, bool b) {

        char path1[strlen("/run/systemd/dynamic-uid/direct:") + DECIMAL_STR_MAX(uid_t) + 1];
        const char *path2;
        int r = 0;

        /* Add direct additional symlinks for direct lookups of dynamic UIDs and their names by userspace code. The
         * only reason we have this is because dbus-daemon cannot use D-Bus for resolving users and groups (since it
         * would be its own client then). We hence keep these world-readable symlinks in place, so that the
         * unprivileged dbus user can read the mappings when it needs them via these symlinks instead of having to go
         * via the bus. Ideally, we'd use the lock files we keep for this anyway, but we can't since we use BSD locks
         * on them and as those may be taken by any user with read access we can't make them world-readable. */

        xsprintf(path1, "/run/systemd/dynamic-uid/direct:" UID_FMT, uid);
        if (unlink(path1) < 0) {
                if (errno != ENOENT)
                        r = -errno;
        }
        if (b) {
                if (symlink(name, path1) < 0)
                        r = -errno;
        }

        path2 = strjoina("/run/systemd/dynamic-uid/direct:", name);
        if (unlink(path2) < 0) {
                if (errno != ENOENT)
                        r = -errno;
        }
        if (b) {
                if (symlink(path1 + strlen("/run/systemd/dynamic-uid/direct:"), path2) < 0)
                        r = -errno;
        }

        return r;
}

static int pick_uid(const char *name, uid_t *ret_uid) {

        static const uint8_t hash_key[] = {
                0x37, 0x53, 0x7e, 0x31, 0xcf, 0xce, 0x48, 0xf5,
                0x8a, 0xbb, 0x39, 0x57, 0x8d, 0xd9, 0xec, 0x59
        };

        unsigned n_tries = 100;
        uid_t candidate;
        int r;

        /* A static user by this name does not exist yet. Let's find a free ID then, and use that. We start with a UID
         * generated as hash from the user name. */
        candidate = UID_CLAMP_INTO_RANGE(siphash24(name, strlen(name), hash_key));

        (void) mkdir("/run/systemd/dynamic-uid", 0755);

        for (;;) {
                char lock_path[strlen("/run/systemd/dynamic-uid/") + DECIMAL_STR_MAX(uid_t) + 1];
                _cleanup_close_ int lock_fd = -1;
                ssize_t l;

                if (--n_tries <= 0) /* Give up retrying eventually */
                        return -EBUSY;

                if (candidate < UID_PICK_MIN || candidate > UID_PICK_MAX)
                        goto next;

                xsprintf(lock_path, "/run/systemd/dynamic-uid/" UID_FMT, candidate);

                for (;;) {
                        struct stat st;

                        lock_fd = open(lock_path, O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC|O_NOCTTY, 0600);
                        if (lock_fd < 0)
                                return -errno;

                        r = flock(lock_fd, LOCK_EX|LOCK_NB); /* Try to get a BSD file lock on the UID lock file */
                        if (r < 0) {
                                if (errno == EBUSY || errno == EAGAIN)
                                        goto next; /* already in use */

                                return -errno;
                        }

                        if (fstat(lock_fd, &st) < 0)
                                return -errno;
                        if (st.st_nlink > 0)
                                break;

                        /* Oh, bummer, we got got the lock, but the file was unlinked between the time we opened it and
                         * got the lock. Close it, and try again. */
                        lock_fd = safe_close(lock_fd);
                }

                /* Some superficial check whether this UID/GID might already be taken by some static user */
                if (getpwuid(candidate) || getgrgid((gid_t) candidate)) {
                        (void) unlink(lock_path);
                        goto next;
                }

                /* Let's store the user name in the lock file, so that we can use it for looking up the username for a UID */
                l = pwritev(lock_fd,
                            (struct iovec[2]) {
                                    { .iov_base = (char*) name, .iov_len = strlen(name) },
                                    { .iov_base = (char[1]) { '\n' }, .iov_len = 1 }
                            }, 2, 0);
                if (l < 0) {
                        (void) unlink(lock_path);
                        return -errno;
                }

                (void) ftruncate(lock_fd, l);
                (void) make_uid_symlinks(candidate, name, true); /* also add direct lookup symlinks */

                *ret_uid = candidate;
                r = lock_fd;
                lock_fd = -1;

                return r;

        next:
                /* Pick another random UID, and see if that works for us. */
                random_bytes(&candidate, sizeof(candidate));
                candidate = UID_CLAMP_INTO_RANGE(candidate);
        }
}

static int dynamic_user_pop(DynamicUser *d, uid_t *ret_uid, int *ret_lock_fd) {
        uid_t uid = UID_INVALID;
        struct iovec iov = {
                .iov_base = &uid,
                .iov_len = sizeof(uid),
        };
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };
        struct cmsghdr *cmsg;

        ssize_t k;
        int lock_fd = -1;

        assert(d);
        assert(ret_uid);
        assert(ret_lock_fd);

        /* Read the UID and lock fd that is stored in the storage AF_UNIX socket. This should be called with the lock
         * on the socket taken. */

        k = recvmsg(d->storage_socket[0], &mh, MSG_DONTWAIT|MSG_NOSIGNAL|MSG_CMSG_CLOEXEC);
        if (k < 0)
                return -errno;

        cmsg = cmsg_find(&mh, SOL_SOCKET, SCM_RIGHTS, CMSG_LEN(sizeof(int)));
        if (cmsg)
                lock_fd = *(int*) CMSG_DATA(cmsg);
        else
                cmsg_close_all(&mh); /* just in case... */

        *ret_uid = uid;
        *ret_lock_fd = lock_fd;

        return 0;
}

static int dynamic_user_push(DynamicUser *d, uid_t uid, int lock_fd) {
        struct iovec iov = {
                .iov_base = &uid,
                .iov_len = sizeof(uid),
        };
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };
        ssize_t k;

        assert(d);

        /* Store the UID and lock_fd in the storage socket. This should be called with the socket pair lock taken. */

        if (lock_fd >= 0) {
                struct cmsghdr *cmsg;

                cmsg = CMSG_FIRSTHDR(&mh);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(int));
                memcpy(CMSG_DATA(cmsg), &lock_fd, sizeof(int));

                mh.msg_controllen = CMSG_SPACE(sizeof(int));
        } else {
                mh.msg_control = NULL;
                mh.msg_controllen = 0;
        }

        k = sendmsg(d->storage_socket[1], &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (k < 0)
                return -errno;

        return 0;
}

static void unlink_uid_lock(int lock_fd, uid_t uid, const char *name) {
        char lock_path[strlen("/run/systemd/dynamic-uid/") + DECIMAL_STR_MAX(uid_t) + 1];

        if (lock_fd < 0)
                return;

        xsprintf(lock_path, "/run/systemd/dynamic-uid/" UID_FMT, uid);
        (void) unlink(lock_path);

        (void) make_uid_symlinks(uid, name, false); /* remove direct lookup symlinks */
}

int dynamic_user_realize(DynamicUser *d, uid_t *ret) {

        _cleanup_close_ int etc_passwd_lock_fd = -1, uid_lock_fd = -1;
        uid_t uid = UID_INVALID;
        int r;

        assert(d);

        /* Acquire a UID for the user name. This will allocate a UID for the user name if the user doesn't exist
         * yet. If it already exists its existing UID/GID will be reused. */

        if (lockf(d->storage_socket[0], F_LOCK, 0) < 0)
                return -errno;

        r = dynamic_user_pop(d, &uid, &uid_lock_fd);
        if (r < 0) {
                int new_uid_lock_fd;
                uid_t new_uid;

                if (r != -EAGAIN)
                        goto finish;

                /* OK, nothing stored yet, let's try to find something useful. While we are working on this release the
                 * lock however, so that nobody else blocks on our NSS lookups. */
                (void) lockf(d->storage_socket[0], F_ULOCK, 0);

                /* Let's see if a proper, static user or group by this name exists. Try to take the lock on
                 * /etc/passwd, if that fails with EROFS then /etc is read-only. In that case it's fine if we don't
                 * take the lock, given that users can't be added there anyway in this case. */
                etc_passwd_lock_fd = take_etc_passwd_lock(NULL);
                if (etc_passwd_lock_fd < 0 && etc_passwd_lock_fd != -EROFS)
                        return etc_passwd_lock_fd;

                /* First, let's parse this as numeric UID */
                r = parse_uid(d->name, &uid);
                if (r < 0) {
                        struct passwd *p;
                        struct group *g;

                        /* OK, this is not a numeric UID. Let's see if there's a user by this name */
                        p = getpwnam(d->name);
                        if (p)
                                uid = p->pw_uid;

                        /* Let's see if there's a group by this name */
                        g = getgrnam(d->name);
                        if (g) {
                                /* If the UID/GID of the user/group of the same don't match, refuse operation */
                                if (uid != UID_INVALID && uid != (uid_t) g->gr_gid)
                                        return -EILSEQ;

                                uid = (uid_t) g->gr_gid;
                        }
                }

                if (uid == UID_INVALID) {
                        /* No static UID assigned yet, excellent. Let's pick a new dynamic one, and lock it. */

                        uid_lock_fd = pick_uid(d->name, &uid);
                        if (uid_lock_fd < 0)
                                return uid_lock_fd;
                }

                /* So, we found a working UID/lock combination. Let's see if we actually still need it. */
                if (lockf(d->storage_socket[0], F_LOCK, 0) < 0) {
                        unlink_uid_lock(uid_lock_fd, uid, d->name);
                        return -errno;
                }

                r = dynamic_user_pop(d, &new_uid, &new_uid_lock_fd);
                if (r < 0) {
                        if (r != -EAGAIN) {
                                /* OK, something bad happened, let's get rid of the bits we acquired. */
                                unlink_uid_lock(uid_lock_fd, uid, d->name);
                                goto finish;
                        }

                        /* Great! Nothing is stored here, still. Store our newly acquired data. */
                } else {
                        /* Hmm, so as it appears there's now something stored in the storage socket. Throw away what we
                         * acquired, and use what's stored now. */

                        unlink_uid_lock(uid_lock_fd, uid, d->name);
                        safe_close(uid_lock_fd);

                        uid = new_uid;
                        uid_lock_fd = new_uid_lock_fd;
                }
        }

        /* If the UID/GID was already allocated dynamically, push the data we popped out back in. If it was already
         * allocated statically, push the UID back too, but do not push the lock fd in. If we allocated the UID
         * dynamically right here, push that in along with the lock fd for it. */
        r = dynamic_user_push(d, uid, uid_lock_fd);
        if (r < 0)
                goto finish;

        *ret = uid;
        r = 0;

finish:
        (void) lockf(d->storage_socket[0], F_ULOCK, 0);
        return r;
}

int dynamic_user_current(DynamicUser *d, uid_t *ret) {
        _cleanup_close_ int lock_fd = -1;
        uid_t uid;
        int r;

        assert(d);
        assert(ret);

        /* Get the currently assigned UID for the user, if there's any. This simply pops the data from the storage socket, and pushes it back in right-away. */

        if (lockf(d->storage_socket[0], F_LOCK, 0) < 0)
                return -errno;

        r = dynamic_user_pop(d, &uid, &lock_fd);
        if (r < 0)
                goto finish;

        r = dynamic_user_push(d, uid, lock_fd);
        if (r < 0)
                goto finish;

        *ret = uid;
        r = 0;

finish:
        (void) lockf(d->storage_socket[0], F_ULOCK, 0);
        return r;
}

DynamicUser* dynamic_user_ref(DynamicUser *d) {
        if (!d)
                return NULL;

        assert(d->n_ref > 0);
        d->n_ref++;

        return d;
}

DynamicUser* dynamic_user_unref(DynamicUser *d) {
        if (!d)
                return NULL;

        /* Note that this doesn't actually release any resources itself. If a dynamic user should be fully destroyed
         * and its UID released, use dynamic_user_destroy() instead. NB: the dynamic user table may contain entries
         * with no references, which is commonly the case right before a daemon reload. */

        assert(d->n_ref > 0);
        d->n_ref--;

        return NULL;
}

static int dynamic_user_close(DynamicUser *d) {
        _cleanup_close_ int lock_fd = -1;
        uid_t uid;
        int r;

        /* Release the user ID, by releasing the lock on it, and emptying the storage socket. After this the user is
         * unrealized again, much like it was after it the DynamicUser object was first allocated. */

        if (lockf(d->storage_socket[0], F_LOCK, 0) < 0)
                return -errno;

        r = dynamic_user_pop(d, &uid, &lock_fd);
        if (r == -EAGAIN) {
                /* User wasn't realized yet, nothing to do. */
                r = 0;
                goto finish;
        }
        if (r < 0)
                goto finish;

        /* This dynamic user was realized and dynamically allocated. In this case, let's remove the lock file. */
        unlink_uid_lock(lock_fd, uid, d->name);
        r = 1;

finish:
        (void) lockf(d->storage_socket[0], F_ULOCK, 0);
        return r;
}

DynamicUser* dynamic_user_destroy(DynamicUser *d) {
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

int dynamic_user_serialize(Manager *m, FILE *f, FDSet *fds) {
        DynamicUser *d;
        Iterator i;

        assert(m);
        assert(f);
        assert(fds);

        /* Dump the dynamic user database into the manager serialization, to deal with daemon reloads. */

        HASHMAP_FOREACH(d, m->dynamic_users, i) {
                int copy0, copy1;

                copy0 = fdset_put_dup(fds, d->storage_socket[0]);
                if (copy0 < 0)
                        return copy0;

                copy1 = fdset_put_dup(fds, d->storage_socket[1]);
                if (copy1 < 0)
                        return copy1;

                fprintf(f, "dynamic-user=%s %i %i\n", d->name, copy0, copy1);
        }

        return 0;
}

void dynamic_user_deserialize_one(Manager *m, const char *value, FDSet *fds) {
        _cleanup_free_ char *name = NULL, *s0 = NULL, *s1 = NULL;
        int r, fd0, fd1;

        assert(m);
        assert(value);
        assert(fds);

        /* Parse the serialization again, after a daemon reload */

        r = extract_many_words(&value, NULL, 0, &name, &s0, &s1, NULL);
        if (r != 3 || !isempty(value)) {
                log_debug("Unable to parse dynamic user line.");
                return;
        }

        if (safe_atoi(s0, &fd0) < 0 || !fdset_contains(fds, fd0)) {
                log_debug("Unable to process dynamic user fd specification.");
                return;
        }

        if (safe_atoi(s1, &fd1) < 0 || !fdset_contains(fds, fd1)) {
                log_debug("Unable to process dynamic user fd specification.");
                return;
        }

        r = dynamic_user_add(m, name, (int[]) { fd0, fd1 }, NULL);
        if (r < 0) {
                log_debug_errno(r, "Failed to add dynamic user: %m");
                return;
        }

        (void) fdset_remove(fds, fd0);
        (void) fdset_remove(fds, fd1);
}

void dynamic_user_vacuum(Manager *m, bool close_user) {
        DynamicUser *d;
        Iterator i;

        assert(m);

        /* Empty the dynamic user database, optionally cleaning up orphaned dynamic users, i.e. destroy and free users
         * to which no reference exist. This is called after a daemon reload finished, in order to destroy users which
         * might not be referenced anymore. */

        HASHMAP_FOREACH(d, m->dynamic_users, i) {
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
        char lock_path[strlen("/run/systemd/dynamic-uid/") + DECIMAL_STR_MAX(uid_t) + 1];
        _cleanup_free_ char *user = NULL;
        uid_t check_uid;
        int r;

        assert(m);
        assert(ret);

        /* A friendly way to translate a dynamic user's UID into a his name. */

        if (uid < UID_PICK_MIN)
                return -ESRCH;
        if (uid > UID_PICK_MAX)
                return -ESRCH;

        xsprintf(lock_path, "/run/systemd/dynamic-uid/" UID_FMT, uid);
        r = read_one_line_file(lock_path, &user);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        /* The lock file might be stale, hence let's verify the data before we return it */
        r = dynamic_user_lookup_name(m, user, &check_uid);
        if (r < 0)
                return r;
        if (check_uid != uid) /* lock file doesn't match our own idea */
                return -ESRCH;

        *ret = user;
        user = NULL;

        return 0;
}

int dynamic_user_lookup_name(Manager *m, const char *name, uid_t *ret) {
        DynamicUser *d;
        int r;

        assert(m);
        assert(name);
        assert(ret);

        /* A friendly call for translating a dynamic user's name into its UID */

        d = hashmap_get(m->dynamic_users, name);
        if (!d)
                return -ESRCH;

        r = dynamic_user_current(d, ret);
        if (r == -EAGAIN) /* not realized yet? */
                return -ESRCH;

        return r;
}

int dynamic_creds_acquire(DynamicCreds *creds, Manager *m, const char *user, const char *group) {
        bool acquired = false;
        int r;

        assert(creds);
        assert(m);

        /* A DynamicUser object encapsulates an allocation of both a UID and a GID for a specific name. However, some
         * services use different user and groups. For cases like that there's DynamicCreds containing a pair of user
         * and group. This call allocates a pair. */

        if (!creds->user && user) {
                r = dynamic_user_acquire(m, user, &creds->user);
                if (r < 0)
                        return r;

                acquired = true;
        }

        if (!creds->group) {

                if (creds->user && (!group || streq_ptr(user, group)))
                        creds->group = dynamic_user_ref(creds->user);
                else {
                        r = dynamic_user_acquire(m, group, &creds->group);
                        if (r < 0) {
                                if (acquired)
                                        creds->user = dynamic_user_unref(creds->user);
                                return r;
                        }
                }
        }

        return 0;
}

int dynamic_creds_realize(DynamicCreds *creds, uid_t *uid, gid_t *gid) {
        uid_t u = UID_INVALID;
        gid_t g = GID_INVALID;
        int r;

        assert(creds);
        assert(uid);
        assert(gid);

        /* Realize both the referenced user and group */

        if (creds->user) {
                r = dynamic_user_realize(creds->user, &u);
                if (r < 0)
                        return r;
        }

        if (creds->group && creds->group != creds->user) {
                r = dynamic_user_realize(creds->group, &g);
                if (r < 0)
                        return r;
        } else
                g = u;

        *uid = u;
        *gid = g;

        return 0;
}

void dynamic_creds_unref(DynamicCreds *creds) {
        assert(creds);

        creds->user = dynamic_user_unref(creds->user);
        creds->group = dynamic_user_unref(creds->group);
}

void dynamic_creds_destroy(DynamicCreds *creds) {
        assert(creds);

        creds->user = dynamic_user_destroy(creds->user);
        creds->group = dynamic_user_destroy(creds->group);
}
