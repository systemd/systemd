/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <grp.h>
#include <sched.h>
#include <sys/eventfd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "namespace-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "uid-classification.h"
#include "user-util.h"
#include "userns-restrict.h"

static int make_tmpfs_fsmount(void) {
        _cleanup_close_ int fsfd = -EBADF, mntfd = -EBADF;

        fsfd = ASSERT_OK_ERRNO(fsopen("tmpfs", FSOPEN_CLOEXEC));
        ASSERT_OK_ERRNO(fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0));

        mntfd = ASSERT_OK_ERRNO(fsmount(fsfd, FSMOUNT_CLOEXEC, 0));

        return TAKE_FD(mntfd);
}

/* A tmpfs on the host, but idmapped through the passed user namespace, i.e. the equivalent of what mountfsd
 * hands to clients: our transient UID lands on disk as UID 0, so nothing recyclable is recorded. */
static int make_idmapped_tmpfs_fsmount(int userns_fd) {
        _cleanup_close_ int mntfd = -EBADF;

        mntfd = ASSERT_OK(make_tmpfs_fsmount());

        ASSERT_OK_ERRNO(mount_setattr(mntfd, "", AT_EMPTY_PATH,
                                      &(struct mount_attr) {
                                              .attr_set = MOUNT_ATTR_IDMAP,
                                              .userns_fd = userns_fd,
                                      }, sizeof(struct mount_attr)));

        return TAKE_FD(mntfd);
}

static struct userns_restrict_bpf *bpf_obj = NULL;
STATIC_DESTRUCTOR_REGISTER(bpf_obj, userns_restrict_bpf_freep);

static int intro(void) {
        int r;

        r = userns_restrict_install(/* pin= */ false, &bpf_obj);
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return log_tests_skipped("LSM-BPF logic not supported");
        if (ERRNO_IS_PRIVILEGE(r))
                return log_tests_skipped("Lacking privileges");
        ASSERT_OK(r);

        ASSERT_OK(userns_restrict_attach(bpf_obj, /* pin= */ false));

        return 0;
}

TEST(userns_restrict) {
        _cleanup_close_ int userns_fd = -EBADF, host_fd1 = -EBADF, host_tmpfs = -EBADF,
                             idmapped_tmpfs = -EBADF;
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        int r;

        ASSERT_OK(mkdtemp_malloc(NULL, &t));
        /* Make sure the dir is owned by the transient UID we'll be using so we don't get rejected with a
         * permission error before we even get to the BPF-LSM. */
        ASSERT_OK_ERRNO(chown(t, CONTAINER_UID_MIN, CONTAINER_UID_MIN));

        host_fd1 = ASSERT_OK_ERRNO(open(t, O_DIRECTORY|O_CLOEXEC));
        host_tmpfs = ASSERT_OK(make_tmpfs_fsmount());

        _cleanup_free_ char *idmap = NULL;
        ASSERT_OK(asprintf(&idmap, "0 "UID_FMT" 1", CONTAINER_UID_MIN));
        userns_fd = ASSERT_OK(userns_acquire(idmap, idmap, /* setgroups_deny= */ true));

        idmapped_tmpfs = ASSERT_OK(make_idmapped_tmpfs_fsmount(userns_fd));

        ASSERT_OK(userns_restrict_register_by_fd(bpf_obj, userns_fd));

        r = ASSERT_OK(pidref_safe_fork("(test)", FORK_DEATHSIG_SIGKILL, &pidref));
        if (r == 0) {
                _cleanup_close_ int private_tmpfs = -EBADF;

                ASSERT_OK(namespace_enter(-EBADF, -EBADF, -EBADF, userns_fd, -EBADF));
                ASSERT_OK_ERRNO(unshare(CLONE_NEWNS));

                /* Allocate tmpfs locally, i.e. a file system that dies together with our user namespace */
                private_tmpfs = make_tmpfs_fsmount();

                /* These two host mounts would record our transient UID on disk, hence are inaccessible */
                ASSERT_ERROR_ERRNO(openat(host_fd1, "test", O_RDWR|O_CREAT|O_CLOEXEC, 0666), EPERM);
                ASSERT_ERROR_ERRNO(openat(host_tmpfs, "xxx", O_RDWR|O_CREAT|O_CLOEXEC, 0666), EPERM);
                ASSERT_ERROR_ERRNO(mkdirat(host_fd1, "test2", 0666), EPERM);
                ASSERT_ERROR_ERRNO(mkdirat(host_tmpfs, "xxx2", 0666), EPERM);

                /* But this mount created locally should be fine */
                safe_close(ASSERT_OK_ERRNO(openat(private_tmpfs, "yyy", O_RDWR|O_CREAT|O_CLOEXEC, 0666)));
                ASSERT_OK_ERRNO(mkdirat(private_tmpfs, "yyy2", 0666));

                /* And so should the idmapped host mount: it translates our transient UID to UID 0 before
                 * anything reaches the disk */
                safe_close(ASSERT_OK_ERRNO(openat(idmapped_tmpfs, "zzz", O_RDWR|O_CREAT|O_CLOEXEC, 0666)));
                ASSERT_OK_ERRNO(mkdirat(idmapped_tmpfs, "zzz2", 0666));

                /* chown() is subject to the same policy. Unlike the creation hooks it is handed the ID that
                 * ends up on disk, so it needs no idmap arithmetic of its own. Setting a group the inode
                 * already has still reaches the hook, before the change is applied. Giving the host
                 * directory (which outlives us) our transient GID would leave something recyclable behind,
                 * hence is refused... */
                ASSERT_ERROR_ERRNO(fchownat(host_fd1, "", GID_INVALID, 0, AT_EMPTY_PATH), EPERM);

                /* ...while the same chown() is fine on the file system that dies with us, and on the
                 * idmapped mount where our transient GID is translated to 0 before it reaches the disk. */
                ASSERT_OK_ERRNO(fchownat(private_tmpfs, "yyy", GID_INVALID, 0, 0));
                ASSERT_OK_ERRNO(fchownat(idmapped_tmpfs, "zzz", GID_INVALID, 0, 0));

                /* Unsharing a mount namespace hands us clones of every mount we can see, owned by our own
                 * user namespace. That must not buy us anything.
                 *
                 * Note that this has to go through a path, not through the directory fd opened above: an
                 * already open fd pins the original mount, while a path lookup lands on the clone, and it
                 * is the clone that used to be mistaken for one of ours. */
                ASSERT_OK_ERRNO(unshare(CLONE_NEWNS));

                _cleanup_free_ char *p1 = NULL, *p2 = NULL;
                ASSERT_NOT_NULL(p1 = path_join(t, "newns"));
                ASSERT_NOT_NULL(p2 = path_join(t, "newns2"));

                ASSERT_ERROR_ERRNO(open(p1, O_RDWR|O_CREAT|O_CLOEXEC, 0666), EPERM);
                ASSERT_ERROR_ERRNO(mkdir(p2, 0666), EPERM);
                ASSERT_ERROR_ERRNO(openat(host_fd1, "newns3", O_RDWR|O_CREAT|O_CLOEXEC, 0666), EPERM);
                ASSERT_ERROR_ERRNO(openat(host_tmpfs, "newns4", O_RDWR|O_CREAT|O_CLOEXEC, 0666), EPERM);

                /* And chown() through the clone must stay refused too, not just inode creation. */
                ASSERT_ERROR_ERRNO(fchownat(AT_FDCWD, t, GID_INVALID, 0, 0), EPERM);

                /* Neither must nesting a user namespace, which is not in the managed map itself */
                ASSERT_OK_ERRNO(unshare(CLONE_NEWUSER));

                _cleanup_free_ char *p3 = NULL, *p4 = NULL;
                ASSERT_NOT_NULL(p3 = path_join(t, "newuser"));
                ASSERT_NOT_NULL(p4 = path_join(t, "newuser2"));

                ASSERT_ERROR_ERRNO(open(p3, O_RDWR|O_CREAT|O_CLOEXEC, 0666), EPERM);
                ASSERT_ERROR_ERRNO(mkdir(p4, 0666), EPERM);
                ASSERT_ERROR_ERRNO(openat(host_fd1, "newuser3", O_RDWR|O_CREAT|O_CLOEXEC, 0666), EPERM);
                ASSERT_ERROR_ERRNO(openat(host_tmpfs, "newuser4", O_RDWR|O_CREAT|O_CLOEXEC, 0666), EPERM);

                /* …while what was legitimately writable before stays writable */
                safe_close(ASSERT_OK_ERRNO(openat(private_tmpfs, "aaa", O_RDWR|O_CREAT|O_CLOEXEC, 0666)));
                safe_close(ASSERT_OK_ERRNO(openat(idmapped_tmpfs, "bbb", O_RDWR|O_CREAT|O_CLOEXEC, 0666)));

                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(pidref_wait_for_terminate_and_check("(test)", &pidref, WAIT_LOG));
}

TEST(userns_restrict_overlayfs) {
        _cleanup_close_ int userns_fd = -EBADF, idmapped_upper = -EBADF, bad_userns_fd = -EBADF,
                             bad_upper = -EBADF;
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL, *th = NULL, *ti = NULL, *tb = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        _cleanup_free_ char *idmap = NULL, *bad_idmap = NULL, *hlower = NULL, *hupper = NULL, *hwork = NULL,
                            *hmerged = NULL;
        int r;

        /* overlay writes land on its upper layer via vfs_create(), which the path-based hooks never see, so
         * a transient-owned inode could persist there. The policy judges the upper at mount time. An upper
         * is allowed when it dies with the namespace (a tmpfs the client set up) or is idmapped to map the
         * transient range away; it is refused when it outlives the namespace and records the transient range
         * on disk (a plain init-owned upper, or one idmapped so the transient range still reaches its disk).
         * We also check that an overlay mounted read-only but with such an upper is refused, since it could
         * otherwise be remounted read-write afterwards without re-entering the hook. */

        ASSERT_OK(mkdtemp_malloc(NULL, &t));
        ASSERT_OK_ERRNO(chown(t, CONTAINER_UID_MIN, CONTAINER_UID_MIN));

        ASSERT_OK(asprintf(&idmap, "0 "UID_FMT" 1", CONTAINER_UID_MIN));
        userns_fd = ASSERT_OK(userns_acquire(idmap, idmap, /* setgroups_deny= */ true));

        ASSERT_OK(userns_restrict_register_by_fd(bpf_obj, userns_fd));

        /* Set up the layer dirs for the refuse case on the init-owned file system backing our temporary dir,
         * i.e. one that outlives the user namespace. This has to happen here as root: the managed client
         * cannot create these itself, as the path hooks already block a transient-owned inode on a file
         * system that outlives it. */
        ASSERT_OK(mkdtemp_malloc(NULL, &th));
        ASSERT_OK_ERRNO(chown(th, CONTAINER_UID_MIN, CONTAINER_UID_MIN));
        ASSERT_NOT_NULL(hlower = path_join(th, "lower"));
        ASSERT_NOT_NULL(hupper = path_join(th, "upper"));
        ASSERT_NOT_NULL(hwork = path_join(th, "work"));
        ASSERT_NOT_NULL(hmerged = path_join(th, "merged"));
        ASSERT_OK_ERRNO(mkdir(hlower, 0755));
        ASSERT_OK_ERRNO(mkdir(hupper, 0755));
        ASSERT_OK_ERRNO(mkdir(hwork, 0755));
        ASSERT_OK_ERRNO(mkdir(hmerged, 0755));
        ASSERT_OK_ERRNO(chown(hlower, CONTAINER_UID_MIN, CONTAINER_UID_MIN));
        ASSERT_OK_ERRNO(chown(hupper, CONTAINER_UID_MIN, CONTAINER_UID_MIN));
        ASSERT_OK_ERRNO(chown(hwork, CONTAINER_UID_MIN, CONTAINER_UID_MIN));
        ASSERT_OK_ERRNO(chown(hmerged, CONTAINER_UID_MIN, CONTAINER_UID_MIN));

        /* And an idmapped upper for the third case: a tmpfs created here, i.e. in the initial user namespace
         * so that it outlives the managed one, but idmapped through it so our transient range lands on its
         * disk as non-transient ids. Set it up as root and attach it at a path the client can point
         * upperdir= at. */
        idmapped_upper = ASSERT_OK(make_idmapped_tmpfs_fsmount(userns_fd));
        ASSERT_OK(mkdtemp_malloc(NULL, &ti));
        ASSERT_OK_ERRNO(move_mount(idmapped_upper, "", -EBADF, ti, MOVE_MOUNT_F_EMPTY_PATH));

        /* And a fourth upper, for the refuse path of the idmap check: an init-owned tmpfs idmapped so that
         * it records our transient range on disk unchanged (identity over it), i.e. one that does NOT
         * neutralize the range. We create and chown the layer dirs before idmapping it, since afterwards
         * neither we (uid 0, left unmapped by the narrow idmap) nor the client (whose transient-owned
         * writes to a persistent file system are refused) could. This overlay must be refused. */
        ASSERT_OK(asprintf(&bad_idmap, UID_FMT" "UID_FMT" 1", CONTAINER_UID_MIN, CONTAINER_UID_MIN));
        bad_userns_fd = ASSERT_OK(userns_acquire(bad_idmap, bad_idmap, /* setgroups_deny= */ false));
        bad_upper = ASSERT_OK(make_tmpfs_fsmount());
        ASSERT_OK_ERRNO(mkdirat(bad_upper, "upper", 0755));
        ASSERT_OK_ERRNO(mkdirat(bad_upper, "work", 0755));
        ASSERT_OK_ERRNO(fchownat(bad_upper, "upper", CONTAINER_UID_MIN, CONTAINER_UID_MIN, 0));
        ASSERT_OK_ERRNO(fchownat(bad_upper, "work", CONTAINER_UID_MIN, CONTAINER_UID_MIN, 0));
        ASSERT_OK_ERRNO(mount_setattr(bad_upper, "", AT_EMPTY_PATH,
                                      &(struct mount_attr) {
                                              .attr_set = MOUNT_ATTR_IDMAP,
                                              .userns_fd = bad_userns_fd,
                                      }, sizeof(struct mount_attr)));
        ASSERT_OK(mkdtemp_malloc(NULL, &tb));
        ASSERT_OK_ERRNO(move_mount(bad_upper, "", -EBADF, tb, MOVE_MOUNT_F_EMPTY_PATH));

        r = ASSERT_OK(pidref_safe_fork("(test-ovl)", FORK_DEATHSIG_SIGKILL, &pidref));
        if (r == 0) {
                ASSERT_OK(namespace_enter(-EBADF, -EBADF, -EBADF, userns_fd, -EBADF));
                ASSERT_OK_ERRNO(unshare(CLONE_NEWNS));
                ASSERT_OK_ERRNO(mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL));

                /* Hold the overlay layers on a tmpfs of our own, so nothing touches the host. */
                ASSERT_OK_ERRNO(mount("tmpfs", t, "tmpfs", 0, NULL));

                _cleanup_free_ char *lower = NULL, *lower2 = NULL, *upper = NULL, *work = NULL,
                        *merged = NULL;
                ASSERT_NOT_NULL(lower = path_join(t, "lower"));
                ASSERT_NOT_NULL(lower2 = path_join(t, "lower2"));
                ASSERT_NOT_NULL(upper = path_join(t, "upper"));
                ASSERT_NOT_NULL(work = path_join(t, "work"));
                ASSERT_NOT_NULL(merged = path_join(t, "merged"));
                ASSERT_OK_ERRNO(mkdir(lower, 0755));
                ASSERT_OK_ERRNO(mkdir(lower2, 0755));
                ASSERT_OK_ERRNO(mkdir(upper, 0755));
                ASSERT_OK_ERRNO(mkdir(work, 0755));
                ASSERT_OK_ERRNO(mkdir(merged, 0755));

                /* Control: a read-only overlay (no upper layer) is harmless and must be allowed. The kernel
                 * rejects a single lowerdir with no upper, so stack two lowers. If even this fails,
                 * unprivileged overlayfs is unavailable on this kernel — treat as a skip. */
                _cleanup_free_ char *ro_opts = NULL;
                ASSERT_NOT_NULL(ro_opts = strjoin("lowerdir=", lower, ":", lower2));
                if (mount("overlay", merged, "overlay", MS_RDONLY, ro_opts) < 0) {
                        /* A read-only overlay has no upper and must be allowed. If our hook (rather than the
                         * kernel) refused it we would see EPERM, which is a bug, not a reason to skip. */
                        ASSERT_TRUE(errno != EPERM);
                        log_notice_errno(errno, "Unprivileged overlayfs unavailable, skipping: %m");
                        _exit(EXIT_SUCCESS);
                }
                ASSERT_OK_ERRNO(umount(merged));

                /* The writable overlay's upper is on the tmpfs above, which dies with our user namespace, so
                 * the BPF-LSM must allow the mount. */
                _cleanup_free_ char *rw_opts = NULL;
                ASSERT_NOT_NULL(rw_opts = strjoin("lowerdir=", lower, ",upperdir=", upper,
                                                  ",workdir=", work));
                ASSERT_OK_ERRNO(mount("overlay", merged, "overlay", 0, rw_opts));

                /* A write through the overlay really lands on the upper (our tmpfs), which the path hooks
                 * never see directly. chown() over the merged mount reaches path_chown, which sees the
                 * overlay superblock (ours, so it dies with us) and allows it, even to a transient gid. */
                _cleanup_free_ char *f = NULL, *uf = NULL;
                ASSERT_NOT_NULL(f = path_join(merged, "f"));
                ASSERT_NOT_NULL(uf = path_join(upper, "f"));
                safe_close(ASSERT_OK_ERRNO(open(f, O_RDWR|O_CREAT|O_CLOEXEC, 0666)));
                ASSERT_OK_ERRNO(access(uf, F_OK));
                ASSERT_OK_ERRNO(fchownat(AT_FDCWD, f, UID_INVALID, 0, 0));

                ASSERT_OK_ERRNO(umount(merged));

                /* The same writable overlay, but with its upper on the init-owned host file system that
                 * outlives our user namespace: the policy must refuse it. Overlayfs sets the upper up via
                 * vfs_mkdir()/vfs_create(), reaching only the inode hooks, so nothing blocks it before
                 * sb_kern_mount runs, and the kernel itself permits the mount (verified without the BPF-LSM
                 * loaded) — hence the EPERM here is sb_kern_mount refusing it. */
                _cleanup_free_ char *bad_opts = NULL;
                ASSERT_NOT_NULL(bad_opts = strjoin("lowerdir=", hlower, ",upperdir=", hupper,
                                                   ",workdir=", hwork));
                ASSERT_ERROR_ERRNO(mount("overlay", hmerged, "overlay", 0, bad_opts), EPERM);

                /* The same persistent upper, but mounted read-only, must be refused too: it still has an
                 * upper, so allowing it on the strength of the (mutable) read-only flag would let the client
                 * remount it read-write afterwards, which does not re-enter this hook. */
                ASSERT_ERROR_ERRNO(mount("overlay", hmerged, "overlay", MS_RDONLY, bad_opts), EPERM);

                /* Then the idmapped upper: its superblock outlives us, but its idmapping maps our
                 * transient range away, so nothing recyclable reaches its disk and the mount is allowed
                 * again. The layer dirs are created by us, the transient client, which the idmapping permits
                 * the same way it permits writes through the mount. */
                _cleanup_free_ char *iupper = NULL, *iwork = NULL, *idmapped_opts = NULL;
                ASSERT_NOT_NULL(iupper = path_join(ti, "upper"));
                ASSERT_NOT_NULL(iwork = path_join(ti, "work"));
                ASSERT_OK_ERRNO(mkdir(iupper, 0755));
                ASSERT_OK_ERRNO(mkdir(iwork, 0755));
                ASSERT_NOT_NULL(idmapped_opts = strjoin("lowerdir=", lower, ",upperdir=", iupper,
                                                        ",workdir=", iwork));
                ASSERT_OK_ERRNO(mount("overlay", merged, "overlay", 0, idmapped_opts));
                ASSERT_OK_ERRNO(umount(merged));

                /* Finally the idmapped upper whose idmapping does NOT map our transient range away (it
                 * records it on disk unchanged): the mount reaches sb_kern_mount, whose idmap check must
                 * refuse it. */
                _cleanup_free_ char *bupper = NULL, *bwork = NULL, *bad_idmapped_opts = NULL;
                ASSERT_NOT_NULL(bupper = path_join(tb, "upper"));
                ASSERT_NOT_NULL(bwork = path_join(tb, "work"));
                ASSERT_NOT_NULL(bad_idmapped_opts = strjoin("lowerdir=", lower, ",upperdir=", bupper,
                                                            ",workdir=", bwork));
                ASSERT_ERROR_ERRNO(mount("overlay", merged, "overlay", 0, bad_idmapped_opts), EPERM);

                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(pidref_wait_for_terminate_and_check("(test-ovl)", &pidref, WAIT_LOG));

        /* Detach the extra uppers we attached in our (initial) mount namespace before the temp dirs are
         * removed. */
        (void) umount(ti);
        (void) umount(tb);
}

static void write_child_mappings(PidRef *child, int parent_userns_fd) {
        /* The kernel requires uid_map/gid_map to be written from the parent user namespace of the
         * target namespace. Fork a helper that joins the parent userns and writes the mappings from
         * there, mirroring what write_userns() does in nsresourcework.c. */
        int r;

        r = ASSERT_OK(pidref_safe_fork("(sd-write-map)", FORK_DEATHSIG_SIGKILL|FORK_WAIT|FORK_LOG, NULL));
        if (r == 0) {
                char path[STRLEN("/proc//uid_map") + DECIMAL_STR_MAX(pid_t) + 1];

                ASSERT_OK_ERRNO(setns(parent_userns_fd, CLONE_NEWUSER));

                xsprintf(path, "/proc/" PID_FMT "/uid_map", child->pid);
                ASSERT_OK(write_string_file(path, "0 0 1\n", WRITE_STRING_FILE_DISABLE_BUFFER));

                xsprintf(path, "/proc/" PID_FMT "/gid_map", child->pid);
                ASSERT_OK(write_string_file(path, "0 0 1\n", WRITE_STRING_FILE_DISABLE_BUFFER));

                _exit(EXIT_SUCCESS);
        }
}

TEST(setgroups_deny) {
        _cleanup_close_ int deny_userns_fd = -EBADF, allow_userns_fd = -EBADF,
                             afd = -EBADF, bfd = -EBADF;
        int r;

        _cleanup_free_ char *idmap = NULL;
        ASSERT_OK(asprintf(&idmap, "0 "UID_FMT" 1", CONTAINER_UID_MIN));

        /* Create a userns that will have setgroups() denied via BPF. We don't set setgroups_deny here
         * because that uses /proc/self/setgroups which is transitive and we want to test the BPF-LSM
         * denial specifically. */
        deny_userns_fd = ASSERT_OK(userns_acquire(idmap, idmap, /* setgroups_deny= */ false));

        ASSERT_OK(userns_restrict_register_by_fd(bpf_obj, deny_userns_fd));
        ASSERT_OK(userns_restrict_setgroups_deny_by_fd(bpf_obj, deny_userns_fd));

        /* Create a userns that is managed but does NOT have setgroups() denied */
        allow_userns_fd = ASSERT_OK(userns_acquire(idmap, idmap, /* setgroups_deny= */ false));

        ASSERT_OK(userns_restrict_register_by_fd(bpf_obj, allow_userns_fd));

        afd = ASSERT_OK_ERRNO(eventfd(0, EFD_CLOEXEC));
        bfd = ASSERT_OK_ERRNO(eventfd(0, EFD_CLOEXEC));

        /* Test 1: setgroups() should be denied in the deny userns, including after unsharing into a child
         * user namespace (the ancestor walk should find the deny entry). */
        {
                _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;

                r = ASSERT_OK(pidref_safe_fork("(test-deny)", FORK_LOG|FORK_DEATHSIG_SIGKILL, &pidref));
                if (r == 0) {
                        /* Enter the userns manually without going through namespace_enter(), because
                         * that calls reset_uid_gid() which calls setgroups() internally. Since the
                         * BPF LSM denies setgroups(), reset_uid_gid() would fail before calling
                         * setresuid()/setresgid(), leaving us as the overflow UID without
                         * capabilities. */
                        ASSERT_OK_ERRNO(setns(deny_userns_fd, CLONE_NEWUSER));
                        ASSERT_OK_ERRNO(setresgid(0, 0, 0));
                        ASSERT_OK_ERRNO(setresuid(0, 0, 0));

                        /* setgroups() should be denied by BPF LSM */
                        ASSERT_ERROR_ERRNO(setgroups(0, NULL), EPERM);

                        /* Unshare into a child user namespace. The parent will write the mappings
                         * for us since writing /proc/self/uid_map from inside the userns fails
                         * because the proc mount belongs to the init user namespace. */
                        ASSERT_OK_ERRNO(unshare(CLONE_NEWUSER));
                        ASSERT_OK_ERRNO(eventfd_write(afd, 1));
                        uint64_t x;
                        ASSERT_OK_ERRNO(eventfd_read(bfd, &x));

                        /* setgroups() should still be denied because the ancestor walk finds the
                         * deny entry on the parent user namespace */
                        ASSERT_ERROR_ERRNO(setgroups(0, NULL), EPERM);

                        _exit(EXIT_SUCCESS);
                }

                uint64_t x;
                ASSERT_OK_ERRNO(eventfd_read(afd, &x));
                write_child_mappings(&pidref, deny_userns_fd);
                ASSERT_OK_ERRNO(eventfd_write(bfd, 1));

                ASSERT_OK(pidref_wait_for_terminate_and_check("(test-deny)", &pidref, WAIT_LOG));
        }

        /* Test 2: setgroups() should be allowed in the managed-only userns (managed map but no setgroups
         * deny entry), including in a child user namespace. */
        {
                _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;

                r = ASSERT_OK(pidref_safe_fork("(test-allow)", FORK_LOG|FORK_DEATHSIG_SIGKILL, &pidref));
                if (r == 0) {
                        ASSERT_OK_ERRNO(setns(allow_userns_fd, CLONE_NEWUSER));
                        ASSERT_OK_ERRNO(setresgid(0, 0, 0));
                        ASSERT_OK_ERRNO(setresuid(0, 0, 0));

                        /* setgroups() should succeed since this userns is only in the managed map */
                        ASSERT_OK_ERRNO(setgroups(0, NULL));

                        /* Also should work in a child userns since the ancestor walk finds the
                         * managed map entry (not the setgroups deny entry) */
                        ASSERT_OK_ERRNO(unshare(CLONE_NEWUSER));
                        ASSERT_OK_ERRNO(eventfd_write(afd, 1));
                        uint64_t x;
                        ASSERT_OK_ERRNO(eventfd_read(bfd, &x));

                        ASSERT_OK_ERRNO(setgroups(0, NULL));

                        _exit(EXIT_SUCCESS);
                }

                uint64_t x;
                ASSERT_OK_ERRNO(eventfd_read(afd, &x));
                write_child_mappings(&pidref, allow_userns_fd);
                ASSERT_OK_ERRNO(eventfd_write(bfd, 1));

                ASSERT_OK(pidref_wait_for_terminate_and_check("(test-allow)", &pidref, WAIT_LOG));
        }
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
