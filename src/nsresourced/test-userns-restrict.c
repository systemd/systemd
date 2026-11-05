/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <grp.h>
#include <linux/btrfs.h>
#include <linux/magic.h>
#include <mqueue.h>
#include <sched.h>
#include <stdio.h>
#include <sys/eventfd.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bpf-link.h"
#include "bpf-util.h"
#include "btrfs-util.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "namespace-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "uid-classification.h"
#include "unaligned.h"
#include "user-util.h"
#include "userns-restrict-skel.h"
#include "userns-restrict.h"

static int make_tmpfs_fsmount(void) {
        _cleanup_close_ int fsfd = -EBADF, mntfd = -EBADF;

        fsfd = ASSERT_OK_ERRNO(fsopen("tmpfs", FSOPEN_CLOEXEC));
        ASSERT_OK_ERRNO(fsconfig(fsfd, FSCONFIG_CMD_CREATE, /* key= */ NULL, /* value= */ NULL, /* aux= */ 0));

        mntfd = ASSERT_OK_ERRNO(fsmount(fsfd, FSMOUNT_CLOEXEC, /* attr_flags= */ 0));

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

static bool inode_hooks = false;

static int intro(void) {
        int r;

        r = userns_restrict_install(/* pin= */ false, &bpf_obj);
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return log_tests_skipped("LSM-BPF logic not supported");
        if (ERRNO_IS_PRIVILEGE(r))
                return log_tests_skipped("Lacking privileges");
        ASSERT_OK(r);

        inode_hooks = sym_bpf_program__fd(bpf_obj->progs.userns_restrict_inode_create) >= 0;

        r = userns_restrict_attach(bpf_obj, /* pin= */ false);
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return log_tests_skipped("LSM-BPF programs cannot be attached");
        ASSERT_OK(r);

        return 0;
}

static typeof(sym_bpf_link__pin) pin_without_failure;
static unsigned pins_until_failure;

static int pin_with_failure(struct bpf_link *link, const char *path) {
        if (--pins_until_failure == 0)
                return -ENOMEM;

        return pin_without_failure(link, path);
}

static uint32_t link_id(struct bpf_link *link) {
        struct bpf_link_info info = {};
        uint32_t len = sizeof(info);

        ASSERT_OK(sym_bpf_obj_get_info_by_fd(sym_bpf_link__fd(link), &info, &len));
        return info.id;
}

static void check_pinned_links(const uint32_t *ids, bool replaced) {
        for (int i = 0; i < bpf_obj->skeleton->prog_cnt; i++) {
                struct bpf_prog_skeleton *ps = bpf_obj->skeleton->progs + i;
                _cleanup_(bpf_link_freep) struct bpf_link *link = NULL;
                _cleanup_free_ char *path = NULL;
                const char *name;

                if (sym_bpf_program__fd(*ps->prog) < 0)
                        continue;

                name = ASSERT_NOT_NULL(startswith(ps->name, "userns_restrict_"));
                ASSERT_NOT_NULL(path = path_join("/sys/fs/bpf/systemd/userns-restrict-v2/programs", name));
                link = sym_bpf_link__open(path);
                ASSERT_OK(bpf_get_error_translated(link));
                if (replaced)
                        ASSERT_NE(link_id(link), ids[i]);
                else
                        ASSERT_EQ(link_id(link), ids[i]);
        }
}

TEST_RET(userns_restrict_replace_pins) {
        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
        _cleanup_(userns_restrict_bpf_freep) struct userns_restrict_bpf *obj = NULL;
        _cleanup_free_ uint32_t *ids = NULL;
        struct stat st;
        int r;

        r = ASSERT_OK(pidref_safe_fork("(test-bpf-pins)", FORK_DEATHSIG_SIGKILL, &child));
        if (r > 0)
                return ASSERT_OK(pidref_wait_for_terminate_and_check("(test-bpf-pins)", &child, WAIT_LOG));

        /* A private bpffs prevents the test from replacing the daemon's pinned policy. */
        r = RET_NERRNO(unshare(CLONE_NEWNS));
        if (ERRNO_IS_NEG_PRIVILEGE(r))
                _exit(log_tests_skipped_errno(r, "Cannot create a mount namespace"));
        ASSERT_OK(r);
        ASSERT_OK_ERRNO(mount(/* source= */ NULL, "/", /* filesystemtype= */ NULL, MS_PRIVATE|MS_REC, /* data= */ NULL));
        ASSERT_OK_ERRNO(mount("bpf", "/sys/fs/bpf", "bpf", /* mountflags= */ 0, /* data= */ NULL));

        ASSERT_OK(userns_restrict_install(/* pin= */ true, &obj));
        ASSERT_OK(userns_restrict_attach(obj, /* pin= */ true));

        ASSERT_NOT_NULL(ids = new0(uint32_t, obj->skeleton->prog_cnt));
        for (int i = 0; i < obj->skeleton->prog_cnt; i++) {
                struct bpf_prog_skeleton *ps = obj->skeleton->progs + i;

                if (*ps->link)
                        ids[i] = link_id(*ps->link);
        }
        obj = userns_restrict_bpf_free(obj);

        ASSERT_OK(userns_restrict_install(/* pin= */ true, &obj));
        pin_without_failure = sym_bpf_link__pin;
        sym_bpf_link__pin = pin_with_failure;
        pins_until_failure = 2;
        ASSERT_ERROR(userns_restrict_attach(obj, /* pin= */ true), ENOMEM);
        ASSERT_EQ(pins_until_failure, 0U);
        sym_bpf_link__pin = pin_without_failure;
        obj = userns_restrict_bpf_free(obj);

        check_pinned_links(ids, /* replaced= */ false);
        ASSERT_ERROR_ERRNO(lstat("/sys/fs/bpf/systemd/userns-restrict-v2/programs-new", &st), ENOENT);

        ASSERT_OK(userns_restrict_install(/* pin= */ true, &obj));
        ASSERT_OK(userns_restrict_attach(obj, /* pin= */ true));
        obj = userns_restrict_bpf_free(obj);
        check_pinned_links(ids, /* replaced= */ true);
        ASSERT_ERROR_ERRNO(lstat("/sys/fs/bpf/systemd/userns-restrict-v2/programs-new", &st), ENOENT);

        _exit(EXIT_SUCCESS);
}

/* nsresourced removes the map entries of a user namespace when the namespace dies. The tests don't run
 * nsresourced, so they remove the entries themselves. Otherwise a later namespace can get the same inode
 * number, and the BPF programs treat it as managed. The setgroups() check then stops at that namespace
 * and never reaches a parent with a deny entry. */
static void unregister_userns(uint64_t *inode) {
        assert(inode);

        if (*inode != 0)
                (void) userns_restrict_reset_by_inode(bpf_obj, *inode);
}

static uint64_t register_userns(int userns_fd) {
        struct stat st;

        ASSERT_OK_ERRNO(fstat(userns_fd, &st));
        ASSERT_OK(userns_restrict_register_by_inode(bpf_obj, st.st_ino));

        return st.st_ino;
}

TEST(userns_restrict) {
        _cleanup_(unregister_userns) uint64_t registered = 0;
        _cleanup_close_ int userns_fd = -EBADF, host_fd1 = -EBADF, host_tmpfs = -EBADF,
                             idmapped_tmpfs = -EBADF;
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        bool have_tmpfile;
        int r;

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));
        /* Make sure the dir is owned by the transient UID we'll be using so we don't get rejected with a
         * permission error before we even get to the BPF-LSM. */
        ASSERT_OK_ERRNO(chown(t, CONTAINER_UID_MIN, CONTAINER_UID_MIN));

        host_fd1 = ASSERT_OK(xopenat(AT_FDCWD, t, O_DIRECTORY));
        safe_close(ASSERT_OK(xopenat_full(host_fd1, "source", O_CREAT|O_EXCL|O_WRONLY, /* xopen_flags= */ 0, 0600)));
        ASSERT_OK_ERRNO(fchownat(host_fd1, "source", CONTAINER_UID_MIN, CONTAINER_UID_MIN, 0));
        ASSERT_OK_ERRNO(mkdirat(host_fd1, "empty", 0700));
        ASSERT_OK_ERRNO(fchownat(host_fd1, "empty", CONTAINER_UID_MIN, CONTAINER_UID_MIN, 0));
        host_tmpfs = ASSERT_OK(make_tmpfs_fsmount());

        r = xopenat_full(host_fd1, ".", O_TMPFILE|O_RDWR, /* xopen_flags= */ 0, 0666);
        have_tmpfile = r >= 0;
        if (have_tmpfile)
                safe_close(r);
        else {
                ASSERT_ERROR(r, EOPNOTSUPP);
                log_notice("O_TMPFILE is not supported here, skipping host directory checks.");
        }

        /* The client cannot create a file in the host directory for the whiteout check. */
        safe_close(ASSERT_OK(xopenat_full(host_fd1, "white", O_CREAT|O_EXCL|O_WRONLY, /* xopen_flags= */ 0, 0644)));

        _cleanup_free_ char *idmap = NULL;
        ASSERT_OK(asprintf(&idmap, "0 "UID_FMT" 1", CONTAINER_UID_MIN));
        userns_fd = ASSERT_OK(userns_acquire(idmap, idmap, /* setgroups_deny= */ true));

        idmapped_tmpfs = ASSERT_OK(make_idmapped_tmpfs_fsmount(userns_fd));

        registered = register_userns(userns_fd);

        r = ASSERT_OK(pidref_safe_fork("(test)", FORK_DEATHSIG_SIGKILL, &pidref));
        if (r == 0) {
                _cleanup_close_ int private_tmpfs = -EBADF;

                ASSERT_OK(namespace_enter(-EBADF, -EBADF, -EBADF, userns_fd, -EBADF));
                ASSERT_OK_ERRNO(unshare(CLONE_NEWNS));

                /* Allocate tmpfs locally, i.e. a file system that dies together with our user namespace */
                private_tmpfs = make_tmpfs_fsmount();

                /* These two host mounts would record our transient UID on disk, hence are inaccessible */
                ASSERT_ERROR(xopenat_full(host_fd1, "test", O_RDWR|O_CREAT,
                                          /* xopen_flags= */ 0, 0666), EPERM);
                ASSERT_ERROR(xopenat_full(host_tmpfs, "xxx", O_RDWR|O_CREAT,
                                          /* xopen_flags= */ 0, 0666), EPERM);
                ASSERT_ERROR_ERRNO(mkdirat(host_fd1, "test2", 0666), EPERM);
                ASSERT_ERROR_ERRNO(mkdirat(host_tmpfs, "xxx2", 0666), EPERM);
                ASSERT_ERROR_ERRNO(symlinkat("target", host_fd1, "symlink"), EPERM);
                ASSERT_ERROR_ERRNO(mkfifoat(host_fd1, "fifo", 0600), EPERM);
                ASSERT_ERROR_ERRNO(linkat(host_fd1, "source", host_fd1, "link", 0), EPERM);

                ASSERT_OK_ERRNO(renameat(host_fd1, "source", host_fd1, "renamed"));
                ASSERT_OK_ERRNO(unlinkat(host_fd1, "renamed", 0));
                ASSERT_OK_ERRNO(unlinkat(host_fd1, "empty", AT_REMOVEDIR));

                ASSERT_OK_ERRNO(fchmod(host_fd1, 0700));

                /* But this mount created locally should be fine */
                safe_close(ASSERT_OK(xopenat_full(private_tmpfs, "yyy", O_RDWR|O_CREAT,
                                                  /* xopen_flags= */ 0, 0666)));
                ASSERT_OK_ERRNO(mkdirat(private_tmpfs, "yyy2", 0666));
                ASSERT_OK_ERRNO(symlinkat("yyy", private_tmpfs, "symlink"));
                ASSERT_OK_ERRNO(mkfifoat(private_tmpfs, "fifo", 0600));
                ASSERT_OK_ERRNO(linkat(private_tmpfs, "yyy", private_tmpfs, "link", 0));

                /* And so should the idmapped host mount: it translates our transient UID to UID 0 before
                 * anything reaches the disk */
                safe_close(ASSERT_OK(xopenat_full(idmapped_tmpfs, "zzz", O_RDWR|O_CREAT,
                                                  /* xopen_flags= */ 0, 0666)));
                ASSERT_OK_ERRNO(mkdirat(idmapped_tmpfs, "zzz2", 0666));
                ASSERT_OK_ERRNO(symlinkat("zzz", idmapped_tmpfs, "symlink"));
                ASSERT_OK_ERRNO(mkfifoat(idmapped_tmpfs, "fifo", 0600));
                ASSERT_OK_ERRNO(linkat(idmapped_tmpfs, "zzz", idmapped_tmpfs, "link", 0));

                /* Giving the host directory our transient GID would persist ownership after the namespace exits. */
                ASSERT_ERROR_ERRNO(fchownat(host_fd1, "", GID_INVALID, 0, AT_EMPTY_PATH), EPERM);

                ASSERT_OK_ERRNO(fchownat(private_tmpfs, "yyy", GID_INVALID, 0, 0));
                ASSERT_OK_ERRNO(fchownat(idmapped_tmpfs, "zzz", GID_INVALID, 0, 0));

                if (have_tmpfile) {
                        ASSERT_ERROR(xopenat_full(host_fd1, ".", O_TMPFILE|O_RDWR, /* xopen_flags= */ 0, 0666), EPERM);
                        ASSERT_ERROR(xopenat_full(host_fd1, ".", O_TMPFILE|O_EXCL|O_RDWR, /* xopen_flags= */ 0, 0666), EPERM);
                }
                ASSERT_ERROR(xopenat_full(host_tmpfs, ".", O_TMPFILE|O_RDWR, /* xopen_flags= */ 0, 0666), EPERM);
                ASSERT_ERROR(xopenat_full(host_tmpfs, ".", O_TMPFILE|O_EXCL|O_RDWR, /* xopen_flags= */ 0, 0666), EPERM);

                _cleanup_close_ int tmpfile1 = -EBADF, tmpfile2 = -EBADF;
                tmpfile1 = ASSERT_OK(xopenat_full(private_tmpfs, ".", O_TMPFILE|O_RDWR, /* xopen_flags= */ 0, 0666));
                ASSERT_OK(link_fd(tmpfile1, private_tmpfs, "ccc"));
                tmpfile2 = ASSERT_OK(xopenat_full(idmapped_tmpfs, ".", O_TMPFILE|O_RDWR, /* xopen_flags= */ 0, 0666));
                ASSERT_OK(link_fd(tmpfile2, idmapped_tmpfs, "ddd"));

                safe_close(ASSERT_OK(xopenat_full(private_tmpfs, ".", O_TMPFILE|O_EXCL|O_RDWR, /* xopen_flags= */ 0, 0666)));
                safe_close(ASSERT_OK(xopenat_full(idmapped_tmpfs, ".", O_TMPFILE|O_EXCL|O_RDWR, /* xopen_flags= */ 0, 0666)));

                /* So is the whiteout RENAME_WHITEOUT leaves behind, which is owned by us too */
                ASSERT_ERROR_ERRNO(renameat2(host_fd1, "white", host_fd1, "white2", RENAME_WHITEOUT), EPERM);
                ASSERT_OK_ERRNO(renameat2(private_tmpfs, "ccc", private_tmpfs, "ccc2", RENAME_WHITEOUT));
                ASSERT_OK_ERRNO(renameat2(idmapped_tmpfs, "ddd", idmapped_tmpfs, "ddd2", RENAME_WHITEOUT));

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

                ASSERT_ERROR(xopenat_full(AT_FDCWD, p1, O_RDWR|O_CREAT, /* xopen_flags= */ 0, 0666), EPERM);
                ASSERT_ERROR_ERRNO(mkdir(p2, 0666), EPERM);
                ASSERT_ERROR(xopenat_full(host_fd1, "newns3", O_RDWR|O_CREAT,
                                          /* xopen_flags= */ 0, 0666), EPERM);
                ASSERT_ERROR(xopenat_full(host_tmpfs, "newns4", O_RDWR|O_CREAT,
                                          /* xopen_flags= */ 0, 0666), EPERM);
                if (have_tmpfile)
                        ASSERT_ERROR(xopenat_full(AT_FDCWD, t, O_TMPFILE|O_RDWR, /* xopen_flags= */ 0, 0666), EPERM);

                /* And chown() through the clone must stay refused too, not just inode creation. */
                ASSERT_ERROR_ERRNO(fchownat(AT_FDCWD, t, GID_INVALID, 0, 0), EPERM);

                /* Neither must nesting a user namespace, which is not in the managed map itself */
                ASSERT_OK_ERRNO(unshare(CLONE_NEWUSER));

                _cleanup_free_ char *p3 = NULL, *p4 = NULL;
                ASSERT_NOT_NULL(p3 = path_join(t, "newuser"));
                ASSERT_NOT_NULL(p4 = path_join(t, "newuser2"));

                ASSERT_ERROR(xopenat_full(AT_FDCWD, p3, O_RDWR|O_CREAT, /* xopen_flags= */ 0, 0666), EPERM);
                ASSERT_ERROR_ERRNO(mkdir(p4, 0666), EPERM);
                ASSERT_ERROR(xopenat_full(host_fd1, "newuser3", O_RDWR|O_CREAT,
                                          /* xopen_flags= */ 0, 0666), EPERM);
                ASSERT_ERROR(xopenat_full(host_tmpfs, "newuser4", O_RDWR|O_CREAT,
                                          /* xopen_flags= */ 0, 0666), EPERM);
                ASSERT_ERROR(xopenat_full(host_tmpfs, ".", O_TMPFILE|O_RDWR, /* xopen_flags= */ 0, 0666), EPERM);

                /* …while what was legitimately writable before stays writable */
                safe_close(ASSERT_OK(xopenat_full(private_tmpfs, "aaa", O_RDWR|O_CREAT,
                                                  /* xopen_flags= */ 0, 0666)));
                safe_close(ASSERT_OK(xopenat_full(idmapped_tmpfs, "bbb", O_RDWR|O_CREAT,
                                                  /* xopen_flags= */ 0, 0666)));

                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(pidref_wait_for_terminate_and_check("(test)", &pidref, WAIT_LOG));
}

TEST(userns_restrict_btrfs) {
        _cleanup_(rm_rf_subvolume_and_freep) char *t = NULL;
        _cleanup_close_ int dir_fd = -EBADF, host_fd = -EBADF, mapped_fd = -EBADF,
                             mount_fd = -EBADF, idmapped_fd = -EBADF, userns_fd = -EBADF,
                             tmpfs_mount = -EBADF, tmpfs_fd = -EBADF;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        _cleanup_free_ char *idmap = NULL;
        struct stat st;
        int r;

        ASSERT_OK(mkdtemp_malloc("/var/tmp/test-userns-restrict-btrfs.XXXXXX", &t));
        dir_fd = ASSERT_OK(xopenat(AT_FDCWD, t, O_DIRECTORY));
        if (ASSERT_OK(fd_is_fs_type(dir_fd, BTRFS_SUPER_MAGIC)) == 0)
                return (void) log_tests_skipped("Temporary directory is not on Btrfs");

        host_fd = ASSERT_OK(xopenat_full(dir_fd, "host", O_DIRECTORY|O_CREAT, /* xopen_flags= */ 0, 0700));
        mapped_fd = ASSERT_OK(xopenat_full(dir_fd, "mapped", O_DIRECTORY|O_CREAT, /* xopen_flags= */ 0, 0700));
        ASSERT_OK_ERRNO(fchown(host_fd, CONTAINER_UID_MIN, CONTAINER_UID_MIN));

        ASSERT_OK(btrfs_subvol_make(host_fd, "probe"));
        ASSERT_OK(btrfs_subvol_remove_at(host_fd, "probe", /* flags= */ 0));

        ASSERT_OK(asprintf(&idmap, "0 "UID_FMT" 1", CONTAINER_UID_MIN));
        userns_fd = ASSERT_OK(userns_acquire(idmap, idmap, /* setgroups_deny= */ true));

        mount_fd = ASSERT_OK_ERRNO(open_tree(mapped_fd, "", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH));
        ASSERT_OK_ERRNO(mount_setattr(mount_fd, "", AT_EMPTY_PATH,
                                      &(struct mount_attr) {
                                              .attr_set = MOUNT_ATTR_IDMAP,
                                              .userns_fd = userns_fd,
                                      }, sizeof(struct mount_attr)));
        idmapped_fd = ASSERT_OK(xopenat(mount_fd, ".", O_DIRECTORY));

        tmpfs_mount = ASSERT_OK(make_tmpfs_fsmount());
        tmpfs_fd = ASSERT_OK(xopenat(tmpfs_mount, ".", O_DIRECTORY));

        ASSERT_OK(userns_restrict_register_by_fd(bpf_obj, userns_fd));

        r = ASSERT_OK(pidref_safe_fork("(btrfs)", FORK_DEATHSIG_SIGKILL, &pidref));
        if (r == 0) {
                struct btrfs_ioctl_vol_args legacy = { .name = "legacy" };
                struct btrfs_ioctl_vol_args_v2 modern = { .name = "modern" };
                struct btrfs_ioctl_fs_info_args info = {};

                ASSERT_OK(namespace_enter(-EBADF, -EBADF, -EBADF, userns_fd, -EBADF));
                ASSERT_OK_ERRNO(unshare(CLONE_NEWNS));

                ASSERT_ERROR_ERRNO(ioctl(host_fd, BTRFS_IOC_SUBVOL_CREATE, &legacy), EPERM);
                ASSERT_ERROR_ERRNO(ioctl(host_fd, BTRFS_IOC_SUBVOL_CREATE_V2, &modern), EPERM);
                ASSERT_OK_ERRNO(ioctl(idmapped_fd, BTRFS_IOC_SUBVOL_CREATE, &legacy));
                ASSERT_OK_ERRNO(ioctl(idmapped_fd, BTRFS_IOC_SUBVOL_CREATE_V2, &modern));
                ASSERT_OK_ERRNO(ioctl(host_fd, BTRFS_IOC_FS_INFO, &info));

                ASSERT_ERROR_ERRNO(ioctl(tmpfs_fd, BTRFS_IOC_SUBVOL_CREATE, &legacy), ENOTTY);
                ASSERT_ERROR_ERRNO(ioctl(tmpfs_fd, BTRFS_IOC_SUBVOL_CREATE_V2, &modern), ENOTTY);

                ASSERT_OK_ERRNO(unshare(CLONE_NEWUSER));
                ASSERT_ERROR_ERRNO(ioctl(host_fd, BTRFS_IOC_SUBVOL_CREATE, &legacy), EPERM);
                ASSERT_ERROR_ERRNO(ioctl(host_fd, BTRFS_IOC_SUBVOL_CREATE_V2, &modern), EPERM);

                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(pidref_wait_for_terminate_and_check("(btrfs)", &pidref, WAIT_LOG));

        FOREACH_STRING(name, "legacy", "modern") {
                ASSERT_OK_ERRNO(fstatat(mapped_fd, name, &st, 0));
                ASSERT_EQ(st.st_uid, 0U);
                ASSERT_EQ(st.st_gid, 0U);
        }

        ASSERT_OK_ERRNO(fstat(userns_fd, &st));
        ASSERT_OK(userns_restrict_reset_by_inode(bpf_obj, st.st_ino));
}

TEST(userns_restrict_link_owner) {
        _cleanup_(unregister_userns) uint64_t registered = 0;
        _cleanup_close_ int userns_fd = -EBADF, host_tmpfs = -EBADF;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        _cleanup_free_ char *idmap = NULL;
        int r;

        if (!inode_hooks)
                return (void) log_tests_skipped("Inode LSM hooks with mount idmaps are not supported");

        host_tmpfs = ASSERT_OK(make_tmpfs_fsmount());

        /* The client links this file below. The file is owned by the client's transient ID, and its mode
         * keeps fs.protected_hardlinks=1 from refusing the link before the BPF-LSM runs. */
        safe_close(ASSERT_OK(xopenat_full(host_tmpfs, "file", O_CREAT|O_EXCL|O_WRONLY, /* xopen_flags= */ 0, 0666)));
        ASSERT_OK_ERRNO(fchmodat(host_tmpfs, "file", 0666, 0));
        ASSERT_OK_ERRNO(fchownat(host_tmpfs, "file", CONTAINER_UID_MIN, CONTAINER_UID_MIN, 0));

        /* ID 1 maps to a foreign ID, which is not transient. The client switches its fsuid and fsgid to it
         * before it adds the link. */
        ASSERT_OK(asprintf(&idmap, "0 "UID_FMT" 1\n1 "UID_FMT" 1", CONTAINER_UID_MIN, FOREIGN_UID_MIN));
        userns_fd = ASSERT_OK(userns_acquire(idmap, idmap, /* setgroups_deny= */ true));

        registered = register_userns(userns_fd);

        r = ASSERT_OK(pidref_safe_fork("(test-link)", FORK_DEATHSIG_SIGKILL, &pidref));
        if (r == 0) {
                ASSERT_OK(namespace_enter(-EBADF, -EBADF, -EBADF, userns_fd, -EBADF));

                /* A linkable O_TMPFILE would be owned by our transient ID, and any task that gets the file
                 * descriptor could link it. */
                ASSERT_ERROR(xopenat_full(host_tmpfs, ".", O_TMPFILE|O_RDWR, /* xopen_flags= */ 0, 0600), EPERM);

                (void) setfsgid(1);
                (void) setfsuid(1);
                ASSERT_EQ(setfsuid(UID_INVALID), 1);

                /* The file is owned by our transient ID, no matter which fsuid adds the link. */
                ASSERT_ERROR_ERRNO(linkat(host_tmpfs, "file", host_tmpfs, "link", 0), EPERM);

                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(pidref_wait_for_terminate_and_check("(test-link)", &pidref, WAIT_LOG));
}

TEST(userns_restrict_idmap_to_transient) {
        _cleanup_(unregister_userns) uint64_t registered = 0;
        _cleanup_close_ int userns_fd = -EBADF, idmap_fd = -EBADF, mntfd = -EBADF;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        _cleanup_free_ char *idmap = NULL;
        int r;

        userns_fd = ASSERT_OK(userns_acquire("0 0 1", "0 0 1", /* setgroups_deny= */ true));
        ASSERT_OK(asprintf(&idmap, UID_FMT" 0 1", CONTAINER_UID_MIN));
        idmap_fd = ASSERT_OK(userns_acquire(idmap, idmap, /* setgroups_deny= */ true));

        mntfd = ASSERT_OK(make_tmpfs_fsmount());
        ASSERT_OK_ERRNO(fchownat(mntfd, "", CONTAINER_UID_MIN, CONTAINER_UID_MIN, AT_EMPTY_PATH));
        ASSERT_OK_ERRNO(mount_setattr(mntfd, "", AT_EMPTY_PATH,
                                      &(struct mount_attr) {
                                              .attr_set = MOUNT_ATTR_IDMAP,
                                              .userns_fd = idmap_fd,
                                      }, sizeof(struct mount_attr)));

        registered = register_userns(userns_fd);
        r = ASSERT_OK(pidref_safe_fork("(test-idmap)", FORK_DEATHSIG_SIGKILL, &pidref));
        if (r == 0) {
                ASSERT_OK(namespace_enter(-EBADF, -EBADF, -EBADF, userns_fd, -EBADF));
                ASSERT_ERROR(xopenat_full(mntfd, "file", O_CREAT|O_WRONLY, /* xopen_flags= */ 0, 0600), EPERM);
                ASSERT_ERROR_ERRNO(mkdirat(mntfd, "dir", 0700), EPERM);
                ASSERT_ERROR_ERRNO(fchownat(mntfd, "", UID_INVALID, 0, AT_EMPTY_PATH), EPERM);
                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(pidref_wait_for_terminate_and_check("(test-idmap)", &pidref, WAIT_LOG));
}

static void assert_overlay_unwritable(const char *target, unsigned long flags, const char *options) {
        _cleanup_close_ int fd = -EBADF;

        if (!inode_hooks) {
                ASSERT_ERROR_ERRNO(mount("overlay", target, "overlay", flags, options), EPERM);
                return;
        }

        /* OverlayFS mounts read-only if an inode hook denies creating its work directory. */
        if (mount("overlay", target, "overlay", flags, options) < 0) {
                ASSERT_EQ(errno, EPERM);
                return;
        }

        fd = ASSERT_OK(xopenat(AT_FDCWD, target, O_RDONLY|O_DIRECTORY));
        ASSERT_ERROR(xopenat_full(fd, "file", O_CREAT|O_RDWR, /* xopen_flags= */ 0, 0600), EROFS);

        fd = safe_close(fd);
        ASSERT_OK_ERRNO(umount(target));
}

TEST(userns_restrict_overlayfs) {
        _cleanup_(unregister_userns) uint64_t registered = 0;
        _cleanup_close_ int userns_fd = -EBADF, idmapped_upper = -EBADF, bad_userns_fd = -EBADF,
                             bad_upper = -EBADF;
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL, *th = NULL, *ti = NULL, *tb = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        _cleanup_free_ char *idmap = NULL, *bad_idmap = NULL, *hlower = NULL, *hupper = NULL, *hwork = NULL,
                            *hmerged = NULL;
        int r;

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));
        ASSERT_OK_ERRNO(chown(t, CONTAINER_UID_MIN, CONTAINER_UID_MIN));

        ASSERT_OK(asprintf(&idmap, "0 "UID_FMT" 1", CONTAINER_UID_MIN));
        userns_fd = ASSERT_OK(userns_acquire(idmap, idmap, /* setgroups_deny= */ true));

        registered = register_userns(userns_fd);

        /* Set up the layer dirs for the refuse case on the init-owned file system backing our temporary dir,
         * i.e. one that outlives the user namespace. This has to happen here as root: the managed client
         * cannot create these itself, as the path hooks already block a transient-owned inode on a file
         * system that outlives it. */
        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &th));
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
        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &ti));
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
        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &tb));
        ASSERT_OK_ERRNO(move_mount(bad_upper, "", -EBADF, tb, MOVE_MOUNT_F_EMPTY_PATH));

        r = ASSERT_OK(pidref_safe_fork("(test-ovl)", FORK_DEATHSIG_SIGKILL, &pidref));
        if (r == 0) {
                ASSERT_OK(namespace_enter(-EBADF, -EBADF, -EBADF, userns_fd, -EBADF));
                ASSERT_OK_ERRNO(unshare(CLONE_NEWNS));
                ASSERT_OK_ERRNO(mount(/* source= */ NULL, "/", /* filesystemtype= */ NULL, MS_SLAVE|MS_REC, /* data= */ NULL));

                /* Hold the overlay layers on a tmpfs of our own, so nothing touches the host. */
                ASSERT_OK_ERRNO(mount("tmpfs", t, "tmpfs", /* mountflags= */ 0, /* data= */ NULL));

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
                ASSERT_OK_ERRNO(mount("overlay", merged, "overlay", /* mountflags= */ 0, rw_opts));

                /* A write through the overlay really lands on the upper (our tmpfs), which the path hooks
                 * never see directly. chown() over the merged mount reaches path_chown, which sees the
                 * overlay superblock (ours, so it dies with us) and allows it, even to a transient gid. */
                _cleanup_free_ char *f = NULL, *uf = NULL;
                ASSERT_NOT_NULL(f = path_join(merged, "f"));
                ASSERT_NOT_NULL(uf = path_join(upper, "f"));
                safe_close(ASSERT_OK(xopenat_full(AT_FDCWD, f, O_RDWR|O_CREAT, /* xopen_flags= */ 0, 0666)));
                ASSERT_OK_ERRNO(access(uf, F_OK));
                ASSERT_OK_ERRNO(fchownat(AT_FDCWD, f, UID_INVALID, 0, 0));

                ASSERT_OK_ERRNO(umount(merged));

                _cleanup_free_ char *bad_opts = NULL;
                ASSERT_NOT_NULL(bad_opts = strjoin("lowerdir=", hlower, ",upperdir=", hupper,
                                                   ",workdir=", hwork));
                assert_overlay_unwritable(hmerged, /* flags= */ 0, bad_opts);
                assert_overlay_unwritable(hmerged, MS_RDONLY, bad_opts);

                if (inode_hooks) {
                        _cleanup_free_ char *p = NULL;

                        ASSERT_NOT_NULL(p = path_join(hwork, "work"));
                        ASSERT_ERROR_ERRNO(access(p, F_OK), ENOENT);
                }

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
                ASSERT_OK_ERRNO(mount("overlay", merged, "overlay", /* mountflags= */ 0, idmapped_opts));
                safe_close(ASSERT_OK(xopenat_full(AT_FDCWD, f, O_RDWR|O_CREAT, /* xopen_flags= */ 0, 0600)));
                ASSERT_OK_ERRNO(fchownat(AT_FDCWD, f, UID_INVALID, 0, 0));
                ASSERT_OK_ERRNO(umount(merged));

                _cleanup_free_ char *bupper = NULL, *bwork = NULL, *bad_idmapped_opts = NULL;
                ASSERT_NOT_NULL(bupper = path_join(tb, "upper"));
                ASSERT_NOT_NULL(bwork = path_join(tb, "work"));
                ASSERT_NOT_NULL(bad_idmapped_opts = strjoin("lowerdir=", lower, ",upperdir=", bupper,
                                                            ",workdir=", bwork));
                assert_overlay_unwritable(merged, /* flags= */ 0, bad_idmapped_opts);

                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(pidref_wait_for_terminate_and_check("(test-ovl)", &pidref, WAIT_LOG));

        /* Detach the extra uppers we attached in our (initial) mount namespace before the temp dirs are
         * removed. */
        (void) umount(ti);
        (void) umount(tb);
}

TEST(userns_restrict_overlayfs_identity) {
        _cleanup_(unregister_userns) uint64_t registered = 0;
        _cleanup_close_ int userns_fd = -EBADF;
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        _cleanup_free_ char *lower = NULL, *upper = NULL, *work = NULL, *merged = NULL, *options = NULL;
        int r;

        if (!inode_hooks)
                return (void) log_tests_skipped("Inode LSM hooks with mount idmaps are not supported");

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));
        ASSERT_NOT_NULL(lower = path_join(t, "lower"));
        ASSERT_NOT_NULL(upper = path_join(t, "upper"));
        ASSERT_NOT_NULL(work = path_join(t, "work"));
        ASSERT_NOT_NULL(merged = path_join(t, "merged"));
        ASSERT_OK_ERRNO(mkdir(lower, 0755));
        ASSERT_OK_ERRNO(mkdir(upper, 0755));
        ASSERT_OK_ERRNO(mkdir(work, 0755));
        ASSERT_OK_ERRNO(mkdir(merged, 0755));
        ASSERT_NOT_NULL(options = strjoin("lowerdir=", lower, ",upperdir=", upper, ",workdir=", work));

        userns_fd = ASSERT_OK(userns_acquire("0 0 1", "0 0 1", /* setgroups_deny= */ true));
        registered = register_userns(userns_fd);

        r = ASSERT_OK(pidref_safe_fork("(test-ovl-id)", FORK_DEATHSIG_SIGKILL, &pidref));
        if (r == 0) {
                _cleanup_close_ int fd = -EBADF;

                ASSERT_OK(namespace_enter(-EBADF, -EBADF, -EBADF, userns_fd, -EBADF));
                ASSERT_OK_ERRNO(unshare(CLONE_NEWNS));
                ASSERT_OK_ERRNO(mount(/* source= */ NULL, "/", /* filesystemtype= */ NULL, MS_SLAVE|MS_REC, /* data= */ NULL));

                r = mount("overlay", merged, "overlay", /* mountflags= */ 0, options);
                if (r < 0 && errno != EPERM) {
                        log_tests_skipped_errno(errno, "OverlayFS upper is not supported");
                        _exit(EXIT_SUCCESS);
                }

                ASSERT_OK_ERRNO(r);
                fd = ASSERT_OK(xopenat(AT_FDCWD, merged, O_RDONLY|O_DIRECTORY));
                safe_close(ASSERT_OK(xopenat_full(fd, "file", O_CREAT|O_RDWR, /* xopen_flags= */ 0, 0600)));
                ASSERT_OK_ERRNO(mkdirat(fd, "dir", 0700));
                ASSERT_OK_ERRNO(symlinkat("file", fd, "symlink"));
                ASSERT_OK_ERRNO(mkfifoat(fd, "fifo", 0600));
                ASSERT_OK_ERRNO(linkat(fd, "file", fd, "link", 0));
                ASSERT_OK_ERRNO(fchownat(fd, "file", 0, 0, 0));

                fd = safe_close(fd);
                ASSERT_OK_ERRNO(umount(merged));
                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(pidref_wait_for_terminate_and_check("(test-ovl-id)", &pidref, WAIT_LOG));
}

TEST(userns_restrict_cgroupfs) {
        _cleanup_(unregister_userns) uint64_t registered = 0;
        _cleanup_close_ int userns_fd = -EBADF, undelegated_fd = -EBADF, delegated_fd = -EBADF;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        _cleanup_free_ char *cg = NULL, *undelegated = NULL, *delegated = NULL, *idmap = NULL;
        int r;

        if (cg_is_available() <= 0)
                return (void) log_tests_skipped("cgroupfs is not mounted");

        /* Shifted, as cg_create() and friends prefix what we return here with /sys/fs/cgroup, which in a
         * container without its own cgroup namespace is not where the unshifted path is rooted. */
        r = cg_pid_get_path_shifted(/* pid= */ 0, /* cached_root= */ NULL, &cg);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "Failed to determine our own cgroup");

        ASSERT_NOT_NULL(undelegated = path_join(cg, "test-userns-restrict"));
        ASSERT_NOT_NULL(delegated = path_join(undelegated, "delegated"));

        /* Always start clean, in case an earlier run failed halfway through */
        (void) cg_trim(undelegated, /* delete_root= */ true);

        r = cg_create(undelegated);
        if (ERRNO_IS_NEG_FS_WRITE_REFUSED(r) || r == -ENOENT)
                return (void) log_tests_skipped_errno(r, "Failed to create cgroup %s", undelegated);
        ASSERT_OK(r);

        ASSERT_OK(cg_create(delegated));

        undelegated_fd = ASSERT_OK(cg_path_open(undelegated));
        delegated_fd = ASSERT_OK(cg_path_open(delegated));

        /* Hand the inner cgroup to the transient range, the way AddControlGroupToUserNamespace() does. */
        ASSERT_OK_ERRNO(fchown(delegated_fd, CONTAINER_UID_MIN, CONTAINER_UID_MIN));

        ASSERT_OK(asprintf(&idmap, "0 "UID_FMT" 1", CONTAINER_UID_MIN));
        userns_fd = ASSERT_OK(userns_acquire(idmap, idmap, /* setgroups_deny= */ true));

        registered = register_userns(userns_fd);

        r = ASSERT_OK(pidref_safe_fork("(test-cgroup)", FORK_DEATHSIG_SIGKILL, &pidref));
        if (r == 0) {
                ASSERT_OK(namespace_enter(-EBADF, -EBADF, -EBADF, userns_fd, -EBADF));

                /* The delegated cgroup is owned by our transient range, so this must work. */
                ASSERT_OK_ERRNO(mkdirat(delegated_fd, "payload", 0755));
                /* chown() is subject to the same policy, and hence exempt here as well. */
                ASSERT_OK_ERRNO(fchownat(delegated_fd, "payload", UID_INVALID, 0, 0));
                /* Its parent is not ours, so we should get EACCES from DAC. */
                ASSERT_ERROR_ERRNO(mkdirat(undelegated_fd, "payload", 0755), EACCES);

                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(pidref_wait_for_terminate_and_check("(test-cgroup)", &pidref, WAIT_LOG));

        ASSERT_OK(cg_trim(undelegated, /* delete_root= */ true));
}

static void write_child_mappings(PidRef *child, int parent_userns_fd) {
        /* The kernel requires uid_map/gid_map to be written from the parent user namespace of the
         * target namespace. Fork a helper that joins the parent userns and writes the mappings from
         * there, mirroring what write_userns() does in nsresourcework.c. */
        int r;

        r = ASSERT_OK(pidref_safe_fork("(sd-write-map)", FORK_DEATHSIG_SIGKILL|FORK_WAIT|FORK_LOG, /* ret= */ NULL));
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
        _cleanup_(unregister_userns) uint64_t registered_deny = 0, registered_allow = 0;
        _cleanup_close_ int deny_userns_fd = -EBADF, allow_userns_fd = -EBADF,
                             afd = -EBADF, bfd = -EBADF;
        int r;

        _cleanup_free_ char *idmap = NULL;
        ASSERT_OK(asprintf(&idmap, "0 "UID_FMT" 1", CONTAINER_UID_MIN));

        /* Create a userns that will have setgroups() denied via BPF. We don't set setgroups_deny here
         * because that uses /proc/self/setgroups which is transitive and we want to test the BPF-LSM
         * denial specifically. */
        deny_userns_fd = ASSERT_OK(userns_acquire(idmap, idmap, /* setgroups_deny= */ false));

        registered_deny = register_userns(deny_userns_fd);
        ASSERT_OK(userns_restrict_setgroups_deny_by_fd(bpf_obj, deny_userns_fd));

        /* Create a userns that is managed but does NOT have setgroups() denied */
        allow_userns_fd = ASSERT_OK(userns_acquire(idmap, idmap, /* setgroups_deny= */ false));

        registered_allow = register_userns(allow_userns_fd);

        afd = ASSERT_OK_ERRNO(eventfd(0, EFD_CLOEXEC));
        bfd = ASSERT_OK_ERRNO(eventfd(0, EFD_CLOEXEC));

        /* Test 1: setgroups() should be denied in the deny userns, including after unsharing into a child
         * user namespace (the ancestor walk should find the deny entry). */
        {
                _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;

                r = ASSERT_OK(pidref_safe_fork("(test-deny)", FORK_LOG|FORK_DEATHSIG_SIGKILL, &pidref));
                if (r == 0) {
                        /* Entering must work even though the BPF LSM denies the setgroups() involved. */
                        ASSERT_OK(namespace_enter(-EBADF, -EBADF, -EBADF, deny_userns_fd, -EBADF));

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

static int ringbuf_userns_freed(void *userdata, void *data, size_t size) {
        unsigned *inode = ASSERT_PTR(userdata);

        ASSERT_EQ(size, sizeof(unsigned));
        if (unaligned_read_ne32(data) == *inode)
                *inode = 0;

        return 0;
}

TEST_RET(userns_mqueue_lifetime) {
        _cleanup_(pidref_done_sigkill_wait) PidRef supervisor = PIDREF_NULL, creator = PIDREF_NULL;
        _cleanup_(bpf_ring_buffer_freep) struct ring_buffer *rb = NULL;
        _cleanup_close_ int userns_fd = -EBADF;
        _cleanup_free_ char *idmap = NULL;
        struct stat userns_st, queue_st;
        const struct mq_attr attr = { .mq_maxmsg = 1, .mq_msgsize = 1 };
        mqd_t queue;
        unsigned inode;
        int r;

        /* A separate IPC namespace prevents failed assertions from leaving queues on the host. */
        r = ASSERT_OK(pidref_safe_fork("(test-mqueue)", FORK_DEATHSIG_SIGKILL, &supervisor));
        if (r > 0)
                return ASSERT_OK(pidref_wait_for_terminate_and_check("(test-mqueue)", &supervisor, WAIT_LOG));

        r = RET_NERRNO(unshare(CLONE_NEWIPC));
        if (ERRNO_IS_NEG_PRIVILEGE(r) || IN_SET(r, -EINVAL, -ENOSYS))
                _exit(log_tests_skipped_errno(r, "Cannot create an IPC namespace"));
        ASSERT_OK(r);

        queue = mq_open("/probe", O_CREAT|O_EXCL|O_RDONLY|O_CLOEXEC, 0600, &attr);
        if (queue < 0 && errno == ENOSYS)
                _exit(log_tests_skipped("POSIX message queues are not supported"));
        ASSERT_OK_ERRNO(queue);
        ASSERT_OK_ERRNO(mq_close(queue));
        ASSERT_OK_ERRNO(mq_unlink("/probe"));

        ASSERT_OK(asprintf(&idmap, "0 "UID_FMT" 1", CONTAINER_UID_MIN));
        userns_fd = ASSERT_OK(userns_acquire(idmap, idmap, /* setgroups_deny= */ true));
        ASSERT_OK_ERRNO(fstat(userns_fd, &userns_st));
        inode = 0;

        rb = sym_ring_buffer__new(sym_bpf_map__fd(bpf_obj->maps.userns_ringbuf), ringbuf_userns_freed, &inode, /* opts= */ NULL);
        ASSERT_NOT_NULL(rb);
        ASSERT_OK(sym_ring_buffer__poll(rb, /* timeout_ms= */ 0));
        inode = (unsigned) userns_st.st_ino;
        ASSERT_NE(inode, 0U);

        ASSERT_EQ(register_userns(userns_fd), userns_st.st_ino);

        r = ASSERT_OK(pidref_safe_fork("(mqueue-creator)", FORK_DEATHSIG_SIGKILL, &creator));
        if (r == 0) {
                ASSERT_OK(namespace_enter(-EBADF, -EBADF, -EBADF, userns_fd, -EBADF));
                userns_fd = safe_close(userns_fd);
                queue = ASSERT_OK_ERRNO(mq_open("/lifetime", O_CREAT|O_EXCL|O_RDONLY|O_CLOEXEC, 0600, &attr));
                ASSERT_OK_ERRNO(mq_close(queue));
                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(pidref_wait_for_terminate_and_check("(mqueue-creator)", &creator, WAIT_LOG));
        queue = ASSERT_OK_ERRNO(mq_open("/lifetime", O_RDONLY|O_CLOEXEC));
        ASSERT_OK_ERRNO(fstat(queue, &queue_st));
        ASSERT_EQ(queue_st.st_uid, CONTAINER_UID_MIN);
        ASSERT_EQ(queue_st.st_gid, CONTAINER_UID_MIN);
        ASSERT_OK_ERRNO(mq_close(queue));
        userns_fd = safe_close(userns_fd);

        /* The queue's ucounts reference must keep its creator's user namespace alive after the creator exits. */
        usec_t end = usec_add(now(CLOCK_MONOTONIC), USEC_PER_SEC);
        do {
                ASSERT_OK(sym_ring_buffer__poll(rb, 100));
                ASSERT_NE(inode, 0U);
        } while (now(CLOCK_MONOTONIC) < end);

        ASSERT_OK_ERRNO(mq_unlink("/lifetime"));

        /* The kernel frees user namespaces from a workqueue, so the notification arrives asynchronously. */
        end = usec_add(now(CLOCK_MONOTONIC), 30 * USEC_PER_SEC);
        while (inode != 0) {
                ASSERT_LT(now(CLOCK_MONOTONIC), end);
                ASSERT_OK(sym_ring_buffer__poll(rb, 100));
        }

        ASSERT_OK(userns_restrict_reset_by_inode(bpf_obj, userns_st.st_ino));
        _exit(EXIT_SUCCESS);
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
