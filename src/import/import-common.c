/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <sys/prctl.h>

#include "sd-event.h"

#include "capability-util.h"
#include "copy.h"
#include "dirent-util.h"
#include "dissect-image.h"
#include "fd-util.h"
#include "fs-util.h"
#include "import-common.h"
#include "libarchive-util.h"
#include "log.h"
#include "namespace-util.h"
#include "nsresource.h"
#include "os-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "selinux-util.h"
#include "stat-util.h"
#include "tar-util.h"
#include "tmpfile-util.h"

int import_fork_tar_x(int tree_fd, int userns_fd, PidRef *ret_pid) {
        int r;

        assert(tree_fd >= 0);
        assert(ret_pid);

        r = dlopen_libarchive();
        if (r < 0)
                return r;

        TarFlags flags = mac_selinux_use() ? TAR_SELINUX : 0;

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        if (pipe2(pipefd, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to create pipe for tar: %m");

        (void) fcntl(pipefd[0], F_SETPIPE_SZ, IMPORT_BUFFER_SIZE);

        r = pidref_safe_fork_full(
                        "tar-x",
                        /* stdio_fds= */ NULL,
                        (int[]) { tree_fd, pipefd[0], userns_fd }, userns_fd >= 0 ? 3 : 2,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_REOPEN_LOG,
                        ret_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                static const uint64_t retain =
                        (1ULL << CAP_CHOWN) |
                        (1ULL << CAP_FOWNER) |
                        (1ULL << CAP_FSETID) |
                        (1ULL << CAP_MKNOD) |
                        (1ULL << CAP_SETFCAP) |
                        (1ULL << CAP_DAC_OVERRIDE) |
                        (1ULL << CAP_DAC_READ_SEARCH);

                /* Child */

                if (userns_fd >= 0) {
                        r = detach_mount_namespace_userns(userns_fd);
                        if (r < 0) {
                                log_error_errno(r, "Failed to join user namespace: %m");
                                _exit(EXIT_FAILURE);
                        }
                }

                if (unshare(CLONE_NEWNET) < 0)
                        log_debug_errno(errno, "Failed to lock tar into network namespace, ignoring: %m");

                r = capability_bounding_set_drop(retain, true);
                if (r < 0)
                        log_debug_errno(r, "Failed to drop capabilities, ignoring: %m");

                if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
                        log_warning_errno(errno, "Failed to enable PR_SET_NO_NEW_PRIVS, ignoring: %m");

                if (tar_x(pipefd[0], tree_fd, flags) < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        return TAKE_FD(pipefd[1]);
}

int import_fork_tar_c(int tree_fd, int userns_fd, PidRef *ret_pid) {
        int r;

        assert(tree_fd >= 0);
        assert(ret_pid);

        r = dlopen_libarchive();
        if (r < 0)
                return r;

        TarFlags flags = mac_selinux_use() ? TAR_SELINUX : 0;

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        if (pipe2(pipefd, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to create pipe for tar: %m");

        (void) fcntl(pipefd[0], F_SETPIPE_SZ, IMPORT_BUFFER_SIZE);

        r = pidref_safe_fork_full(
                        "tar-c",
                        /* stdio_fds= */ NULL,
                        (int[]) { tree_fd, pipefd[1], userns_fd }, userns_fd >= 0 ? 3 : 2,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_REOPEN_LOG,
                        ret_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                static const uint64_t retain = (1ULL << CAP_DAC_OVERRIDE);

                /* Child */

                if (userns_fd >= 0) {
                        r = detach_mount_namespace_userns(userns_fd);
                        if (r < 0) {
                                log_error_errno(r, "Failed to join user namespace: %m");
                                _exit(EXIT_FAILURE);
                        }
                }

                if (unshare(CLONE_NEWNET) < 0)
                        log_debug_errno(errno, "Failed to lock tar into network namespace, ignoring: %m");

                r = capability_bounding_set_drop(retain, true);
                if (r < 0)
                        log_debug_errno(r, "Failed to drop capabilities, ignoring: %m");

                if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
                        log_warning_errno(errno, "Failed to enable PR_SET_NO_NEW_PRIVS, ignoring: %m");

                if (tar_c(tree_fd, pipefd[1], /* filename= */ NULL, flags) < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        return TAKE_FD(pipefd[0]);
}

int import_mangle_os_tree(const char *path) {
        _cleanup_free_ char *child = NULL, *t = NULL, *joined = NULL;
        _cleanup_closedir_ DIR *d = NULL, *cd = NULL;
        struct dirent *dent;
        struct stat st;
        int r;

        assert(path);

        /* Some tarballs contain a single top-level directory that contains the actual OS directory tree. Try to
         * recognize this, and move the tree one level up. */

        r = path_is_os_tree(path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether '%s' is an OS tree: %m", path);
        if (r > 0) {
                log_debug("Directory tree '%s' is a valid OS tree.", path);
                return 0;
        }

        log_debug("Directory tree '%s' is not recognizable as OS tree, checking whether to rearrange it.", path);

        d = opendir(path);
        if (!d)
                return log_error_errno(r, "Failed to open directory '%s': %m", path);

        errno = 0;
        dent = readdir_no_dot(d);
        if (!dent) {
                if (errno != 0)
                        return log_error_errno(errno, "Failed to iterate through directory '%s': %m", path);

                log_debug("Directory '%s' is empty, leaving it as it is.", path);
                return 0;
        }

        child = strdup(dent->d_name);
        if (!child)
                return log_oom();

        errno = 0;
        dent = readdir_no_dot(d);
        if (dent) {
                if (errno != 0)
                        return log_error_errno(errno, "Failed to iterate through directory '%s': %m", path);

                log_debug("Directory '%s' does not look like an OS tree, and has multiple children, leaving as it is.", path);
                return 0;
        }

        if (fstatat(dirfd(d), child, &st, AT_SYMLINK_NOFOLLOW) < 0)
                return log_debug_errno(errno, "Failed to stat file '%s/%s': %m", path, child);
        r = stat_verify_directory(&st);
        if (r < 0) {
                log_debug_errno(r, "Child '%s' of directory '%s' is not a directory, leaving things as they are.", child, path);
                return 0;
        }

        joined = path_join(path, child);
        if (!joined)
                return log_oom();
        r = path_is_os_tree(joined);
        if (r == -ENOTDIR) {
                log_debug("Directory '%s' does not look like an OS tree, and contains a single regular file only, leaving as it is.", path);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether '%s' is an OS tree: %m", joined);
        if (r == 0) {
                log_debug("Neither '%s' nor '%s' is a valid OS tree, leaving them as they are.", path, joined);
                return 0;
        }

        /* Nice, we have checked now:
         *
         * 1. The top-level directory does not qualify as OS tree
         * 1. The top-level directory only contains one item
         * 2. That item is a directory
         * 3. And that directory qualifies as OS tree
         *
         * Let's now rearrange things, moving everything in the inner directory one level up */

        cd = xopendirat(dirfd(d), child, O_NOFOLLOW);
        if (!cd)
                return log_error_errno(errno, "Can't open directory '%s': %m", joined);

        log_info("Rearranging '%s', moving OS tree one directory up.", joined);

        /* Let's rename the child to an unguessable name so that we can be sure all files contained in it can be
         * safely moved up and won't collide with the name. */
        r = tempfn_random(child, NULL, &t);
        if (r < 0)
                return log_oom();
        r = rename_noreplace(dirfd(d), child, dirfd(d), t);
        if (r < 0)
                return log_error_errno(r, "Unable to rename '%s' to '%s/%s': %m", joined, path, t);

        FOREACH_DIRENT_ALL(de, cd, return log_error_errno(errno, "Failed to iterate through directory '%s': %m", joined)) {
                if (dot_or_dot_dot(de->d_name))
                        continue;

                r = rename_noreplace(dirfd(cd), de->d_name, dirfd(d), de->d_name);
                if (r < 0)
                        return log_error_errno(r, "Unable to move '%s/%s/%s' to '%s/%s': %m", path, t, de->d_name, path, de->d_name);
        }

        if (unlinkat(dirfd(d), t, AT_REMOVEDIR) < 0)
                return log_error_errno(errno, "Failed to remove temporary directory '%s/%s': %m", path, t);

        r = futimens(dirfd(d), (struct timespec[2]) { st.st_atim, st.st_mtim });
        if (r < 0)
                log_debug_errno(r, "Failed to adjust top-level timestamps '%s', ignoring: %m", path);

        r = fchmod_and_chown(dirfd(d), st.st_mode, st.st_uid, st.st_gid);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust top-level directory mode/ownership '%s': %m", path);

        log_info("Successfully rearranged OS tree.");

        return 0;
}

bool import_validate_local(const char *name, ImportFlags flags) {

        /* By default we insist on a valid hostname for naming images. But optionally we relax that, in which
         * case it can be any path name */

        if (FLAGS_SET(flags, IMPORT_DIRECT))
                return path_is_valid(name);

        return image_name_is_valid(name);
}

static int interrupt_signal_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        log_notice("Transfer aborted.");
        sd_event_exit(sd_event_source_get_event(s), EINTR);
        return 0;
}

int import_allocate_event_with_signals(sd_event **ret) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        assert(ret);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        (void) sd_event_add_signal(event, NULL, SIGTERM|SD_EVENT_SIGNAL_PROCMASK, interrupt_signal_handler,  NULL);
        (void) sd_event_add_signal(event, NULL, SIGINT|SD_EVENT_SIGNAL_PROCMASK, interrupt_signal_handler, NULL);

        *ret = TAKE_PTR(event);
        return 0;
}

int import_make_foreign_userns(int *userns_fd) {
        assert(userns_fd);

        if (*userns_fd >= 0)
                return 0;

        *userns_fd = nsresource_allocate_userns(/* name= */ NULL, NSRESOURCE_UIDS_64K); /* allocate 64K users */
        if (*userns_fd < 0)
                return log_error_errno(*userns_fd, "Failed to allocate transient user namespace: %m");

        return 1;
}

int import_copy_foreign(
                int source_fd,
                int target_fd,
                int *userns_fd) {

        int r;

        assert(source_fd >= 0);
        assert(target_fd >= 0);
        assert(userns_fd);

        /* Copies dir referenced by source_fd into dir referenced by source_fd, moves to the specified userns
         * for that (allocated if needed), which should be foreign UID range */

        r = import_make_foreign_userns(userns_fd);
        if (r < 0)
                return r;

        r = safe_fork_full(
                        "copy-tree",
                        /* stdio_fds= */ NULL,
                        (int[]) { *userns_fd, source_fd, target_fd }, 3,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_REOPEN_LOG|FORK_WAIT,
                        /* ret_pid= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                r = namespace_enter(
                                /* pidns_fd= */ -EBADF,
                                /* mntns_fd= */ -EBADF,
                                /* netns_fd= */ -EBADF,
                                *userns_fd,
                                /* root_fd= */ -EBADF);
                if (r < 0) {
                        log_error_errno(r, "Failed to join user namespace: %m");
                        _exit(EXIT_FAILURE);
                }

                r = copy_tree_at(
                                source_fd, /* from= */ NULL,
                                target_fd, /* to = */ NULL,
                                /* override_uid= */ UID_INVALID,
                                /* override_gid= */ GID_INVALID,
                                COPY_REFLINK|COPY_HARDLINKS|COPY_MERGE_EMPTY|COPY_MERGE_APPLY_STAT|COPY_SAME_MOUNT|COPY_ALL_XATTRS,
                                /* denylist= */ NULL,
                                /* subvolumes= */ NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to copy tree: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        return 0;
}

int import_remove_tree_foreign(const char *path, int *userns_fd) {
        int r;

        assert(path);
        assert(userns_fd);

        r = import_make_foreign_userns(userns_fd);
        if (r < 0)
                return r;

        _cleanup_close_ int tree_fd = -EBADF;
        r = mountfsd_mount_directory(
                        path,
                        *userns_fd,
                        DISSECT_IMAGE_FOREIGN_UID,
                        &tree_fd);
        if (r < 0)
                return r;

        r = safe_fork_full(
                        "rm-tree",
                        /* stdio_fds= */ NULL,
                        (int[]) { *userns_fd, tree_fd }, 2,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_REOPEN_LOG|FORK_WAIT,
                        /* ret_pid= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                /* child */

                r = namespace_enter(
                                /* pidns_fd= */ -EBADF,
                                /* mntns_fd= */ -EBADF,
                                /* netns_fd= */ -EBADF,
                                *userns_fd,
                                /* root_fd= */ -EBADF);
                if (r < 0) {
                        log_error_errno(r, "Failed to join user namespace: %m");
                        _exit(EXIT_FAILURE);
                }

                _cleanup_close_ int dfd = fd_reopen(tree_fd, O_DIRECTORY|O_CLOEXEC);
                if (dfd < 0) {
                        log_error_errno(r, "Failed to reopen tree fd: %m");
                        _exit(EXIT_FAILURE);
                }

                r = rm_rf_children(dfd, REMOVE_PHYSICAL|REMOVE_SUBVOLUME|REMOVE_CHMOD, /* root_dev= */ NULL);
                if (r < 0)
                        log_warning_errno(r, "Failed to empty '%s' directory in foreign UID mode, ignoring: %m", path);

                _exit(EXIT_SUCCESS);
        }

        return 0;
}

int import_remove_tree(const char *path, int *userns_fd, ImportFlags flags) {
        int r;

        assert(path);
        assert(userns_fd);

        /* Try the userns dance first, to remove foreign UID range owned trees */
        if (FLAGS_SET(flags, IMPORT_FOREIGN_UID))
                (void) import_remove_tree_foreign(path, userns_fd);

        r = rm_rf(path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME|REMOVE_MISSING_OK|REMOVE_CHMOD);
        if (r < 0)
                return log_error_errno(r, "Failed to remove '%s': %m", path);

        return 0;
}
