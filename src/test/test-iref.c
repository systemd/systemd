/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "capability-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "iref.h"
#include "path-util.h"
#include "rm-rf.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

static void make_root(char **ret_tmpdir, IRef **ret_root) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL;

        ASSERT_OK(mkdtemp_malloc("/var/tmp/test-iref.XXXXXX", &tmpdir));
        ASSERT_OK(iref_open_root(tmpdir, IREF_PATH, &root));

        *ret_tmpdir = TAKE_PTR(tmpdir);
        *ret_root = TAKE_PTR(root);
}

static void make_host_dir(char **ret_tmpdir, IRef **ret_dir) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *dir = NULL;

        ASSERT_OK(mkdtemp_malloc("/var/tmp/test-iref.XXXXXX", &tmpdir));
        ASSERT_OK(iref_open(NULL, tmpdir, IREF_PATH, &dir));

        *ret_tmpdir = TAKE_PTR(tmpdir);
        *ret_dir = TAKE_PTR(dir);
}

static void touch_at(IRef *dir, const char *filename) {
        _cleanup_close_ int fd = xopenat(iref_fd(dir), filename, O_CREAT|O_WRONLY);
        ASSERT_OK(fd);
}

TEST(iref_relative_lookup_uses_fd) {
        /* A directory is renamed and replaced after its file is opened. Relative lookup and empty-path
         * reopen must still return the original inodes. Self-removal must remove the original file. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *dir = NULL, *file = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "dir", 0755));
        ASSERT_OK(write_string_file_at(iref_fd(root), "dir/file", "original", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(iref_open(root, "dir", IREF_PATH, &dir));
        ASSERT_OK(iref_open(dir, "file", IREF_PATH, &file));

        /* The replacement uses the same names but contains different inodes and file contents. */
        ASSERT_OK_ERRNO(renameat(iref_fd(root), "dir", iref_fd(root), "moved"));
        ASSERT_OK(iref_mkdir(root, "dir", 0755));
        ASSERT_OK(write_string_file_at(iref_fd(root), "dir/file", "replacement", WRITE_STRING_FILE_CREATE));

        /* Lookup must use the opened directory even though the reported path remains cached. */
        _cleanup_(iref_unrefp) IRef *opened = NULL, *parent = NULL, *self = NULL;
        _cleanup_free_ char *filename = NULL, *path = NULL;
        ASSERT_OK(iref_open(dir, "file", IREF_PATH, &opened));
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(iref_fd(opened), iref_fd(file)));
        ASSERT_STREQ(iref_path(opened), "/dir/file");
        ASSERT_OK(iref_open_parent(dir, "file", /* flags= */ 0, &parent, &filename));
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(iref_fd(parent), iref_fd(dir)));
        ASSERT_STREQ(filename, "file");
        ASSERT_OK(iref_chase(dir, "file", /* flags= */ 0, &path));
        ASSERT_STREQ(path, "/dir/file");

        _cleanup_fclose_ FILE *stream = NULL;
        _cleanup_free_ char *line = NULL;
        ASSERT_OK(iref_fopen_unlocked(dir, "file", IREF_REGULAR, "re", &stream));
        ASSERT_OK_POSITIVE(read_line(stream, LONG_LINE_MAX, &line));
        ASSERT_STREQ(line, "original");

        /* Empty-path reopen must retain the parent used for self-removal. */
        ASSERT_OK(iref_open(file, "", IREF_REGULAR, &self));
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(iref_fd(self), iref_fd(file)));
        ASSERT_OK(iref_unlink(self, /* filename= */ NULL, /* flags= */ 0));
        ASSERT_ERROR(iref_access(dir, "file", F_OK), ENOENT);
        ASSERT_OK(iref_access(root, "dir", F_OK));
        ASSERT_OK(iref_chase(root, "dir/file", /* flags= */ 0, /* ret= */ NULL));
}

TEST(iref_parent_after_ancestor_rename) {
        /* A temporary root contains a file, a symlink, and a directory below an ancestor that is moved
         * and replaced. Parent lookup and self-operations must use the original containing directory.
         * A self-rename must retain the destination parent if that directory is moved afterwards. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *file = NULL, *link = NULL, *dir = NULL, *destination = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "ancestor", 0755));
        ASSERT_OK_ERRNO(mkdirat(iref_fd(root), "ancestor/parent", 0755));
        touch_at(root, "ancestor/parent/file");
        ASSERT_OK_ERRNO(symlinkat("file", iref_fd(root), "ancestor/parent/link"));
        ASSERT_OK_ERRNO(mkdirat(iref_fd(root), "ancestor/parent/dir", 0755));
        ASSERT_OK_ERRNO(symlinkat("/ancestor/parent/file", iref_fd(root), "alias"));
        ASSERT_OK(iref_open(root, "alias", IREF_PATH, &file));
        ASSERT_OK(iref_open(root, "ancestor/parent/link", IREF_NOFOLLOW|IREF_PATH, &link));
        ASSERT_OK(iref_open(root, "ancestor/parent/dir", IREF_PATH, &dir));

        /* The original cached paths now refer to replacements. */
        ASSERT_OK_ERRNO(renameat(iref_fd(root), "ancestor", iref_fd(root), "moved"));
        ASSERT_OK(iref_mkdir(root, "ancestor", 0755));
        ASSERT_OK_ERRNO(mkdirat(iref_fd(root), "ancestor/parent", 0755));
        touch_at(root, "ancestor/parent/file");
        ASSERT_OK_ERRNO(symlinkat("file", iref_fd(root), "ancestor/parent/link"));
        ASSERT_OK_ERRNO(mkdirat(iref_fd(root), "ancestor/parent/dir", 0755));

        _cleanup_(iref_unrefp) IRef *moved = NULL;
        ASSERT_OK(iref_open(root, "moved/parent", IREF_PATH, &moved));
        IRef *entries[] = { file, link, dir };
        FOREACH_ELEMENT(entry, entries) {
                _cleanup_(iref_unrefp) IRef *parent = NULL, *opened_parent = NULL;
                _cleanup_free_ char *filename = NULL, *opened_filename = NULL;

                ASSERT_OK(iref_parent_full(*entry, &parent, &filename));
                ASSERT_OK_POSITIVE(fds_inode_and_mount_same(iref_fd(parent), iref_fd(moved)));
                ASSERT_STREQ(filename, last_path_component(iref_path(*entry)));
                ASSERT_OK(iref_open_parent(*entry, "", /* flags= */ 0, &opened_parent, &opened_filename));
                ASSERT_OK_POSITIVE(fds_inode_and_mount_same(iref_fd(opened_parent), iref_fd(moved)));
                ASSERT_STREQ(opened_filename, filename);
        }

        /* Renaming or removing the original entries must leave the replacements in place. */
        ASSERT_OK(iref_mkdir(root, "destination", 0755));
        ASSERT_OK(iref_open(root, "destination", IREF_PATH, &destination));
        ASSERT_OK(iref_rename(file, /* from_name= */ NULL, destination, "renamed", /* flags= */ 0));
        ASSERT_OK(iref_unlink(link, /* filename= */ NULL, /* flags= */ 0));
        ASSERT_OK(iref_unlink(dir, /* filename= */ NULL, AT_REMOVEDIR));
        FOREACH_STRING(name, "file", "link", "dir") {
                ASSERT_ERROR(iref_access(moved, name, F_OK), ENOENT);
                _cleanup_free_ char *replacement = ASSERT_PTR(path_join("ancestor/parent", name));
                ASSERT_OK(iref_chase(root, replacement, IREF_NOFOLLOW, /* ret= */ NULL));
        }

        /* The renamed file must use its destination parent after the destination path is replaced. */
        ASSERT_OK_ERRNO(renameat(iref_fd(root), "destination", iref_fd(root), "destination-moved"));
        ASSERT_OK(iref_mkdir(root, "destination", 0755));
        touch_at(root, "destination/renamed");
        ASSERT_OK(iref_unlink(file, /* filename= */ NULL, /* flags= */ 0));
        ASSERT_ERROR(iref_access(destination, "renamed", F_OK), ENOENT);
        ASSERT_OK(iref_chase(root, "destination/renamed", /* flags= */ 0, /* ret= */ NULL));
}

TEST(iref_directory_parent_after_move) {
        /* A directory is moved to another parent without changing its basename. Parent lookup and
         * self-rename must open its current parent rather than use the old path or a cached parent.
         * Self-removal after the rename must use the updated basename. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *dir = NULL, *parent = NULL, *destination = NULL;
        _cleanup_free_ char *filename = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "source", 0755));
        ASSERT_OK_ERRNO(mkdirat(iref_fd(root), "source/dir", 0755));
        ASSERT_OK(iref_mkdir(root, "destination", 0755));
        ASSERT_OK(iref_open(root, "source/dir", IREF_PATH, &dir));
        ASSERT_OK(iref_open(root, "destination", IREF_PATH, &destination));

        ASSERT_OK_ERRNO(renameat(iref_fd(root), "source/dir", iref_fd(destination), "dir"));
        ASSERT_OK_ERRNO(mkdirat(iref_fd(root), "source/dir", 0755));
        ASSERT_OK(iref_parent_full(dir, &parent, &filename));
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(iref_fd(parent), iref_fd(destination)));
        ASSERT_STREQ(filename, "dir");
        ASSERT_OK(iref_rename(dir, /* from_name= */ NULL, destination, "renamed", /* flags= */ 0));
        ASSERT_OK(iref_access(destination, "renamed", F_OK));
        ASSERT_OK(iref_unlink(dir, /* filename= */ NULL, AT_REMOVEDIR));
        ASSERT_ERROR(iref_access(destination, "dir", F_OK), ENOENT);
        ASSERT_ERROR(iref_access(destination, "renamed", F_OK), ENOENT);
        ASSERT_OK(iref_chase(root, "source/dir", /* flags= */ 0, /* ret= */ NULL));
}

TEST(iref_paths_are_normalized) {
        /* A temporary root contains a directory, a symlink to it, and a regular file. Reported paths
         * must omit trailing slashes. An input ending in a slash must still require a directory during
         * a chase lookup. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL;
        static const struct {
                const char *path;
                const char *expected;
                const char *filename;
        } cases[] = {
                { "sub///",  "/sub", "sub" },
                { "link/",   "/sub", "sub" },
                { "/",       "/",    "."   },
                { ".",       "/",    "."   },
                { "sub/../", "/",    "."   },
        };

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK_ERRNO(symlinkat("/sub", iref_fd(root), "link"));
        touch_at(root, "file");

        FOREACH_ELEMENT(c, cases) {
                _cleanup_(iref_unrefp) IRef *opened = NULL, *parent = NULL;
                _cleanup_free_ char *path = NULL, *filename = NULL;

                ASSERT_OK(iref_chase(root, c->path, /* flags= */ 0, &path));
                ASSERT_STREQ(path, c->expected);
                ASSERT_OK(iref_open(root, c->path, IREF_PATH|IREF_DIRECTORY, &opened));
                ASSERT_STREQ(iref_path(opened), c->expected);
                ASSERT_OK(iref_open_parent(root, c->path, /* flags= */ 0, &parent, &filename));
                ASSERT_STREQ(iref_path(parent), "/");
                ASSERT_STREQ(filename, c->filename);
                ASSERT_OK_POSITIVE(fds_inode_and_mount_same(iref_fd(parent), iref_fd(root)));
        }

        /* A trailing slash in the input requires a directory. */
        ASSERT_ERROR(iref_chase(root, "file/", /* flags= */ 0, /* ret= */ NULL), ENOTDIR);
}

TEST(iref_open_parent) {
        /* When /etc/os-release is accessible, parent lookup without a configured root must return an
         * absolute parent path and the filename. The filename output must also be optional. */
        _cleanup_(iref_unrefp) IRef *parent = NULL;
        _cleanup_free_ char *fname = NULL;

        if (iref_open_parent(NULL, "/etc/os-release", /* flags= */ 0, &parent, &fname) < 0)
                return (void) log_tests_skipped("/etc/os-release not accessible");

        ASSERT_TRUE(path_is_absolute(iref_path(parent)));
        ASSERT_STREQ(fname, "os-release");

        _cleanup_(iref_unrefp) IRef *parent2 = NULL;
        ASSERT_OK(iref_open_parent(NULL, "/etc/os-release", /* flags= */ 0, &parent2, /* ret_filename= */ NULL));
}

TEST(iref_open_parent_relative) {
        /* A temporary host directory contains sub/. Looking up sub/file must return sub's inode and
         * the filename "file" even though the file does not exist. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *dir = NULL, *parent = NULL;
        _cleanup_free_ char *fname = NULL;

        make_host_dir(&tmpdir, &dir);

        ASSERT_OK(iref_mkdir(dir, "sub", 0755));
        ASSERT_OK(iref_open_parent(dir, "sub/file", /* flags= */ 0, &parent, &fname));
        ASSERT_STREQ(fname, "file");

        struct stat a, b;
        _cleanup_(iref_unrefp) IRef *sub = NULL;
        ASSERT_OK(iref_open(dir, "sub", IREF_PATH, &sub));
        ASSERT_OK(iref_stat(parent, &a));
        ASSERT_OK(iref_stat(sub, &b));
        ASSERT_EQ(a.st_ino, b.st_ino);
}

TEST(iref_open_parent_mkdir) {
        /* In an empty temporary root, IREF_MKDIR_0755 must create /etc/kernel during parent lookup and
         * leave cmdline absent. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *parent = NULL;
        _cleanup_free_ char *fname = NULL;
        struct stat st;

        make_root(&tmpdir, &root);

        ASSERT_OK(iref_open_parent(root, "/etc/kernel/cmdline", IREF_MKDIR_0755, &parent, &fname));
        ASSERT_STREQ(iref_path(parent), "/etc/kernel");
        ASSERT_STREQ(fname, "cmdline");
        ASSERT_OK_ERRNO(fstatat(iref_fd(root), "etc/kernel", &st, 0));
        ASSERT_TRUE(S_ISDIR(st.st_mode));
        ASSERT_ERROR_ERRNO(fstatat(iref_fd(root), "etc/kernel/cmdline", &st, 0), ENOENT);
}

TEST(iref_open_mkdir) {
        /* In an empty temporary root, lookup and creation flags must create /boot/token/1.0 once.
         * Creating the root or a symlink resolving to it must fail with EISDIR. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *dir = NULL, *again = NULL, *bad = NULL;
        struct stat st;

        make_root(&tmpdir, &root);

        ASSERT_OK(iref_open(root, "/boot/token/1.0", IREF_MKDIR_0755|IREF_CREAT|IREF_DIRECTORY|IREF_PATH, &dir));
        ASSERT_STREQ(iref_path(dir), "/boot/token/1.0");
        ASSERT_OK(iref_stat(dir, &st));
        ASSERT_TRUE(S_ISDIR(st.st_mode));
        ASSERT_OK(iref_open(root, "/boot/token/1.0", IREF_MKDIR_0755|IREF_CREAT|IREF_DIRECTORY|IREF_PATH, &again));
        ASSERT_OK_POSITIVE(fd_inode_same(iref_fd(dir), iref_fd(again)));

        ASSERT_OK_ERRNO(symlinkat("/", iref_fd(root), "up"));
        ASSERT_ERROR(iref_open(root, "/up", IREF_CREAT|IREF_DIRECTORY|IREF_PATH, &bad), EISDIR);
        ASSERT_ERROR(iref_open(root, "/", IREF_CREAT|IREF_DIRECTORY|IREF_PATH, &bad), EISDIR);
}

TEST(iref_open_create_flags) {
        /* A temporary root contains no entries. Creation must honor the requested inode type, create
         * missing parents when requested, reject an existing entry with O_EXCL, and reopen it otherwise. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL;

        make_root(&tmpdir, &root);

        static const struct {
                const char *path;
                IRefFlags flags;
                mode_t type;
        } cases[] = {
                { "file",     IREF_REGULAR|IREF_WRONLY,                S_IFREG },
                { "dir",      IREF_DIRECTORY|IREF_PATH,                S_IFDIR },
                { "sub/file", IREF_MKDIR_0755|IREF_REGULAR|IREF_WRONLY, S_IFREG },
                { "sub/dir",  IREF_MKDIR_0755|IREF_DIRECTORY|IREF_PATH, S_IFDIR },
        };

        FOREACH_ELEMENT(c, cases) {
                _cleanup_(iref_unrefp) IRef *created = NULL, *again = NULL;
                _cleanup_free_ char *path = ASSERT_PTR(path_join("/", c->path));
                struct stat st;

                ASSERT_OK(iref_open(root, c->path, c->flags|IREF_CREAT|IREF_EXCL, &created));
                ASSERT_STREQ(iref_path(created), path);
                ASSERT_OK(iref_stat(created, &st));
                ASSERT_EQ(st.st_mode & S_IFMT, c->type);
                ASSERT_TRUE(FLAGS_SET(ASSERT_OK_ERRNO(fcntl(iref_fd(created), F_GETFD)), FD_CLOEXEC));

                /* An exclusive open must fail without replacing the inode. */
                ASSERT_ERROR(iref_open(root, c->path, c->flags|IREF_CREAT|IREF_EXCL, &again), EEXIST);
                ASSERT_NULL(again);
                ASSERT_OK(iref_open(root, c->path, c->flags|IREF_CREAT, &again));
                ASSERT_OK_POSITIVE(fds_inode_and_mount_same(iref_fd(created), iref_fd(again)));
        }
}

TEST(iref_open_xopen_flags) {
        /* A regular file in a temporary root must open read/write with IREF_AUTO_RW_RO, including when
         * reopening its pinned inode. Read-only permissions must make an unprivileged open fall back to reading. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *file = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_open(root, "file", IREF_CREAT|IREF_EXCL|IREF_REGULAR|IREF_AUTO_RW_RO, &file));
        ASSERT_EQ(ASSERT_OK_ERRNO(fcntl(iref_fd(file), F_GETFL)) & O_ACCMODE, O_RDWR);

        _cleanup_(iref_unrefp) IRef *reopened = NULL;
        ASSERT_OK(iref_open(file, "", IREF_REGULAR|IREF_AUTO_RW_RO, &reopened));
        ASSERT_EQ(ASSERT_OK_ERRNO(fcntl(iref_fd(reopened), F_GETFL)) & O_ACCMODE, O_RDWR);
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(iref_fd(file), iref_fd(reopened)));

        /* CAP_DAC_OVERRIDE bypasses the mode bits, so only a process without it can check the fallback. */
        if (have_effective_cap(CAP_DAC_OVERRIDE) <= 0) {
                ASSERT_OK_ERRNO(fchmod(iref_fd(file), 0444));
                const struct {
                        IRef *base;
                        const char *path;
                } cases[] = {
                        { root, "file" },
                        { file, ""     },
                };

                FOREACH_ELEMENT(c, cases) {
                        _cleanup_(iref_unrefp) IRef *readonly = NULL;

                        ASSERT_OK(iref_open(c->base, c->path, IREF_REGULAR|IREF_AUTO_RW_RO, &readonly));
                        ASSERT_EQ(ASSERT_OK_ERRNO(fcntl(iref_fd(readonly), F_GETFL)) & O_ACCMODE, O_RDONLY);
                }
        }
}

TEST(iref_open_socket) {
        /* A temporary root contains a bound Unix socket and a regular file. IREF_SOCKET must pin the
         * socket with IREF_PATH, preserve it on empty-path reopen, and reject the regular file. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *socket_ref = NULL, *reopened = NULL, *bad = NULL;
        _cleanup_close_ int socket_fd = -EBADF;
        union sockaddr_union sa;

        make_root(&tmpdir, &root);
        touch_at(root, "file");
        _cleanup_free_ char *path = ASSERT_PTR(path_join(tmpdir, "socket"));
        socket_fd = ASSERT_OK_ERRNO(socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, /* protocol= */ 0));
        ASSERT_OK(sockaddr_un_set_path(&sa.un, path));
        ASSERT_OK_ERRNO(bind(socket_fd, &sa.sa, sockaddr_un_len(&sa.un)));

        ASSERT_OK(iref_open(root, "socket", IREF_PATH|IREF_SOCKET, &socket_ref));
        ASSERT_OK(iref_open(socket_ref, "", IREF_PATH|IREF_SOCKET, &reopened));
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(iref_fd(socket_ref), iref_fd(reopened)));
        ASSERT_ERROR(iref_open(root, "file", IREF_PATH|IREF_SOCKET, &bad), ENOTSOCK);
        ASSERT_ERROR(iref_open(root, "socket", IREF_PATH|IREF_REGULAR, &bad), EBADFD);
}

TEST(iref_refcount) {
        /* A child keeps its root alive after the caller releases the root reference. Create a child,
         * release the root, and check that parent lookup and reopening the child still work. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *child = NULL;

        make_root(&tmpdir, &root);

        IRef *ref = iref_ref(root);
        ASSERT_PTR_EQ(ref, root);
        ref = iref_unref(ref);
        ASSERT_NULL(ref);

        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK(iref_open(root, "sub", IREF_PATH, &child));
        root = iref_unref(root);

        _cleanup_(iref_unrefp) IRef *parent = NULL;
        ASSERT_OK(iref_parent(child, &parent));
        ASSERT_STREQ(iref_path(parent), "/");
        ASSERT_STREQ(iref_root_path(child), tmpdir);
        child = iref_unref(child);

        _cleanup_(iref_unrefp) IRef *again = NULL;
        ASSERT_OK(iref_open(parent, "sub", IREF_PATH, &again));
        ASSERT_STREQ(iref_path(again), "/sub");
}

TEST(iref_file_parent_refcount) {
        /* A newly created file must retain its parent and root after the caller releases the root.
         * Reopening through the retained parent must preserve ownership after the first file is released. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *file = NULL, *parent = NULL, *again = NULL;
        _cleanup_free_ char *filename = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK(iref_open(root, "sub/file", IREF_REGULAR|IREF_CREAT|IREF_EXCL|IREF_WRONLY, &file));
        root = iref_unref(root);

        ASSERT_OK(iref_parent_full(file, &parent, &filename));
        ASSERT_STREQ(iref_path(parent), "/sub");
        ASSERT_STREQ(filename, "file");
        ASSERT_STREQ(iref_root_path(parent), tmpdir);
        file = iref_unref(file);

        /* Releasing the parent must leave the reopened file's parent reference valid. */
        ASSERT_OK(iref_open(parent, filename, IREF_PATH, &again));
        parent = iref_unref(parent);
        ASSERT_OK(iref_parent(again, &parent));
        ASSERT_STREQ(iref_root_path(again), tmpdir);
        ASSERT_OK(iref_unlink(again, /* filename= */ NULL, /* flags= */ 0));
        ASSERT_ERROR(iref_access(parent, filename, F_OK), ENOENT);
}

TEST(iref_is_root) {
        /* References to the host root must report that they are root and reject parent lookup and
         * self-removal. A reference to /tmp must report that it is not root. */
        _cleanup_(iref_unrefp) IRef *slash = NULL, *tmp = NULL, *parent = NULL;

        ASSERT_EQ(iref_fd(NULL), XAT_FDROOT);

        ASSERT_OK(iref_open(NULL, "/", IREF_PATH, &slash));
        ASSERT_OK_POSITIVE(iref_is_root(slash));
        ASSERT_STREQ(iref_path(slash), "/");
        ASSERT_STREQ(iref_root_path(slash), "/");

        ASSERT_ERROR(iref_parent(slash, &parent), EINVAL);
        ASSERT_ERROR(iref_unlink(slash, /* filename= */ NULL, AT_REMOVEDIR), EINVAL);

        ASSERT_OK(iref_open(NULL, "/tmp", IREF_PATH, &tmp));
        ASSERT_OK_ZERO(iref_is_root(tmp));
        ASSERT_STREQ(iref_path(tmp), "/tmp");
        ASSERT_STREQ(iref_root_path(tmp), "/");
}

TEST(iref_open_root) {
        /* A temporary directory must become a root with path "/" and its host path recorded separately.
         * Opening without IREF_PATH must return a readable directory; a regular file must fail with ENOTDIR. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *root2 = NULL, *slash = NULL, *bad = NULL;

        make_root(&tmpdir, &root);
        ASSERT_STREQ(iref_path(root), "/");
        ASSERT_STREQ(iref_root_path(root), tmpdir);
        ASSERT_OK_ZERO(iref_is_root(root));

        ASSERT_OK(iref_open_root(tmpdir, /* flags= */ 0, &root2));
        ASSERT_OK(fd_verify_directory(iref_fd(root2)));
        int flags = fcntl(iref_fd(root2), F_GETFL);
        ASSERT_OK_ERRNO(flags);
        ASSERT_FALSE(FLAGS_SET(flags, O_PATH));

        ASSERT_OK(iref_open_root("/", IREF_PATH, &slash));
        ASSERT_OK_POSITIVE(iref_is_root(slash));
        ASSERT_STREQ(iref_path(slash), "/");
        ASSERT_STREQ(iref_root_path(slash), "/");

        touch_at(root, "file");
        _cleanup_free_ char *file = ASSERT_PTR(path_join(tmpdir, "file"));
        ASSERT_ERROR(iref_open_root(file, IREF_PATH, &bad), ENOTDIR);
}

TEST(iref_chase) {
        /* A temporary root contains a file and a symlink to it. Absolute and relative lookups must report
         * paths within that root, while existence and type checks must work without a result path. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *sub = NULL;
        _cleanup_free_ char *p = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        touch_at(root, "sub/file");
        ASSERT_OK_ERRNO(symlinkat("/sub/file", iref_fd(root), "link"));
        ASSERT_OK(iref_open(root, "sub", IREF_PATH, &sub));

        ASSERT_OK(iref_chase(root, "/sub/file", /* flags= */ 0, &p));
        ASSERT_STREQ(p, "/sub/file");
        p = mfree(p);
        ASSERT_OK(iref_chase(root, "link", /* flags= */ 0, &p));
        ASSERT_STREQ(p, "/sub/file");
        p = mfree(p);
        ASSERT_OK(iref_chase(sub, "file", /* flags= */ 0, &p));
        ASSERT_STREQ(p, "/sub/file");
        p = mfree(p);
        ASSERT_OK(iref_chase(sub, "../..", /* flags= */ 0, &p));
        ASSERT_STREQ(p, "/");
        p = mfree(p);

        ASSERT_OK(iref_chase(root, "/sub", IREF_DIRECTORY, /* ret= */ NULL));
        ASSERT_ERROR(iref_chase(root, "/sub/file", IREF_DIRECTORY, /* ret= */ NULL), ENOTDIR);
        ASSERT_ERROR(iref_chase(root, "/missing", /* flags= */ 0, /* ret= */ NULL), ENOENT);

        ASSERT_OK(iref_chase(NULL, "/tmp", /* flags= */ 0, &p));
        ASSERT_STREQ(p, "/tmp");
        p = mfree(p);
        ASSERT_OK(iref_chase(NULL, "tmp", /* flags= */ 0, &p));
        ASSERT_STREQ(p, "/tmp");
}

TEST(iref_chase_flags) {
        /* A rooted directory contains a file, a subdirectory, and relative and absolute symlinks.
         * iref_chase() must return missing and partially resolved paths, extract filenames, and preserve
         * chaseat()'s status with and without a result path. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *sub = NULL;
        static const struct {
                bool from_sub;
                const char *path;
                IRefFlags flags;
                int status;
                const char *result;
        } cases[] = {
                { false, "sub/file",        0,                                       1,       "/sub/file"          },
                { true,  "file",            0,                                       1,       "/sub/file"          },
                { false, "missing/leaf",    IREF_NONEXISTENT,                       0,       "/missing/leaf"      },
                { true,  "missing/leaf",    IREF_NONEXISTENT,                       0,       "/sub/missing/leaf"  },
                { true,  "../missing",      IREF_NONEXISTENT,                       0,       "/missing"           },
                { true,  "file",            IREF_NONEXISTENT,                       1,       "/sub/file"          },
                { false, "link",            IREF_NONEXISTENT,                       1,       "/sub/file"          },
                { false, "sub/file",        IREF_EXTRACT_FILENAME,                  1,       "file"               },
                { true,  "file",            IREF_EXTRACT_FILENAME,                  1,       "file"               },
                { false, "link",            IREF_EXTRACT_FILENAME,                  1,       "file"               },
                { false, "link",            IREF_NOFOLLOW|IREF_EXTRACT_FILENAME,   1,       "link"               },
                { false, "/",               IREF_EXTRACT_FILENAME_HARDER,                  1,       "."                  },
                { true,  "..",              IREF_EXTRACT_FILENAME_HARDER,                  1,       "."                  },
                { true,  "",                IREF_EXTRACT_FILENAME_HARDER,                  1,       "."                  },
                { true,  "missing/leaf",    IREF_NONEXISTENT|IREF_EXTRACT_FILENAME, 0,       "leaf"               },
                { true,  "missing",         IREF_PARENT,                            1,       "/sub/missing"       },
                { true,  "missing",         IREF_PARENT|IREF_EXTRACT_FILENAME,     1,       "missing"            },
                { true,  "file",            IREF_STEP,                              1,       "/sub/file"          },
                { true,  "../sub/file",     IREF_STEP,                              0,       "/sub/file"          },
                { true,  "relative",        IREF_STEP,                              0,       "/sub/dir/../file"   },
                { false, "link",            IREF_STEP,                              0,       "/sub/file"          },
                { true,  "missing",         IREF_STEP|IREF_NONEXISTENT,             1,       "/sub/missing"       },
                { true,  "relative",        IREF_STEP|IREF_NONEXISTENT,             0,       "/sub/dir/../file"   },
                { true,  "missing",         0,                                      -ENOENT,  NULL                 },
                { true,  "missing/leaf",    IREF_PARENT,                           -ENOENT,  NULL                 },
        };

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK(iref_open(root, "sub", IREF_PATH, &sub));
        ASSERT_OK(iref_mkdir(sub, "dir", 0755));
        touch_at(sub, "file");
        ASSERT_OK_ERRNO(symlinkat("/sub/file", iref_fd(root), "link"));
        ASSERT_OK_ERRNO(symlinkat("dir/../file", iref_fd(sub), "relative"));

        FOREACH_ELEMENT(c, cases) {
                _cleanup_free_ char *path = NULL;
                IRef *base = c->from_sub ? sub : root;

                log_debug("Chasing %s from %s with flags %#x", c->path, iref_path(base), (unsigned) c->flags);
                ASSERT_EQ(iref_chase(base, c->path, c->flags, &path), c->status);
                ASSERT_STREQ(path, c->result);
                ASSERT_EQ(iref_chase(base, c->path, c->flags, /* ret= */ NULL), c->status);
        }

        /* Strict extraction must reject results without a filename and preserve the output on failure. */
        FOREACH_STRING(input, "/", ".", "..", "") {
                _cleanup_free_ char *filename = NULL;

                ASSERT_ERROR(iref_chase(sub, input, IREF_EXTRACT_FILENAME, &filename),
                             streq(input, "..") ? EINVAL : EADDRNOTAVAIL);
                ASSERT_NULL(filename);
                ASSERT_OK_POSITIVE(iref_chase(sub, input, IREF_EXTRACT_FILENAME_HARDER, &filename));
                ASSERT_STREQ(filename, ".");
        }
}

TEST(iref_paths_below_root) {
        /* A temporary root contains a directory and a file. Absolute and relative lookups must report
         * paths within that root, and parent lookup must return the containing directory. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL;

        make_root(&tmpdir, &root);

        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        touch_at(root, "file");

        _cleanup_(iref_unrefp) IRef *sub = NULL, *sub2 = NULL, *file = NULL, *self = NULL;
        ASSERT_OK(iref_open(root, "/sub", IREF_PATH, &sub));
        ASSERT_STREQ(iref_path(sub), "/sub");
        ASSERT_STREQ(iref_root_path(sub), tmpdir);
        ASSERT_OK(iref_open(root, "sub", IREF_PATH, &sub2));
        ASSERT_STREQ(iref_path(sub2), "/sub");
        ASSERT_OK(iref_open(root, "/file", IREF_PATH, &file));
        ASSERT_STREQ(iref_path(file), "/file");
        ASSERT_OK(iref_open(root, "/", IREF_PATH, &self));
        ASSERT_STREQ(iref_path(self), "/");

        /* Ancestor lookup must stay within the configured root. */
        ASSERT_OK(iref_mkdir(sub, "x", 0755));
        _cleanup_(iref_unrefp) IRef *x = NULL, *up = NULL, *abs = NULL;
        ASSERT_OK(iref_open(sub, "x", IREF_PATH, &x));
        ASSERT_STREQ(iref_path(x), "/sub/x");
        ASSERT_OK(iref_open(x, "../../file", IREF_PATH, &up));
        ASSERT_STREQ(iref_path(up), "/file");
        ASSERT_OK(iref_open(x, "/sub", IREF_PATH, &abs));
        ASSERT_STREQ(iref_path(abs), "/sub");
        ASSERT_OK_POSITIVE(fd_inode_same(iref_fd(abs), iref_fd(sub)));

        _cleanup_(iref_unrefp) IRef *up2 = NULL, *up3 = NULL;
        ASSERT_OK(iref_open(x, "..", IREF_PATH, &up2));
        ASSERT_STREQ(iref_path(up2), "/sub");
        ASSERT_OK_POSITIVE(fd_inode_same(iref_fd(up2), iref_fd(sub)));
        ASSERT_OK(iref_open(x, "../..", IREF_PATH, &up3));
        ASSERT_STREQ(iref_path(up3), "/");
        ASSERT_ERROR(iref_chase(file, "x", /* flags= */ 0, /* ret= */ NULL), ENOTDIR);

        /* An empty parent lookup must locate the file's tracked entry. */
        _cleanup_(iref_unrefp) IRef *parent = NULL, *file_parent = NULL;
        _cleanup_free_ char *fname = NULL, *file_name = NULL;
        ASSERT_OK(iref_open_parent(root, "/file", /* flags= */ 0, &parent, &fname));
        ASSERT_STREQ(iref_path(parent), "/");
        ASSERT_STREQ(fname, "file");
        ASSERT_OK(iref_open_parent(file, "", /* flags= */ 0, &file_parent, &file_name));
        ASSERT_STREQ(iref_path(file_parent), "/");
        ASSERT_STREQ(file_name, "file");

        _cleanup_(iref_unrefp) IRef *sub_parent = NULL;
        ASSERT_OK(iref_parent(sub, &sub_parent));
        ASSERT_STREQ(iref_path(sub_parent), "/");
}

TEST(iref_open_parent_resolves_to_dir) {
        /* A symlink to the root, a dot path, and an ancestor lookup can resolve without a final filename.
         * The returned directory fd must match the result, and the filename must be ".". An empty path
         * must continue to locate the tracked entry. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "etc", 0755));
        ASSERT_OK_ERRNO(symlinkat("/", iref_fd(root), "etc/hostname"));

        _cleanup_(iref_unrefp) IRef *parent = NULL;
        _cleanup_free_ char *fname = NULL;
        ASSERT_OK(iref_open_parent(root, "/etc/hostname", /* flags= */ 0, &parent, &fname));
        ASSERT_STREQ(fname, ".");
        ASSERT_STREQ(iref_path(parent), "/");
        ASSERT_OK_POSITIVE(fd_inode_same(iref_fd(parent), iref_fd(root)));
        ASSERT_OK(iref_access(parent, fname, F_OK));

        /* An empty path locates the entry. A dot path refers to the directory fd itself. */
        _cleanup_(iref_unrefp) IRef *etc = NULL;
        ASSERT_OK(iref_open(root, "/etc", IREF_PATH, &etc));
        FOREACH_STRING(path, ".", "") {
                _cleanup_(iref_unrefp) IRef *p = NULL;
                _cleanup_free_ char *f = NULL;

                ASSERT_OK(iref_open_parent(etc, path, /* flags= */ 0, &p, &f));
                ASSERT_STREQ(f, isempty(path) ? "etc" : ".");
                ASSERT_STREQ(iref_path(p), isempty(path) ? "/" : "/etc");
                ASSERT_OK_POSITIVE(fd_inode_same(iref_fd(p), iref_fd(isempty(path) ? root : etc)));
        }

        /* A trailing ".." has no final filename, so its fd must refer to the resolved directory. */
        ASSERT_OK(iref_mkdir(etc, "sub", 0755));
        _cleanup_(iref_unrefp) IRef *sub = NULL, *up = NULL;
        _cleanup_free_ char *up_name = NULL;
        ASSERT_OK(iref_open(etc, "sub", IREF_PATH, &sub));
        ASSERT_OK(iref_open_parent(sub, "..", /* flags= */ 0, &up, &up_name));
        ASSERT_STREQ(up_name, ".");
        ASSERT_STREQ(iref_path(up), "/etc");
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(iref_fd(up), iref_fd(etc)));
}

TEST(iref_stays_below_root) {
        /* An empty path, ancestor paths, and a symlink containing ".." must resolve to the configured root.
         * Parent lookup must reject the root, while open-parent lookup must return the root and ".". */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK_ERRNO(symlinkat("..", iref_fd(root), "sub/up"));

        FOREACH_STRING(path, "", "/", "..", "/../..", "/sub/..", "/sub/up") {
                _cleanup_(iref_unrefp) IRef *i = NULL, *parent = NULL;
                _cleanup_free_ char *fname = NULL;

                log_debug("Resolving %s", path);

                ASSERT_OK(iref_open(root, path, IREF_PATH, &i));
                ASSERT_STREQ(iref_path(i), "/");
                ASSERT_OK_POSITIVE(fd_inode_same(iref_fd(i), iref_fd(root)));
                ASSERT_ERROR(iref_parent(i, &parent), EINVAL);

                ASSERT_OK(iref_open_parent(root, path, /* flags= */ 0, &parent, &fname));
                ASSERT_OK_POSITIVE(fd_inode_same(iref_fd(parent), iref_fd(root)));
                ASSERT_STREQ(fname, ".");

                /* The kernel refuses "." as the last component of mkdirat() and unlinkat(). */
                ASSERT_ERROR(iref_mkdir(parent, fname, 0755), EEXIST);
                ASSERT_ERROR(iref_unlink(parent, fname, AT_REMOVEDIR), EINVAL);
        }
}

TEST(iref_open_never_follows_last_component) {
        /* A rooted directory and an unconfined host directory each contain a file symlink. Default
         * lookup must resolve its target, while IREF_NOFOLLOW must require IREF_PATH to pin the link. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir1 = NULL, *tmpdir2 = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *host = NULL;

        make_root(&tmpdir1, &root);
        make_host_dir(&tmpdir2, &host);

        IRef *dirs[] = { root, host };
        FOREACH_ELEMENT(d, dirs) {
                touch_at(*d, "target");
                ASSERT_OK_ERRNO(symlinkat("target", iref_fd(*d), "link"));

                _cleanup_(iref_unrefp) IRef *followed = NULL, *link = NULL;
                ASSERT_OK(iref_open(*d, "link", /* flags= */ 0, &followed));
                ASSERT_NOT_NULL(endswith(iref_path(followed), "/target"));

                ASSERT_ERROR(iref_open(*d, "link", IREF_NOFOLLOW, &link), ELOOP);
                ASSERT_OK(iref_open(*d, "link", IREF_NOFOLLOW|IREF_PATH, &link));
                ASSERT_NOT_NULL(endswith(iref_path(link), "/link"));

                _cleanup_free_ char *t = NULL;
                ASSERT_OK(iref_readlink(link, &t));
                ASSERT_STREQ(t, "target");
        }
}

TEST(iref_open_must_be) {
        /* A temporary root contains a directory, a regular file, and a FIFO. Type flags must reject
         * mismatches, and IREF_REGULAR must reject the FIFO before a blocking open. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *i = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "dir", 0755));
        touch_at(root, "file");

        ASSERT_OK(iref_open(root, "file", IREF_REGULAR, &i));
        i = iref_unref(i);
        ASSERT_ERROR(iref_open(root, "dir", IREF_REGULAR, &i), EISDIR);

        ASSERT_OK(iref_open(root, "dir", IREF_DIRECTORY|IREF_PATH, &i));
        i = iref_unref(i);
        ASSERT_ERROR(iref_open(root, "file", IREF_DIRECTORY|IREF_PATH, &i), ENOTDIR);

        /* open() blocks on a FIFO without a writer, so the type has to be checked before the open. */
        ASSERT_OK_ERRNO(mkfifoat(iref_fd(root), "fifo", 0644));
        ASSERT_ERROR(iref_open(root, "fifo", IREF_REGULAR, &i), EBADFD);
        _cleanup_fclose_ FILE *f = NULL;
        ASSERT_ERROR(iref_fopen_unlocked(root, "fifo", IREF_REGULAR, "re", &f), EBADFD);
}

TEST(iref_mkdir_and_unlink_roundtrip) {
        /* A temporary host directory contains a child directory and a dangling symlink. The child must
         * be removable, and mkdir must refuse to replace the dangling symlink. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *parent = NULL, *sub = NULL;
        struct stat st;

        make_host_dir(&tmpdir, &parent);

        ASSERT_OK(iref_mkdir(parent, "sub", 0755));
        ASSERT_OK(iref_open(parent, "sub", IREF_PATH, &sub));

        ASSERT_OK(iref_stat(sub, &st));
        ASSERT_TRUE(S_ISDIR(st.st_mode));

        ASSERT_OK_ERRNO(symlinkat("missing", iref_fd(parent), "dangling"));
        ASSERT_ERROR(iref_mkdir(parent, "dangling", 0755), EEXIST);
        ASSERT_OK(iref_access(parent, "dangling", F_OK));

        ASSERT_OK(iref_unlink(parent, "sub", AT_REMOVEDIR));

        _cleanup_(iref_unrefp) IRef *gone = NULL;
        ASSERT_ERROR(iref_open(parent, "sub", IREF_PATH, &gone), ENOENT);
}

TEST(iref_unlink_self) {
        /* A temporary root contains a file, a directory, and a file symlink. Self-unlink must remove
         * their tracked entries, preserve the symlink target, and reject the root and missing entries. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *file = NULL, *dir = NULL, *gone = NULL, *link = NULL;
        struct stat st;

        make_root(&tmpdir, &root);
        touch_at(root, "f");
        ASSERT_OK(iref_mkdir(root, "d", 0755));
        touch_at(root, "g");

        ASSERT_OK(iref_open(root, "f", IREF_PATH, &file));
        ASSERT_OK(iref_unlink(file, "", /* flags= */ 0));
        ASSERT_ERROR_ERRNO(fstatat(iref_fd(root), "f", &st, AT_SYMLINK_NOFOLLOW), ENOENT);

        ASSERT_OK(iref_open(root, "d", IREF_PATH, &dir));
        ASSERT_OK(iref_unlink(dir, /* filename= */ NULL, AT_REMOVEDIR));
        ASSERT_ERROR_ERRNO(fstatat(iref_fd(root), "d", &st, AT_SYMLINK_NOFOLLOW), ENOENT);

        ASSERT_OK_ERRNO(symlinkat("g", iref_fd(root), "link"));
        ASSERT_OK(iref_open(root, "link", IREF_NOFOLLOW|IREF_PATH, &link));
        ASSERT_OK(iref_unlink(link, /* filename= */ NULL, /* flags= */ 0));
        ASSERT_ERROR_ERRNO(fstatat(iref_fd(root), "link", &st, AT_SYMLINK_NOFOLLOW), ENOENT);
        ASSERT_OK_ERRNO(fstatat(iref_fd(root), "g", &st, AT_SYMLINK_NOFOLLOW));

        ASSERT_ERROR(iref_unlink(root, /* filename= */ NULL, AT_REMOVEDIR), EINVAL);

        ASSERT_OK(iref_open(root, "g", IREF_PATH, &gone));
        ASSERT_OK_ERRNO(unlinkat(iref_fd(root), "g", 0));
        ASSERT_ERROR(iref_unlink(gone, /* filename= */ NULL, /* flags= */ 0), ENOENT);
}

TEST(iref_unlink_self_stale) {
        /* Replacing the directory entry for a pinned directory, file, or symlink must make self-unlink
         * and self-rename fail with ESTALE. The original and replacement entries must remain in place. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL;

        make_root(&tmpdir, &root);
        FOREACH_STRING(name, "dir", "file", "link") {
                _cleanup_(iref_unrefp) IRef *entry = NULL;
                _cleanup_free_ char *moved = ASSERT_PTR(strjoin(name, "-moved"));

                if (streq(name, "dir"))
                        ASSERT_OK(iref_mkdir(root, name, 0755));
                else if (streq(name, "link"))
                        ASSERT_OK_ERRNO(symlinkat("missing", iref_fd(root), name));
                else
                        touch_at(root, name);
                ASSERT_OK(iref_open(root, name, IREF_NOFOLLOW|IREF_PATH, &entry));

                /* A regular file replaces each original entry, including the dangling symlink. */
                ASSERT_OK_ERRNO(renameat(iref_fd(root), name, iref_fd(root), moved));
                touch_at(root, name);
                ASSERT_ERROR(iref_unlink(entry, /* filename= */ NULL, streq(name, "dir") ? AT_REMOVEDIR : 0), ESTALE);
                ASSERT_ERROR(iref_rename(entry, /* from_name= */ NULL, root, "renamed", /* flags= */ 0), ESTALE);
                ASSERT_STREQ(last_path_component(iref_path(entry)), name);
                ASSERT_OK(iref_access(root, name, F_OK));
                ASSERT_OK(iref_access(root, moved, F_OK));
        }
}

TEST(iref_rename_same_root) {
        /* A temporary host directory contains a file named "a". A named rename within that directory
         * must change the file's name to "b". */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *dir = NULL;
        struct stat st;

        make_host_dir(&tmpdir, &dir);

        touch_at(dir, "a");
        ASSERT_OK(iref_rename(dir, "a", dir, "b", /* flags= */ 0));

        ASSERT_ERROR_ERRNO(fstatat(iref_fd(dir), "a", &st, 0), ENOENT);
        ASSERT_OK_ERRNO(fstatat(iref_fd(dir), "b", &st, 0));
}

TEST(iref_rename_cross_root) {
        /* A file in a temporary source root must move to an empty destination root. Self-rename of the
         * source root must fail with EINVAL. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir_a = NULL, *tmpdir_b = NULL;
        _cleanup_(iref_unrefp) IRef *root_a = NULL, *root_b = NULL;
        struct stat st;

        make_root(&tmpdir_a, &root_a);
        make_root(&tmpdir_b, &root_b);

        touch_at(root_a, "x");
        ASSERT_OK(iref_rename(root_a, "x", root_b, "y", /* flags= */ 0));

        ASSERT_ERROR_ERRNO(fstatat(iref_fd(root_a), "x", &st, 0), ENOENT);
        ASSERT_OK_ERRNO(fstatat(iref_fd(root_b), "y", &st, 0));

        ASSERT_ERROR(iref_rename(root_a, /* from_name= */ NULL, root_b, "z", /* flags= */ 0), EINVAL);
}

TEST(iref_rename_self_cross_root) {
        /* Two temporary roots contain a file opened through an IRef. Self-rename must move the file,
         * update its path and root, and make self-unlink remove the destination entry. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir_a = NULL, *tmpdir_b = NULL;
        _cleanup_(iref_unrefp) IRef *root_a = NULL, *root_b = NULL, *file = NULL;
        struct stat st;

        make_root(&tmpdir_a, &root_a);
        make_root(&tmpdir_b, &root_b);

        touch_at(root_a, "x");
        ASSERT_OK(iref_open(root_a, "x", IREF_PATH, &file));
        ASSERT_OK(iref_rename(file, /* from_name= */ NULL, root_b, "y", /* flags= */ 0));

        ASSERT_ERROR_ERRNO(fstatat(iref_fd(root_a), "x", &st, 0), ENOENT);
        ASSERT_OK_ERRNO(fstatat(iref_fd(root_b), "y", &st, 0));

        ASSERT_STREQ(iref_path(file), "/y");
        ASSERT_STREQ(iref_root_path(file), tmpdir_b);
        ASSERT_OK(iref_unlink(file, /* filename= */ NULL, /* flags= */ 0));
        ASSERT_ERROR_ERRNO(fstatat(iref_fd(root_b), "y", &st, 0), ENOENT);
}

TEST(iref_fopen_and_access) {
        /* A temporary root contains a text file, a file symlink, and a directory. Stream lookup must read
         * the text, honor IREF_NOFOLLOW and IREF_REGULAR, and support creating a new file. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL;

        make_root(&tmpdir, &root);

        ASSERT_OK(write_string_file_at(iref_fd(root), "note", "hello\n", WRITE_STRING_FILE_CREATE));
        ASSERT_OK_ERRNO(symlinkat("note", iref_fd(root), "link"));
        ASSERT_OK(iref_mkdir(root, "dir", 0755));

        ASSERT_OK(iref_access(root, "note", F_OK));
        ASSERT_ERROR(iref_access(root, "missing", F_OK), ENOENT);

        _cleanup_fclose_ FILE *fp = NULL;
        ASSERT_OK(iref_fopen_unlocked(root, "note", /* flags= */ 0, "re", &fp));

        char buf[16] = {};
        ASSERT_TRUE(fread(buf, 1, sizeof(buf) - 1, fp) == 6);
        ASSERT_STREQ(buf, "hello\n");

        _cleanup_fclose_ FILE *followed = NULL, *nofollow = NULL;
        ASSERT_OK(iref_fopen_unlocked(root, "link", /* flags= */ 0, "re", &followed));
        ASSERT_ERROR(iref_fopen_unlocked(root, "link", IREF_NOFOLLOW, "re", &nofollow), ELOOP);

        _cleanup_fclose_ FILE *dir = NULL, *missing = NULL;
        ASSERT_ERROR(iref_fopen_unlocked(root, "dir", IREF_REGULAR, "re", &dir), EISDIR);
        ASSERT_ERROR(iref_fopen_unlocked(root, "missing", /* flags= */ 0, "re", &missing), ENOENT);

        _cleanup_fclose_ FILE *created = NULL;
        ASSERT_OK(iref_fopen_unlocked(root, "new", /* flags= */ 0, "we", &created));
        ASSERT_OK(iref_access(root, "new", F_OK));
}

TEST(iref_symlink_fd) {
        /* A temporary root contains file and directory symlinks. Relative lookup through a symlink fd
         * must fail with ENOTDIR. Empty-path reopen must preserve the symlink. Absolute lookup must still
         * resolve from the configured root. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *sub = NULL;

        make_root(&tmpdir, &root);

        touch_at(root, "target");
        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK(iref_open(root, "sub", IREF_PATH, &sub));
        ASSERT_OK_ERRNO(symlinkat("target", iref_fd(root), "link"));
        ASSERT_OK_ERRNO(symlinkat("/sub", iref_fd(root), "abs"));
        ASSERT_OK_ERRNO(symlinkat("sub", iref_fd(root), "rel"));

        _cleanup_(iref_unrefp) IRef *link = NULL;
        ASSERT_OK(iref_open(root, "link", IREF_NOFOLLOW|IREF_PATH, &link));

        /* Parent lookup of an empty path must locate the tracked symlink entry without following it. */
        _cleanup_(iref_unrefp) IRef *parent = NULL, *parent2 = NULL;
        _cleanup_free_ char *fname = NULL, *fname2 = NULL;
        ASSERT_OK(iref_open_parent(link, "", /* flags= */ 0, &parent, &fname));
        ASSERT_STREQ(fname, "link");
        ASSERT_STREQ(iref_path(parent), "/");
        ASSERT_OK(iref_open_parent(link, "", IREF_NOFOLLOW, &parent2, &fname2));
        ASSERT_STREQ(fname2, "link");
        ASSERT_STREQ(iref_path(parent2), "/");

        /* An O_PATH fd for a directory symlink cannot be used as a directory fd. */
        FOREACH_STRING(name, "abs", "rel") {
                _cleanup_(iref_unrefp) IRef *l = NULL, *p = NULL;
                _cleanup_free_ char *f = NULL;

                ASSERT_OK(iref_open(root, name, IREF_NOFOLLOW|IREF_PATH, &l));
                ASSERT_ERROR(iref_open_parent(l, "x", /* flags= */ 0, &p, &f), ENOTDIR);
                ASSERT_ERROR(iref_chase(l, "x", /* flags= */ 0, /* ret= */ NULL), ENOTDIR);
        }

        /* Reopening a symlink fd must preserve its inode without following its target. */
        _cleanup_(iref_unrefp) IRef *self = NULL;
        _cleanup_free_ char *self_path = NULL;
        ASSERT_OK(iref_open(link, "", IREF_PATH, &self));
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(iref_fd(self), iref_fd(link)));
        ASSERT_OK(iref_chase(link, "", /* flags= */ 0, &self_path));
        ASSERT_STREQ(self_path, "/link");

        /* An absolute path must use the root even when the starting fd is a symlink. */
        _cleanup_(iref_unrefp) IRef *p3 = NULL;
        _cleanup_free_ char *f3 = NULL;
        ASSERT_OK(iref_open_parent(link, "/target", /* flags= */ 0, &p3, &f3));
        ASSERT_STREQ(iref_path(p3), "/");
        ASSERT_STREQ(f3, "target");
}

TEST(iref_parent_on_host) {
        /* A temporary host directory contains a file and a subdirectory. Parent lookup for either
         * entry must return the original directory and the entry's filename. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *dir = NULL;

        make_host_dir(&tmpdir, &dir);
        ASSERT_OK(iref_mkdir(dir, "sub", 0755));
        touch_at(dir, "f");

        FOREACH_STRING(name, "sub", "f") {
                _cleanup_(iref_unrefp) IRef *i = NULL, *parent = NULL;
                _cleanup_free_ char *filename = NULL;

                ASSERT_OK(iref_open(dir, name, IREF_PATH, &i));
                ASSERT_OK(iref_parent_full(i, &parent, &filename));
                ASSERT_OK_POSITIVE(fd_inode_same(iref_fd(parent), iref_fd(dir)));
                ASSERT_STREQ(iref_path(parent), tmpdir);
                ASSERT_STREQ(filename, name);
        }
}

TEST(iref_rename_self) {
        /* A temporary root contains a file, a directory, and a destination subdirectory. Self-renames must
         * update the moved references' paths. A named rename of the containing directory must leave
         * cached child paths unchanged. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *sub = NULL, *file = NULL, *dir = NULL;
        struct stat st;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK(iref_open(root, "sub", IREF_PATH, &sub));

        touch_at(root, "a");
        ASSERT_OK(iref_open(root, "a", IREF_PATH, &file));
        ASSERT_OK(iref_rename(file, /* from_name= */ NULL, root, "b", /* flags= */ 0));
        ASSERT_ERROR_ERRNO(fstatat(iref_fd(root), "a", &st, 0), ENOENT);
        ASSERT_OK_ERRNO(fstatat(iref_fd(root), "b", &st, 0));
        ASSERT_STREQ(iref_path(file), "/b");

        ASSERT_OK(iref_rename(file, /* from_name= */ NULL, sub, "c", /* flags= */ 0));
        ASSERT_ERROR_ERRNO(fstatat(iref_fd(root), "b", &st, 0), ENOENT);
        ASSERT_OK_ERRNO(fstatat(iref_fd(sub), "c", &st, 0));
        ASSERT_STREQ(iref_path(file), "/sub/c");

        ASSERT_OK(iref_mkdir(root, "d", 0755));
        ASSERT_OK(iref_open(root, "d", IREF_PATH, &dir));
        ASSERT_OK(iref_rename(dir, /* from_name= */ NULL, root, "e", /* flags= */ 0));
        ASSERT_ERROR_ERRNO(fstatat(iref_fd(root), "d", &st, 0), ENOENT);
        ASSERT_OK_ERRNO(fstatat(iref_fd(root), "e", &st, 0));
        ASSERT_STREQ(iref_path(dir), "/e");

        ASSERT_OK(iref_rename(dir, /* from_name= */ NULL, sub, "f", /* flags= */ 0));
        ASSERT_OK_ERRNO(fstatat(iref_fd(sub), "f", &st, 0));
        ASSERT_STREQ(iref_path(dir), "/sub/f");

        ASSERT_STREQ(iref_path(sub), "/sub");
        ASSERT_OK(iref_rename(root, "sub", root, "moved", /* flags= */ 0));
        ASSERT_STREQ(iref_path(sub), "/sub");
        ASSERT_STREQ(iref_path(dir), "/sub/f");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
