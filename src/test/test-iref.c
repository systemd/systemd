/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#include "chattr-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "iref.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "umask-util.h"

#define ASSERT_SAME_INODE(a, b) \
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(iref_fd(a), iref_fd(b)))

static void make_root(char **ret_tmpdir, IRef **ret_root) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL;

        ASSERT_OK(mkdtemp_malloc("/var/tmp/test-iref.XXXXXX", &tmpdir));
        ASSERT_OK(iref_open_root(tmpdir, IREF_PATH, &root));
        ASSERT_OK(free_and_strdup(&tmpdir, iref_root_path(root)));

        *ret_tmpdir = TAKE_PTR(tmpdir);
        *ret_root = TAKE_PTR(root);
}

static void make_host_dir(char **ret_tmpdir, IRef **ret_dir) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *host = NULL, *dir = NULL;

        ASSERT_OK(mkdtemp_malloc("/var/tmp/test-iref.XXXXXX", &tmpdir));
        ASSERT_OK(iref_open_root("/", IREF_PATH, &host));
        ASSERT_OK(iref_open(host, tmpdir, IREF_PATH, &dir));

        *ret_tmpdir = TAKE_PTR(tmpdir);
        *ret_dir = TAKE_PTR(dir);
}

static void touch_at(IRef *dir, const char *filename) {
        _cleanup_close_ int fd = xopenat(iref_fd(dir), filename, O_CREAT|O_WRONLY);
        ASSERT_OK(fd);
}

static bool have_tmpfile(IRef *dir) {
        _cleanup_close_ int fd = xopenat_full(iref_fd(dir), ".", O_TMPFILE|O_RDWR, /* xopen_flags= */ 0, 0600);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(fd) || fd == -EISDIR) {
                log_tests_skipped_errno(fd, "O_TMPFILE not supported");
                return false;
        }

        ASSERT_OK(fd);
        return true;
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

        /* Lookup must use the opened directory even though the reported path remains cached. Parent
         * lookup of a path with a filename must return zero. */
        _cleanup_(iref_unrefp) IRef *opened = NULL, *parent = NULL, *self = NULL;
        _cleanup_free_ char *filename = NULL, *path = NULL;
        ASSERT_OK(iref_open(dir, "file", IREF_PATH, &opened));
        ASSERT_SAME_INODE(opened, file);
        ASSERT_STREQ(iref_path(opened), "/dir/file");
        ASSERT_OK_ZERO(iref_open_parent(dir, "file", /* flags= */ 0, &parent, &filename));
        ASSERT_SAME_INODE(parent, dir);
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
        ASSERT_SAME_INODE(self, file);
        ASSERT_OK(iref_unlink(self, /* filename= */ NULL, /* flags= */ 0));
        ASSERT_ERROR(iref_access(dir, "file", F_OK), ENOENT);
        ASSERT_OK(iref_access(root, "dir", F_OK));
        ASSERT_OK(iref_chase(root, "dir/file", /* flags= */ 0, /* ret= */ NULL));
}

TEST(iref_parent_after_ancestor_rename) {
        /* A temporary root contains a file and a directory below an ancestor that is moved and
         * replaced. Parent lookup and self-operations must use the original containing directory.
         * A self-rename must retain the destination parent if that directory is moved afterwards. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *file = NULL, *dir = NULL, *destination = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "ancestor", 0755));
        ASSERT_OK_ERRNO(mkdirat(iref_fd(root), "ancestor/parent", 0755));
        touch_at(root, "ancestor/parent/file");
        ASSERT_OK_ERRNO(mkdirat(iref_fd(root), "ancestor/parent/dir", 0755));
        ASSERT_OK_ERRNO(symlinkat("/ancestor/parent/file", iref_fd(root), "alias"));
        ASSERT_OK(iref_open(root, "alias", IREF_PATH, &file));
        ASSERT_OK(iref_open(root, "ancestor/parent/dir", IREF_PATH, &dir));

        /* The original cached paths now refer to replacements. */
        ASSERT_OK_ERRNO(renameat(iref_fd(root), "ancestor", iref_fd(root), "moved"));
        ASSERT_OK(iref_mkdir(root, "ancestor", 0755));
        ASSERT_OK_ERRNO(mkdirat(iref_fd(root), "ancestor/parent", 0755));
        touch_at(root, "ancestor/parent/file");
        ASSERT_OK_ERRNO(mkdirat(iref_fd(root), "ancestor/parent/dir", 0755));

        _cleanup_(iref_unrefp) IRef *moved = NULL;
        ASSERT_OK(iref_open(root, "moved/parent", IREF_PATH, &moved));
        IRef *entries[] = { file, dir };
        FOREACH_ELEMENT(entry, entries) {
                _cleanup_(iref_unrefp) IRef *parent = NULL, *opened_parent = NULL;
                _cleanup_free_ char *filename = NULL, *opened_filename = NULL;

                ASSERT_OK(iref_parent_full(*entry, &parent, &filename));
                ASSERT_SAME_INODE(parent, moved);
                ASSERT_STREQ(filename, last_path_component(iref_path(*entry)));
                ASSERT_OK(iref_open_parent(*entry, "", /* flags= */ 0, &opened_parent, &opened_filename));
                ASSERT_SAME_INODE(opened_parent, moved);
                ASSERT_STREQ(opened_filename, filename);
        }

        /* Renaming or removing the original entries must leave the replacements in place. */
        ASSERT_OK(iref_mkdir(root, "destination", 0755));
        ASSERT_OK(iref_open(root, "destination", IREF_PATH, &destination));
        ASSERT_OK(iref_rename(file, /* from_name= */ NULL, destination, "renamed", /* flags= */ 0));
        ASSERT_OK(iref_unlink(dir, /* filename= */ NULL, AT_REMOVEDIR));
        FOREACH_STRING(name, "file", "dir") {
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

TEST(iref_paths_are_normalized) {
        /* A temporary root contains a directory, a symlink to it, a regular file, and a subdirectory of
         * the directory. Reported paths must omit trailing slashes and resolve ".." within the root. An
         * input ending in a slash must still require a directory during a chase lookup. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK_ERRNO(mkdirat(iref_fd(root), "sub/x", 0755));
        ASSERT_OK_ERRNO(symlinkat("/sub", iref_fd(root), "link"));
        touch_at(root, "file");

        FOREACH_STRING(input, "sub///", "link/") {
                _cleanup_(iref_unrefp) IRef *opened = NULL, *parent = NULL;
                _cleanup_free_ char *path = NULL, *filename = NULL;

                ASSERT_OK(iref_chase(root, input, /* flags= */ 0, &path));
                ASSERT_STREQ(path, "/sub");
                ASSERT_OK(iref_open(root, input, IREF_PATH|IREF_DIRECTORY, &opened));
                ASSERT_STREQ(iref_path(opened), "/sub");
                ASSERT_OK(iref_open_parent(root, input, /* flags= */ 0, &parent, &filename));
                ASSERT_STREQ(iref_path(parent), "/");
                ASSERT_STREQ(filename, "sub");
                ASSERT_SAME_INODE(parent, root);
        }

        /* Relative ancestor lookups from a subdirectory must report paths within the root. */
        _cleanup_(iref_unrefp) IRef *sub = NULL, *x = NULL, *up = NULL, *file = NULL;
        ASSERT_OK(iref_open(root, "sub", IREF_PATH, &sub));
        ASSERT_OK(iref_open(sub, "x", IREF_PATH, &x));
        ASSERT_OK(iref_open(x, "..", IREF_PATH, &up));
        ASSERT_STREQ(iref_path(up), "/sub");
        ASSERT_SAME_INODE(up, sub);
        ASSERT_OK(iref_open(x, "../../file", IREF_PATH, &file));
        ASSERT_STREQ(iref_path(file), "/file");

        /* A trailing slash in the input requires a directory. */
        ASSERT_ERROR(iref_chase(root, "file/", /* flags= */ 0, /* ret= */ NULL), ENOTDIR);
}

TEST(iref_open_create_flags) {
        /* A temporary root contains no entries. Creation must honor the requested inode type, create
         * missing parents when requested, reject an existing entry with O_EXCL, and reopen it otherwise.
         * Creating the root directory must fail with EISDIR because its path has no filename. */
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
                ASSERT_OK(iref_open(root, c->path, c->flags|IREF_CREAT|IREF_NOFOLLOW, &again));
                ASSERT_SAME_INODE(created, again);
        }

        /* Creation may follow an intermediate symlink to the containing directory. */
        _cleanup_(iref_unrefp) IRef *file = NULL, *bad = NULL;
        ASSERT_OK_ERRNO(symlinkat("sub", iref_fd(root), "sub-link"));
        ASSERT_OK(iref_open(root, "sub-link/new", IREF_CREAT|IREF_NOFOLLOW|IREF_REGULAR|IREF_WRONLY, &file));
        ASSERT_STREQ(iref_path(file), "/sub/new");

        ASSERT_ERROR(iref_open(root, "/", IREF_CREAT|IREF_NOFOLLOW|IREF_DIRECTORY|IREF_PATH, &bad), EISDIR);
}

TEST(iref_open_full_mode) {
        /* An empty temporary root and a 0027 umask must produce a file with the requested permissions.
         * MODE_INVALID must produce the default permissions for files and directories. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL;

        make_root(&tmpdir, &root);
        BLOCK_WITH_UMASK(0027);

        static const struct {
                const char *path;
                IRefFlags flags;
                mode_t mode;
                mode_t expected;
        } cases[] = {
                { "secret",      IREF_REGULAR|IREF_WRONLY, 0600,         0600 },
                { "default",     IREF_REGULAR|IREF_WRONLY, MODE_INVALID, 0640 },
                { "default-dir", IREF_DIRECTORY|IREF_PATH, MODE_INVALID, 0750 },
        };

        FOREACH_ELEMENT(c, cases) {
                _cleanup_(iref_unrefp) IRef *created = NULL;
                struct stat st;

                ASSERT_OK(iref_open_full(root, c->path, c->flags|IREF_CREAT|IREF_EXCL, c->mode, &created));
                ASSERT_OK(iref_stat(created, &st));
                ASSERT_EQ(st.st_mode & 0777, c->expected);
        }
}

TEST(iref_tmpfile) {
        /* A temporary root contains a creation directory. An unnamed file must retain that directory,
         * reject operations that require a filename, and stay unnamed when it is reopened. An empty
         * path must create the unnamed file in the opened directory itself. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *dir = NULL, *tmp = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "cache", 0755));
        ASSERT_OK(iref_open(root, "cache", IREF_PATH, &dir));
        if (!have_tmpfile(dir))
                return;

        ASSERT_OK(iref_open_full(root, "cache", IREF_TMPFILE|IREF_RDWR|IREF_REGULAR, 0600, &tmp));
        ASSERT_NULL(iref_path(tmp));
        ASSERT_STREQ(iref_root_path(tmp), tmpdir);
        struct stat st;
        ASSERT_OK(iref_stat(tmp, &st));
        ASSERT_EQ(st.st_nlink, 0u);

        /* Parent lookup must return the creation directory without inventing a filename. */
        _cleanup_(iref_unrefp) IRef *parent = NULL, *entry_parent = NULL;
        ASSERT_OK(iref_parent(tmp, &parent));
        ASSERT_SAME_INODE(parent, dir);
        ASSERT_OK(iref_open_parent(tmp, "", /* flags= */ 0, &entry_parent, /* ret_filename= */ NULL));
        ASSERT_SAME_INODE(entry_parent, dir);

        _cleanup_free_ char *path = ASSERT_PTR(strdup("untouched"));
        ASSERT_ERROR(iref_parent_full(tmp, &parent, &path), EADDRNOTAVAIL);
        ASSERT_STREQ(path, "untouched");
        ASSERT_SAME_INODE(parent, dir);
        ASSERT_ERROR(iref_unlink(tmp, /* filename= */ NULL, /* flags= */ 0), EADDRNOTAVAIL);
        ASSERT_OK(iref_chase(tmp, "", IREF_REGULAR, /* ret= */ NULL));
        ASSERT_ERROR(iref_chase(tmp, "", /* flags= */ 0, &path), EADDRNOTAVAIL);
        ASSERT_STREQ(path, "untouched");

        /* Reopening must preserve the unnamed state and the inode. */
        _cleanup_(iref_unrefp) IRef *reopened = NULL;
        ASSERT_OK(iref_open(tmp, "", IREF_PATH|IREF_REGULAR, &reopened));
        ASSERT_NULL(iref_path(reopened));
        ASSERT_SAME_INODE(tmp, reopened);

        /* An empty path creates the unnamed file in the directory that dir refers to. */
        _cleanup_(iref_unrefp) IRef *in_dir = NULL, *in_dir_parent = NULL;
        ASSERT_OK(iref_open_full(dir, "", IREF_TMPFILE|IREF_WRONLY, 0600, &in_dir));
        ASSERT_NULL(iref_path(in_dir));
        ASSERT_OK(iref_parent(in_dir, &in_dir_parent));
        ASSERT_SAME_INODE(in_dir_parent, dir);
}

TEST(iref_tmpfile_publish) {
        /* An unnamed file is published into another root on the same filesystem. A failed link must
         * leave the unnamed reference unchanged. A successful link must update the path, root, and
         * parent of that reference only. Linking a named reference must leave its path unchanged. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL, *otherdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *other = NULL, *destination = NULL, *tmp = NULL, *copy = NULL;

        make_root(&tmpdir, &root);
        make_root(&otherdir, &other);
        if (!have_tmpfile(root))
                return;

        ASSERT_OK(iref_mkdir(other, "out", 0755));
        ASSERT_OK(iref_open(other, "out", IREF_PATH, &destination));
        ASSERT_OK(iref_open_full(root, ".", IREF_TMPFILE|IREF_RDWR, 0600, &tmp));
        ASSERT_OK(iref_open(tmp, "", IREF_PATH, &copy));

        /* An existing destination must prevent publication without changing the unnamed reference. */
        touch_at(destination, "result");
        ASSERT_ERROR(iref_link(tmp, destination, "result"), EEXIST);
        ASSERT_NULL(iref_path(tmp));
        ASSERT_STREQ(iref_root_path(tmp), tmpdir);
        _cleanup_(iref_unrefp) IRef *parent = NULL;
        ASSERT_OK(iref_parent(tmp, &parent));
        ASSERT_SAME_INODE(parent, root);
        ASSERT_ERROR(iref_link(tmp, copy, "result"), ENOTDIR);
        ASSERT_OK(iref_unlink(destination, "result", /* flags= */ 0));

        /* Publication must retain the destination parent and root, while the copy stays unnamed. */
        ASSERT_OK(iref_link(tmp, destination, "result"));
        ASSERT_STREQ(iref_path(tmp), "/out/result");
        ASSERT_STREQ(iref_root_path(tmp), otherdir);
        _cleanup_(iref_unrefp) IRef *published_parent = NULL, *opened = NULL;
        _cleanup_free_ char *filename = NULL;
        ASSERT_OK(iref_parent_full(tmp, &published_parent, &filename));
        ASSERT_STREQ(filename, "result");
        ASSERT_SAME_INODE(published_parent, destination);
        ASSERT_OK(iref_open(destination, "result", IREF_REGULAR, &opened));
        ASSERT_SAME_INODE(tmp, opened);
        ASSERT_NULL(iref_path(copy));
        ASSERT_STREQ(iref_root_path(copy), tmpdir);

        /* Linking a named reference must preserve its tracked entry. */
        ASSERT_OK(iref_link(tmp, destination, "second"));
        ASSERT_STREQ(iref_path(tmp), "/out/result");
        ASSERT_OK(iref_access(destination, "second", F_OK));
}

TEST(iref_tmpfile_flags) {
        /* A temporary root must reject incompatible tmpfile flags without creating lookup parents.
         * IREF_EXCL must allow unnamed creation while preventing publication. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL;

        make_root(&tmpdir, &root);
        const IRefFlags incompatible[] = {
                IREF_PATH, IREF_CREAT, IREF_DIRECTORY, IREF_SOCKET, IREF_LABEL, IREF_SUBVOLUME,
                IREF_TRIGGER_AUTOFS, IREF_AUTO_RW_RO,
        };
        FOREACH_ELEMENT(flag, incompatible) {
                _cleanup_(iref_unrefp) IRef *result = iref_ref(root);
                ASSERT_ERROR(iref_open_full(root, "missing/sub", IREF_TMPFILE|IREF_RDWR|IREF_MKDIR_0755|*flag,
                                           0600, &result), EINVAL);
                ASSERT_PTR_EQ(result, root);
                ASSERT_ERROR(iref_access(root, "missing", F_OK), ENOENT);
        }

        _cleanup_(iref_unrefp) IRef *bad = NULL, *exclusive = NULL;
        ASSERT_ERROR(iref_open(root, ".", IREF_TMPFILE, &bad), EINVAL);
        if (!have_tmpfile(root))
                return;

        ASSERT_OK(iref_open_full(root, ".", IREF_TMPFILE|IREF_RDWR|IREF_EXCL, 0600, &exclusive));
        ASSERT_ERROR(iref_link(exclusive, root, "result"), ENOENT);
        ASSERT_NULL(iref_path(exclusive));
        ASSERT_ERROR(iref_access(root, "result", F_OK), ENOENT);
}

TEST(iref_link_symlink) {
        /* A temporary root contains a symlink with an absolute target that does not exist. Linking the
         * pinned symlink must create a second entry for the symlink inode without following its target. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *symlink = NULL, *linked_symlink = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK_ERRNO(symlinkat("/missing", iref_fd(root), "symlink"));
        ASSERT_OK(iref_open(root, "symlink", IREF_PATH|IREF_NOFOLLOW, &symlink));
        ASSERT_OK(iref_link(symlink, root, "linked-symlink"));
        ASSERT_STREQ(iref_path(symlink), "/symlink");
        ASSERT_OK(iref_open(root, "linked-symlink", IREF_PATH|IREF_NOFOLLOW, &linked_symlink));
        ASSERT_SAME_INODE(symlink, linked_symlink);
        _cleanup_free_ char *target = NULL;
        ASSERT_OK(iref_readlink(linked_symlink, &target));
        ASSERT_STREQ(target, "/missing");
}

TEST(iref_open_trailing_slash) {
        /* A temporary root contains a regular file, a directory, and a symlink whose target is the file
         * followed by a slash. Paths ending in "/" must open directories, reject regular files, and refuse
         * to create a regular file. Parent lookup must return a positive status when the final open must
         * enforce a directory requirement. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *file = NULL, *dir = NULL, *missing = NULL;
        struct stat st;

        make_root(&tmpdir, &root);
        touch_at(root, "file");
        ASSERT_OK(iref_mkdir(root, "dir", 0755));
        ASSERT_OK_ERRNO(symlinkat("file/", iref_fd(root), "file-slash"));

        /* Parent lookup must retain the directory requirement when it removes the trailing slash. */
        _cleanup_(iref_unrefp) IRef *parent = NULL;
        _cleanup_free_ char *filename = NULL;
        ASSERT_OK_POSITIVE(iref_open_parent(root, "file/", /* flags= */ 0, &parent, &filename));
        ASSERT_SAME_INODE(parent, root);
        ASSERT_STREQ(filename, "file");

        ASSERT_ERROR(iref_open(root, "file/", IREF_PATH, &file), ENOTDIR);
        ASSERT_NULL(file);
        ASSERT_ERROR(iref_open(root, "dir/", IREF_REGULAR, &file), EBADSLT);
        ASSERT_OK(iref_open(root, "dir/", IREF_PATH, &dir));
        ASSERT_OK(iref_stat(dir, &st));
        ASSERT_TRUE(S_ISDIR(st.st_mode));

        /* A failed writable open must leave no entry behind. */
        ASSERT_ERROR(iref_open(root, "missing/", IREF_CREAT|IREF_NOFOLLOW|IREF_WRONLY, &missing), EISDIR);
        ASSERT_NULL(missing);
        ASSERT_ERROR(iref_access(root, "missing", F_OK), ENOENT);

        /* IREF_CREAT with a directory path must create a directory. */
        ASSERT_OK(iref_open(root, "missing/", IREF_CREAT|IREF_NOFOLLOW|IREF_PATH, &missing));
        ASSERT_OK(iref_stat(missing, &st));
        ASSERT_TRUE(S_ISDIR(st.st_mode));

        /* A trailing slash in the target of the last symlink must also require a directory. */
        _cleanup_(iref_unrefp) IRef *link_parent = NULL;
        _cleanup_free_ char *link_filename = NULL;
        ASSERT_OK_POSITIVE(iref_open_parent(root, "file-slash", /* flags= */ 0, &link_parent, &link_filename));
        ASSERT_SAME_INODE(link_parent, root);
        ASSERT_STREQ(link_filename, "file");
        ASSERT_ERROR(iref_open(root, "file-slash", IREF_PATH, &file), ENOTDIR);
}

TEST(iref_open_xopen_flags) {
        /* A writable regular file in a temporary root must open read/write with IREF_AUTO_RW_RO, both by
         * name and when reopening its pinned inode. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *file = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_open(root, "file", IREF_CREAT|IREF_EXCL|IREF_REGULAR|IREF_AUTO_RW_RO, &file));
        ASSERT_EQ(ASSERT_OK_ERRNO(fcntl(iref_fd(file), F_GETFL)) & O_ACCMODE, O_RDWR);

        _cleanup_(iref_unrefp) IRef *reopened = NULL;
        ASSERT_OK(iref_open(file, "", IREF_REGULAR|IREF_AUTO_RW_RO, &reopened));
        ASSERT_EQ(ASSERT_OK_ERRNO(fcntl(iref_fd(reopened), F_GETFL)) & O_ACCMODE, O_RDWR);
        ASSERT_SAME_INODE(file, reopened);
}

TEST(iref_open_socket) {
        /* A temporary root contains a bound Unix socket and a regular file. IREF_SOCKET must open the
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
        ASSERT_SAME_INODE(socket_ref, reopened);
        ASSERT_ERROR(iref_open(root, "file", IREF_PATH|IREF_SOCKET, &bad), ENOTSOCK);
}

TEST(iref_refcount) {
        /* A directory child and a file child keep their root alive after the caller releases the root
         * reference. Create both children and release the root. Parent lookup must then return the root
         * directory for the directory child and the containing directory for the file child. Lookup
         * through the directory child's parent must still work after the children are released. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *dir = NULL, *file = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK(iref_open(root, "sub", IREF_PATH, &dir));
        ASSERT_OK(iref_open(root, "sub/file", IREF_REGULAR|IREF_CREAT|IREF_EXCL|IREF_WRONLY, &file));
        root = iref_unref(root);

        _cleanup_(iref_unrefp) IRef *dir_parent = NULL, *file_parent = NULL;
        _cleanup_free_ char *filename = NULL;
        ASSERT_OK(iref_parent(dir, &dir_parent));
        ASSERT_STREQ(iref_path(dir_parent), "/");
        ASSERT_STREQ(iref_root_path(dir), tmpdir);
        ASSERT_OK(iref_parent_full(file, &file_parent, &filename));
        ASSERT_STREQ(iref_path(file_parent), "/sub");
        ASSERT_STREQ(filename, "file");
        ASSERT_STREQ(iref_root_path(file_parent), tmpdir);
        dir = iref_unref(dir);
        file = iref_unref(file);

        _cleanup_(iref_unrefp) IRef *again = NULL;
        ASSERT_OK(iref_open(dir_parent, "sub", IREF_PATH, &again));
        ASSERT_STREQ(iref_path(again), "/sub");
}

TEST(iref_is_host_root) {
        /* Open the host root directory as a root. A second reference to "/" below it must report that it
         * is the host root and reject parent lookup and self-removal. A reference to /tmp must report that
         * it is not the host root. */
        _cleanup_(iref_unrefp) IRef *host = NULL, *slash = NULL, *tmp = NULL, *parent = NULL;

        ASSERT_OK(iref_open_root("/", IREF_PATH, &host));
        ASSERT_OK(iref_open(host, "/", IREF_PATH, &slash));
        ASSERT_OK_POSITIVE(iref_is_host_root(slash));
        ASSERT_STREQ(iref_path(slash), "/");
        ASSERT_STREQ(iref_root_path(slash), "/");

        ASSERT_ERROR(iref_parent(slash, &parent), EINVAL);
        ASSERT_ERROR(iref_unlink(slash, /* filename= */ NULL, AT_REMOVEDIR), EINVAL);

        ASSERT_OK(iref_open(host, "/tmp", IREF_PATH, &tmp));
        ASSERT_OK_ZERO(iref_is_host_root(tmp));
        ASSERT_STREQ(iref_path(tmp), "/tmp");
        ASSERT_STREQ(iref_root_path(tmp), "/");
}

TEST(iref_open_root) {
        /* A temporary directory must become a root with path "/" and its host path recorded separately.
         * Opening without IREF_PATH must return a readable directory. Constructing a root from that fd must
         * preserve its mount and record no host path. Parent lookup must still return O_PATH. A regular
         * file must fail. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *root2 = NULL, *root3 = NULL, *slash = NULL, *bad = NULL,
                *parent = NULL;

        make_root(&tmpdir, &root);
        ASSERT_STREQ(iref_path(root), "/");
        ASSERT_STREQ(iref_root_path(root), tmpdir);
        ASSERT_OK_ZERO(iref_is_host_root(root));

        ASSERT_OK(iref_open_root(tmpdir, /* flags= */ 0, &root2));
        ASSERT_OK(fd_verify_directory(iref_fd(root2)));
        int flags = fcntl(iref_fd(root2), F_GETFL);
        ASSERT_OK_ERRNO(flags);
        ASSERT_FALSE(FLAGS_SET(flags, O_PATH));

        ASSERT_OK(iref_open_root_fd(iref_fd(root2), &root3));
        ASSERT_NE(iref_fd(root2), iref_fd(root3));
        ASSERT_SAME_INODE(root2, root3);
        ASSERT_NULL(iref_root_path(root3));

        touch_at(root2, "file");
        ASSERT_OK(iref_open_parent(root2, "file", /* flags= */ 0, &parent, /* ret_filename= */ NULL));
        ASSERT_OK_POSITIVE(fd_is_opath(iref_fd(parent)));

        ASSERT_OK(iref_open_root("/", IREF_PATH, &slash));
        ASSERT_OK_POSITIVE(iref_is_host_root(slash));
        ASSERT_STREQ(iref_path(slash), "/");
        ASSERT_STREQ(iref_root_path(slash), "/");

        _cleanup_free_ char *file = ASSERT_PTR(path_join(tmpdir, "file"));
        ASSERT_ERROR(iref_open_root(file, IREF_PATH, &bad), ENOTDIR);
}

TEST(iref_chase) {
        /* A rooted directory contains a file, a subdirectory, and relative and absolute symlinks.
         * iref_chase() must report absolute and relative lookups as paths within the root, extract
         * filenames, and return chaseat()'s status with and without a result path. Lookups below a root
         * opened on "/" must resolve from the host root. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *sub = NULL;
        static const struct {
                bool from_sub;
                const char *path;
                IRefFlags flags;
                int status;
                const char *result;
        } cases[] = {
                { false, "/sub/file",    0,                                    1,       "/sub/file"         },
                { false, "link",         0,                                    1,       "/sub/file"         },
                { true,  "file",         0,                                    1,       "/sub/file"         },
                { true,  "../..",        0,                                    1,       "/"                 },
                { false, "/sub",         IREF_DIRECTORY,                       1,       "/sub"              },
                { false, "/sub/file",    IREF_DIRECTORY,                       -ENOTDIR, NULL               },
                { true,  "missing/leaf", IREF_NONEXISTENT,                     0,       "/sub/missing/leaf" },
                { true,  "../missing",   IREF_NONEXISTENT,                     0,       "/missing"          },
                { true,  "file",         IREF_EXTRACT_FILENAME,                1,       "file"              },
                { false, "link",         IREF_NOFOLLOW|IREF_EXTRACT_FILENAME,  1,       "link"              },
                { true,  "missing",      IREF_PARENT,                          1,       "/sub/missing"      },
                { true,  "relative",     IREF_STEP,                            0,       "/sub/dir/../file"  },
                { true,  "missing",      0,                                    -ENOENT, NULL                },
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

                log_debug("Chasing %s from %s with flags %#" PRIx64, c->path, iref_path(base), (uint64_t) c->flags);
                ASSERT_EQ(iref_chase(base, c->path, c->flags, &path), c->status);
                ASSERT_STREQ(path, c->result);
                ASSERT_EQ(iref_chase(base, c->path, c->flags, /* ret= */ NULL), c->status);
        }

        /* Strict extraction must reject an empty path, which has no filename, and preserve the output.
         * IREF_EXTRACT_FILENAME_HARDER must return "." instead. */
        _cleanup_free_ char *filename = NULL;
        ASSERT_ERROR(iref_chase(sub, "", IREF_EXTRACT_FILENAME, &filename), EADDRNOTAVAIL);
        ASSERT_NULL(filename);
        ASSERT_OK_POSITIVE(iref_chase(sub, "", IREF_EXTRACT_FILENAME_HARDER, &filename));
        ASSERT_STREQ(filename, ".");

        _cleanup_(iref_unrefp) IRef *host = NULL;
        ASSERT_OK(iref_open_root("/", IREF_PATH, &host));
        FOREACH_STRING(input, "/tmp", "tmp") {
                _cleanup_free_ char *p = NULL;

                ASSERT_OK(iref_chase(host, input, /* flags= */ 0, &p));
                ASSERT_STREQ(p, "/tmp");
        }
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
        /* A temporary root contains a file, a symlink to it, and a dangling symlink. Creation without
         * IREF_NOFOLLOW or IREF_EXCL must fail before lookup. Ordinary lookup must follow symlinks, and
         * creation must not follow them. IREF_NOFOLLOW must require IREF_PATH to open a symlink. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(write_string_file_at(iref_fd(root), "target", "original\n", WRITE_STRING_FILE_CREATE));
        ASSERT_OK_ERRNO(symlinkat("target", iref_fd(root), "link"));
        ASSERT_OK_ERRNO(symlinkat("missing", iref_fd(root), "dangling"));

        /* Refused creation must preserve the output reference and must not create a parent directory. */
        FOREACH_STRING(path, "link", "missing-parent/file") {
                _cleanup_(iref_unrefp) IRef *unchanged = iref_ref(root);

                ASSERT_ERROR(iref_open(root, path, IREF_CREAT|IREF_WRONLY|IREF_TRUNC|IREF_MKDIR_0755,
                                       &unchanged), EINVAL);
                ASSERT_PTR_EQ(unchanged, root);
        }
        ASSERT_ERROR(iref_access(root, "missing-parent", F_OK), ENOENT);

        /* The refused truncating open must leave the 9 bytes of the target in place. */
        _cleanup_(iref_unrefp) IRef *followed = NULL, *link = NULL;
        struct stat st;
        ASSERT_OK(iref_open(root, "link", IREF_REGULAR, &followed));
        ASSERT_STREQ(iref_path(followed), "/target");
        ASSERT_OK(iref_stat(followed, &st));
        ASSERT_EQ(st.st_size, 9);

        /* Creation must not create the missing target of a dangling symlink. */
        _cleanup_(iref_unrefp) IRef *created = NULL;
        ASSERT_ERROR(iref_open(root, "dangling", IREF_CREAT|IREF_NOFOLLOW|IREF_REGULAR, &created), ELOOP);
        ASSERT_ERROR(iref_open(root, "dangling", IREF_CREAT|IREF_EXCL|IREF_REGULAR, &created), EEXIST);
        ASSERT_ERROR(iref_access(root, "missing", F_OK), ENOENT);

        ASSERT_ERROR(iref_open(root, "link", IREF_NOFOLLOW, &link), ELOOP);
        ASSERT_OK(iref_open(root, "link", IREF_NOFOLLOW|IREF_PATH, &link));
        ASSERT_STREQ(iref_path(link), "/link");

        _cleanup_free_ char *t = NULL;
        ASSERT_OK(iref_readlink(link, &t));
        ASSERT_STREQ(t, "target");
}

TEST(iref_open_must_be) {
        /* A temporary root contains a directory, a regular file, and a FIFO. IREF_REGULAR must accept the
         * file and reject the directory with and without IREF_NO_SYNC. IREF_REGULAR must also reject the
         * FIFO before a blocking open. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *i = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_mkdir(root, "dir", 0755));
        touch_at(root, "file");

        ASSERT_OK(iref_open(root, "file", IREF_REGULAR, &i));
        i = iref_unref(i);
        ASSERT_ERROR(iref_open(root, "dir", IREF_REGULAR, &i), EISDIR);

        ASSERT_OK(iref_open(root, "file", IREF_REGULAR|IREF_PATH|IREF_NO_SYNC, &i));
        i = iref_unref(i);
        ASSERT_ERROR(iref_open(root, "dir", IREF_REGULAR|IREF_PATH|IREF_NO_SYNC, &i), EISDIR);

        /* open() blocks on a FIFO without a writer, so the type has to be checked before the open. */
        ASSERT_OK_ERRNO(mkfifoat(iref_fd(root), "fifo", 0644));
        ASSERT_ERROR(iref_open(root, "fifo", IREF_REGULAR, &i), EBADFD);
        _cleanup_fclose_ FILE *f = NULL;
        ASSERT_ERROR(iref_fopen_unlocked(root, "fifo", IREF_REGULAR, "re", &f), EBADFD);
}

TEST(iref_create_and_update_inode) {
        /* A temporary root must create a regular node through mknod, a FIFO, and a symlink. Open the regular
         * file and symlink as pinned references, then check self-access and update the file's mode and times. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *file = NULL, *link = NULL;
        struct stat st;

        make_root(&tmpdir, &root);

        /* Create a regular node, a FIFO, and a symlink through the root directory IRef. */
        ASSERT_OK(iref_mknod(root, "file", S_IFREG|0640, /* dev= */ 0));
        ASSERT_OK(iref_mkfifo(root, "fifo", 0600));
        ASSERT_OK(iref_symlink(root, "file", "link"));
        ASSERT_OK_ERRNO(fstatat(iref_fd(root), "file", &st, AT_SYMLINK_NOFOLLOW));
        ASSERT_TRUE(S_ISREG(st.st_mode));
        ASSERT_OK_ERRNO(fstatat(iref_fd(root), "fifo", &st, AT_SYMLINK_NOFOLLOW));
        ASSERT_TRUE(S_ISFIFO(st.st_mode));
        ASSERT_OK_ERRNO(fstatat(iref_fd(root), "link", &st, AT_SYMLINK_NOFOLLOW));
        ASSERT_TRUE(S_ISLNK(st.st_mode));

        /* Self-access must work for a pinned regular file. */
        ASSERT_OK(iref_open(root, "file", IREF_PATH, &file));
        ASSERT_OK(iref_open(root, "link", IREF_PATH|IREF_NOFOLLOW, &link));
        _cleanup_free_ char *target = NULL;
        ASSERT_OK(iref_readlink(link, &target));
        ASSERT_STREQ(target, "file");
        ASSERT_OK(iref_access(file, /* filename= */ NULL, F_OK));

        /* Metadata updates must operate on the pinned inode even though its fd was opened with O_PATH. */
        ASSERT_OK_POSITIVE(iref_chmod_and_chown(file, 0600, UID_INVALID, GID_INVALID));
        const struct timespec times[2] = {
                { .tv_sec = 10, .tv_nsec = 20 },
                { .tv_sec = 30, .tv_nsec = 40 },
        };
        ASSERT_OK(iref_utimens(file, times));
        ASSERT_OK(iref_stat(file, &st));
        ASSERT_EQ(st.st_mode & 07777, (mode_t) 0600);
        ASSERT_EQ(st.st_atim.tv_sec, times[0].tv_sec);
        ASSERT_EQ(st.st_atim.tv_nsec, times[0].tv_nsec);
        ASSERT_EQ(st.st_mtim.tv_sec, times[1].tv_sec);
        ASSERT_EQ(st.st_mtim.tv_nsec, times[1].tv_nsec);
}

TEST(iref_inspect_inode) {
        /* A temporary root contains a regular file and a subdirectory. Inspect the file through statx and
         * statfs, then enumerate the directory without consuming the IRef's fd. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *file = NULL;

        make_root(&tmpdir, &root);
        touch_at(root, "file");
        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK(iref_open(root, "file", IREF_PATH, &file));

        /* statx and statfs must inspect the pinned inode without reopening its stored path. */
        struct statx sx;
        ASSERT_OK(iref_statx(file, AT_STATX_DONT_SYNC, STATX_TYPE|STATX_MODE|STATX_INO, &sx));
        ASSERT_TRUE(S_ISREG(sx.stx_mode));
        ASSERT_TRUE(sx.stx_mask & STATX_INO);

        struct statfs fs, root_fs;
        ASSERT_OK(iref_statfs(file, &fs));
        ASSERT_OK(iref_statfs(root, &root_fs));
        ASSERT_EQ(fs.f_type, root_fs.f_type);

        /* Directory enumeration must reopen an O_PATH directory fd without consuming the IRef's fd. */
        _cleanup_closedir_ DIR *dir = NULL;
        ASSERT_OK(iref_opendir(root, &dir));
        bool saw_file = false, saw_sub = false;
        for (struct dirent *de; (de = readdir_no_dot(dir));) {
                saw_file |= streq(de->d_name, "file");
                saw_sub |= streq(de->d_name, "sub");
        }
        ASSERT_TRUE(saw_file);
        ASSERT_TRUE(saw_sub);
        ASSERT_ERROR(iref_opendir(file, &dir), ENOTDIR);
}

TEST(iref_xattr) {
        /* A temporary root contains a regular file. When its filesystem supports user extended attributes,
         * IRef operations must preserve binary values and enumerate and remove the attribute name. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *file = NULL;

        make_root(&tmpdir, &root);
        touch_at(root, "file");
        ASSERT_OK(iref_open(root, "file", IREF_PATH, &file));

        const char input[] = { 'v', 0, 'x' };
        int r = iref_setxattr(file, "user.iref", input, sizeof(input), /* flags= */ 0);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return (void) log_tests_skipped_errno(r, "User extended attributes are not supported on /var/tmp");
        ASSERT_OK(r);

        _cleanup_free_ char *value = NULL, *names = NULL;
        size_t size;
        ASSERT_OK(iref_getxattr(file, "user.iref", &value, &size));
        ASSERT_EQ(size, sizeof(input));
        ASSERT_EQ(memcmp(value, input, size), 0);
        ASSERT_OK_POSITIVE(iref_listxattr(file, &names));
        ASSERT_TRUE(nulstr_contains(names, "user.iref"));
        ASSERT_OK(iref_removexattr(file, "user.iref"));
        value = mfree(value);
        ASSERT_ERROR(iref_getxattr(file, "user.iref", &value, &size), ENODATA);
}

TEST(iref_chattr) {
        /* A temporary root contains a regular file and a FIFO. When its filesystem supports inode flags,
         * IRef must update the pinned regular file and reject the FIFO without opening it. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *file = NULL;

        make_root(&tmpdir, &root);
        touch_at(root, "file");
        ASSERT_OK(iref_open(root, "file", IREF_PATH, &file));

        int r = iref_chattr(file, FS_NODUMP_FL, FS_NODUMP_FL);
        if (ERRNO_IS_NEG_IOCTL_NOT_SUPPORTED(r))
                return (void) log_tests_skipped_errno(r, "Inode flags are not supported on /var/tmp");
        ASSERT_OK_POSITIVE(r);

        unsigned attrs;
        ASSERT_OK(read_attr_fd(iref_fd(file), &attrs));
        ASSERT_TRUE(attrs & FS_NODUMP_FL);
        ASSERT_OK_POSITIVE(iref_chattr(file, /* value= */ 0, FS_NODUMP_FL));

        ASSERT_OK(iref_mkfifo(root, "fifo", 0600));
        _cleanup_(iref_unrefp) IRef *fifo = NULL;
        ASSERT_OK(iref_open(root, "fifo", IREF_PATH, &fifo));
        ASSERT_ERROR(iref_chattr(fifo, FS_NODUMP_FL, FS_NODUMP_FL), ENOTTY);
}

TEST(iref_unlink_self_stale) {
        /* Replacing the directory entry for a pinned directory or file must make self-unlink and
         * self-rename fail with ESTALE, and the original and replacement entries must remain in place.
         * Removing the entry of a pinned file must make self-unlink fail with ENOENT. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *gone = NULL;

        make_root(&tmpdir, &root);
        FOREACH_STRING(name, "dir", "file") {
                _cleanup_(iref_unrefp) IRef *entry = NULL;
                _cleanup_free_ char *moved = ASSERT_PTR(strjoin(name, "-moved"));

                if (streq(name, "dir"))
                        ASSERT_OK(iref_mkdir(root, name, 0755));
                else
                        touch_at(root, name);
                ASSERT_OK(iref_open(root, name, IREF_NOFOLLOW|IREF_PATH, &entry));

                /* A regular file replaces each original entry. */
                ASSERT_OK_ERRNO(renameat(iref_fd(root), name, iref_fd(root), moved));
                touch_at(root, name);
                ASSERT_ERROR(iref_unlink(entry, /* filename= */ NULL, streq(name, "dir") ? AT_REMOVEDIR : 0), ESTALE);
                ASSERT_ERROR(iref_rename(entry, /* from_name= */ NULL, root, "renamed", /* flags= */ 0), ESTALE);
                ASSERT_STREQ(last_path_component(iref_path(entry)), name);
                ASSERT_OK(iref_access(root, name, F_OK));
                ASSERT_OK(iref_access(root, moved, F_OK));
        }

        touch_at(root, "gone");
        ASSERT_OK(iref_open(root, "gone", IREF_PATH, &gone));
        ASSERT_OK_ERRNO(unlinkat(iref_fd(root), "gone", 0));
        ASSERT_ERROR(iref_unlink(gone, /* filename= */ NULL, /* flags= */ 0), ENOENT);
}

TEST(iref_fopen) {
        /* A temporary root contains a file and an absolute symlink to it. Exclusive fopen must create the
         * file once, and named fopen must refuse the symlink. Reopening a pinned file must read the
         * original inode after its directory entry is replaced. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *file = NULL;
        _cleanup_fclose_ FILE *created = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(iref_fopen(root, "note", IREF_EXCL, "we", &created));
        ASSERT_GE(fputs("original\n", created), 0);
        created = safe_fclose(created);
        ASSERT_ERROR(iref_fopen(root, "note", IREF_EXCL, "we", &created), EEXIST);
        ASSERT_NULL(created);
        ASSERT_OK(iref_open(root, "note", IREF_PATH, &file));
        ASSERT_OK_ERRNO(symlinkat("/note", iref_fd(root), "link"));
        ASSERT_ERROR(iref_fopen(root, "link", /* flags= */ 0, "re", &created), ELOOP);

        /* The replacement uses the original filename and contains different text. */
        ASSERT_OK_ERRNO(renameat(iref_fd(root), "note", iref_fd(root), "moved"));
        ASSERT_OK(write_string_file_at(iref_fd(root), "note", "replacement", WRITE_STRING_FILE_CREATE));

        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *line = NULL;
        ASSERT_OK(iref_fopen(file, /* filename= */ NULL, /* flags= */ 0, "re", &f));
        ASSERT_OK_POSITIVE(read_line(f, LONG_LINE_MAX, &line));
        ASSERT_STREQ(line, "original");
}

TEST(iref_fopen_create_flags) {
        /* A temporary root contains a file, a symlink to it, and a dangling symlink. Creation modes must
         * require IREF_NOFOLLOW or "x" before lookup and leave the file unchanged when refused.
         * Nonexclusive creation must not follow symlinks, and exclusive creation must report EEXIST. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL;
        _cleanup_fclose_ FILE *f = NULL;

        make_root(&tmpdir, &root);
        ASSERT_OK(write_string_file_at(iref_fd(root), "file", "original\n", WRITE_STRING_FILE_CREATE));
        ASSERT_OK_ERRNO(symlinkat("file", iref_fd(root), "link"));
        ASSERT_OK_ERRNO(symlinkat("missing", iref_fd(root), "dangling"));

        /* Invalid creation flags must not create parent directories or truncate existing files. */
        FOREACH_STRING(path, "file", "missing-parent/file") {
                ASSERT_ERROR(iref_fopen_unlocked(root, path, IREF_MKDIR_0755, "we", &f), EINVAL);
                ASSERT_NULL(f);
        }

        FOREACH_STRING(path, "link", "dangling")
                ASSERT_ERROR(iref_fopen_unlocked(root, path, IREF_NOFOLLOW, "we", &f), ELOOP);

        /* Nonexclusive creation must create a new file and then reopen it. */
        ASSERT_OK(iref_fopen_unlocked(root, "new", IREF_NOFOLLOW, "we", &f));
        f = safe_fclose(f);
        ASSERT_OK(iref_fopen_unlocked(root, "new", IREF_NOFOLLOW, "we", &f));
        f = safe_fclose(f);
        ASSERT_OK(iref_unlink(root, "new", /* flags= */ 0));

        /* Exclusive modes imply no-follow lookup and must only create absent entries. */
        FOREACH_STRING(path, "file", "link", "dangling")
                ASSERT_ERROR(iref_fopen_unlocked(root, path, /* flags= */ 0, "wex", &f), EEXIST);

        ASSERT_OK(iref_fopen_unlocked(root, "new", /* flags= */ 0, "wex", &f));
        f = safe_fclose(f);
        ASSERT_ERROR(iref_fopen_unlocked(root, "new", /* flags= */ 0, "wex", &f), EEXIST);

        ASSERT_ERROR(iref_access(root, "missing", F_OK), ENOENT);
        ASSERT_ERROR(iref_access(root, "missing-parent", F_OK), ENOENT);

        _cleanup_free_ char *contents = NULL;
        ASSERT_OK(iref_fopen_unlocked(root, "file", /* flags= */ 0, "re", &f));
        ASSERT_OK(read_full_stream(f, &contents, /* ret_size= */ NULL));
        ASSERT_STREQ(contents, "original\n");
}

TEST(iref_symlink_fd) {
        /* A temporary root contains a file symlink and a directory symlink. Relative lookup through a
         * symlink fd must fail with ENOTDIR. Empty-path reopen must preserve the symlink. Absolute lookup
         * must still resolve from the configured root. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *link = NULL, *dir_link = NULL;

        make_root(&tmpdir, &root);

        touch_at(root, "target");
        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK_ERRNO(symlinkat("target", iref_fd(root), "link"));
        ASSERT_OK_ERRNO(symlinkat("/sub", iref_fd(root), "dir-link"));
        ASSERT_OK(iref_open(root, "link", IREF_NOFOLLOW|IREF_PATH, &link));

        /* Parent lookup of an empty path must locate the tracked symlink entry without following it. */
        _cleanup_(iref_unrefp) IRef *parent = NULL;
        _cleanup_free_ char *fname = NULL;
        ASSERT_OK(iref_open_parent(link, "", /* flags= */ 0, &parent, &fname));
        ASSERT_STREQ(fname, "link");
        ASSERT_STREQ(iref_path(parent), "/");

        /* An O_PATH fd for a directory symlink cannot be used as a directory fd. */
        _cleanup_(iref_unrefp) IRef *bad = NULL;
        _cleanup_free_ char *bad_name = NULL;
        ASSERT_OK(iref_open(root, "dir-link", IREF_NOFOLLOW|IREF_PATH, &dir_link));
        ASSERT_ERROR(iref_open_parent(dir_link, "x", /* flags= */ 0, &bad, &bad_name), ENOTDIR);
        ASSERT_ERROR(iref_chase(dir_link, "x", /* flags= */ 0, /* ret= */ NULL), ENOTDIR);

        /* Reopening a symlink fd must preserve its inode without following its target. */
        _cleanup_(iref_unrefp) IRef *self = NULL;
        _cleanup_free_ char *self_path = NULL;
        ASSERT_OK(iref_open(link, "", IREF_PATH, &self));
        ASSERT_SAME_INODE(self, link);
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
        /* A temporary host directory below a root opened on "/" contains a subdirectory. Parent lookup for
         * the subdirectory must open the host directory through ".." and return the subdirectory's
         * filename. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(iref_unrefp) IRef *dir = NULL, *sub = NULL, *parent = NULL;
        _cleanup_free_ char *filename = NULL;

        make_host_dir(&tmpdir, &dir);
        ASSERT_OK(iref_mkdir(dir, "sub", 0755));

        ASSERT_OK(iref_open(dir, "sub", IREF_PATH, &sub));
        ASSERT_OK(iref_parent_full(sub, &parent, &filename));
        ASSERT_OK_POSITIVE(fd_inode_same(iref_fd(parent), iref_fd(dir)));
        ASSERT_STREQ(iref_path(parent), tmpdir);
        ASSERT_STREQ(filename, "sub");
}

TEST(iref_rename_self) {
        /* A source root contains a file, a directory, and a destination subdirectory, and a second root
         * is empty. Self-renames must update the path of the moved reference, and a self-rename into the
         * second root must also update its root. A named rename of the containing directory must leave
         * cached child paths unchanged. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL, *otherdir = NULL;
        _cleanup_(iref_unrefp) IRef *root = NULL, *other = NULL, *sub = NULL, *file = NULL, *dir = NULL;

        make_root(&tmpdir, &root);
        make_root(&otherdir, &other);
        ASSERT_OK(iref_mkdir(root, "sub", 0755));
        ASSERT_OK(iref_open(root, "sub", IREF_PATH, &sub));

        /* The file retains its parent and the directory doesn't, so both update paths are covered. */
        touch_at(root, "a");
        ASSERT_OK(iref_open(root, "a", IREF_PATH, &file));
        ASSERT_OK(iref_rename(file, /* from_name= */ NULL, sub, "c", /* flags= */ 0));
        ASSERT_ERROR(iref_access(root, "a", F_OK), ENOENT);
        ASSERT_OK(iref_access(sub, "c", F_OK));
        ASSERT_STREQ(iref_path(file), "/sub/c");

        ASSERT_OK(iref_mkdir(root, "d", 0755));
        ASSERT_OK(iref_open(root, "d", IREF_PATH, &dir));
        ASSERT_OK(iref_rename(dir, /* from_name= */ NULL, sub, "f", /* flags= */ 0));
        ASSERT_OK(iref_access(sub, "f", F_OK));
        ASSERT_STREQ(iref_path(dir), "/sub/f");

        /* A self-rename into another root must update the root, and self-unlink must remove the new
         * entry. */
        ASSERT_OK(iref_rename(file, /* from_name= */ NULL, other, "y", /* flags= */ 0));
        ASSERT_STREQ(iref_path(file), "/y");
        ASSERT_STREQ(iref_root_path(file), otherdir);
        ASSERT_OK(iref_unlink(file, /* filename= */ NULL, /* flags= */ 0));
        ASSERT_ERROR(iref_access(other, "y", F_OK), ENOENT);

        /* A named rename of the containing directory must leave cached paths unchanged. */
        ASSERT_OK(iref_rename(root, "sub", root, "moved", /* flags= */ 0));
        ASSERT_STREQ(iref_path(sub), "/sub");
        ASSERT_STREQ(iref_path(dir), "/sub/f");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
