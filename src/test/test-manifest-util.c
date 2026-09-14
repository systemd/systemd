/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "crypto-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "json-util.h"
#include "manifest-util.h"
#include "mkdir.h"
#include "memstream-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "uapi16-manifest.h"
#include "xattr-util.h"

static int make_tree(char **ret_path) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int fd = -EBADF, tfd = -EBADF;

        assert(ret_path);

        /* Populates a temporary directory with one inode of each type we can create unprivileged, including
         * a pair of hardlinks. */

        ASSERT_OK(tfd = mkdtemp_open(NULL, O_DIRECTORY|O_CLOEXEC, &t));

        ASSERT_OK(write_string_file_at(tfd, "regular.txt", "hello world", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        ASSERT_OK(write_string_file_at(tfd, "empty.txt", "", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        ASSERT_OK_ERRNO(mkdirat(tfd, "subdir", 0755));
        ASSERT_OK(write_string_file_at(tfd, "subdir/nested.txt", "nested", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        ASSERT_OK_ERRNO(symlinkat("regular.txt", tfd, "symlink"));
        ASSERT_OK_ERRNO(mkfifoat(tfd, "fifo", 0600));
        ASSERT_OK(write_string_file_at(tfd, "hardlink_a", "hardlinked content", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        ASSERT_OK_ERRNO(linkat(tfd, "hardlink_a", tfd, "hardlink_b", 0));

        ASSERT_OK_ERRNO(fchmodat(tfd, "regular.txt", 0644, 0));
        ASSERT_OK_ERRNO(fchmodat(tfd, "empty.txt", 0644, 0));
        ASSERT_OK_ERRNO(fchmodat(tfd, "subdir/nested.txt", 0644, 0));
        ASSERT_OK_ERRNO(fchmodat(tfd, "hardlink_a", 0644, 0));

        *ret_path = TAKE_PTR(t);
        return TAKE_FD(tfd);
}

static void context_init(ManifestContext *c, ManifestFormat format) {
        assert(c);

        *c = MANIFEST_CONTEXT_NULL;
        c->format = format;
}

static int generate(ManifestContext *c, int dir_fd, char **ret, size_t *ret_size) {
        _cleanup_(memstream_done) MemStream m = {};
        int r;

        assert(c);
        assert(ret);
        assert(ret_size);

        ASSERT_NOT_NULL(c->output = memstream_init(&m));

        /* manifest_make() enumerates the tree from the current position of the directory fd, like any
         * readdir() style interface does, hence rewind it, since we reuse the fd for multiple runs. */
        ASSERT_OK_ERRNO(lseek(dir_fd, 0, SEEK_SET));

        r = manifest_make(c, dir_fd);
        c->output = NULL;
        if (r < 0)
                return r;

        ASSERT_OK(memstream_finalize(&m, ret, ret_size));
        return 0;
}

static int verify_buffer(ManifestContext *c, int dir_fd, const char *buf, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;

        assert(c);
        assert(buf);

        ASSERT_NOT_NULL(f = fmemopen_unlocked((void*) buf, size, "r"));

        return manifest_verify(c, dir_fd, f);
}

static int verify_pipe(ManifestContext *c, int dir_fd, const char *buf, size_t size) {
        _cleanup_close_pair_ int p[2] = EBADF_PAIR;
        _cleanup_fclose_ FILE *f = NULL;

        assert(c);
        assert(buf);

        /* Like verify_buffer(), but pass the data through a pipe, i.e. something that is not seekable, to
         * validate we really operate in a streaming fashion. The manifests we generate here are small
         * enough to fit into the pipe buffer. */

        ASSERT_OK_ERRNO(pipe2(p, O_CLOEXEC));
        ASSERT_OK(loop_write(p[1], buf, size));
        p[1] = safe_close(p[1]);

        ASSERT_OK(take_fdopen_unlocked(&p[0], "r", &f));

        return manifest_verify(c, dir_fd, f);
}

TEST(manifest_fields_from_string) {
        ManifestField f;

        f = 0;
        ASSERT_OK(manifest_fields_from_string("all", &f));
        ASSERT_EQ(f, _MANIFEST_FIELD_ALL);

        f = _MANIFEST_FIELD_ALL;
        ASSERT_OK(manifest_fields_from_string("none", &f));
        ASSERT_EQ(f, 0);

        f = _MANIFEST_FIELD_ALL;
        ASSERT_OK(manifest_fields_from_string("size,hash", &f));
        ASSERT_EQ(f, MANIFEST_FIELD_SIZE|MANIFEST_FIELD_HASH);

        f = _MANIFEST_FIELD_DEFAULT;
        ASSERT_OK(manifest_fields_from_string("+mtime", &f));
        ASSERT_EQ(f, _MANIFEST_FIELD_DEFAULT|MANIFEST_FIELD_MTIME);

        f = _MANIFEST_FIELD_DEFAULT;
        ASSERT_OK(manifest_fields_from_string("-hash,-uid", &f));
        ASSERT_EQ(f, _MANIFEST_FIELD_DEFAULT & ~(MANIFEST_FIELD_HASH|MANIFEST_FIELD_UID));

        f = _MANIFEST_FIELD_DEFAULT;
        ASSERT_OK(manifest_fields_from_string("mode,+gid", &f));
        ASSERT_EQ(f, MANIFEST_FIELD_MODE|MANIFEST_FIELD_GID);

        f = _MANIFEST_FIELD_DEFAULT;
        ASSERT_ERROR(manifest_fields_from_string("foobar", &f), EINVAL);

        _cleanup_free_ char *s = NULL;
        ASSERT_OK(manifest_fields_to_string(MANIFEST_FIELD_SIZE|MANIFEST_FIELD_MTIME, &s));
        ASSERT_STREQ(s, "size,mtime");
        s = mfree(s);
        ASSERT_OK(manifest_fields_to_string(0, &s));
        ASSERT_STREQ(s, "none");

        ASSERT_STREQ(manifest_field_to_string(MANIFEST_FIELD_HARDLINK), "hardlink");
        ASSERT_EQ(manifest_field_from_string("device"), MANIFEST_FIELD_DEVICE);
        ASSERT_EQ(manifest_field_from_string("nope"), _MANIFEST_FIELD_INVALID);
}

TEST(manifest_list) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;
        _cleanup_free_ char *buf = NULL;
        size_t size;

        ASSERT_OK(tfd = make_tree(&t));

        _cleanup_(manifest_context_done) ManifestContext c;
        context_init(&c, MANIFEST_FORMAT_LIST);
        ASSERT_OK(generate(&c, tfd, &buf, &size));
        ASSERT_STREQ(buf,
                     "empty.txt\n"
                     "fifo\n"
                     "hardlink_a\n"
                     "hardlink_b\n"
                     "regular.txt\n"
                     "subdir/\n"
                     "subdir/nested.txt\n"
                     "symlink\n");

        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_LIST);
        ASSERT_OK(verify_buffer(&c, tfd, buf, size));

        /* Removing a file makes verification fail */
        ASSERT_OK_ERRNO(unlinkat(tfd, "fifo", 0));
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_LIST);
        ASSERT_ERROR(verify_buffer(&c, tfd, buf, size), EBADMSG);
        ASSERT_EQ(c.n_errors, 1U);

        /* A directory listed as a file is a mismatch too */
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_LIST);
        ASSERT_ERROR(verify_buffer(&c, tfd, "subdir\n", strlen("subdir\n")), EBADMSG);
}

TEST(manifest_sums) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;
        _cleanup_free_ char *buf = NULL;
        size_t size;

        ASSERT_OK(tfd = make_tree(&t));

        _cleanup_(manifest_context_done) ManifestContext c;
        context_init(&c, MANIFEST_FORMAT_SHA256SUMS);
        ASSERT_OK(generate(&c, tfd, &buf, &size));
        ASSERT_STREQ(buf,
                     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty.txt\n"
                     "5f3c775a7618b56ac451fbb036042095744ab2c991f371c683c7cc5f704d19ee  hardlink_a\n"
                     "5f3c775a7618b56ac451fbb036042095744ab2c991f371c683c7cc5f704d19ee  hardlink_b\n"
                     "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9  regular.txt\n"
                     "233562de1a0288b139c4fa40b7d189f806e906eeb048517aeb67f34ac0e2faf1  subdir/nested.txt\n");

        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_SHA256SUMS);
        ASSERT_OK(verify_pipe(&c, tfd, buf, size));

        /* Without the hash field we cannot generate this format */
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_SHA256SUMS);
        c.fields &= ~MANIFEST_FIELD_HASH;
        _cleanup_free_ char *nohash = NULL;
        size_t nohash_size;
        ASSERT_ERROR(generate(&c, tfd, &nohash, &nohash_size), EINVAL);

        /* Changing a file's contents is detected */
        ASSERT_OK(write_string_file_at(tfd, "regular.txt", "HELLO WORLD", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_SHA256SUMS);
        ASSERT_ERROR(verify_buffer(&c, tfd, buf, size), EBADMSG);
        ASSERT_EQ(c.n_errors, 1U);
        ASSERT_OK(write_string_file_at(tfd, "regular.txt", "hello world", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));

        /* File names with newlines and backslashes are escaped like coreutils does it */
        ASSERT_OK(write_string_file_at(tfd, "a\nb", "x", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        ASSERT_OK(write_string_file_at(tfd, "back\\slash", "y", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        _cleanup_free_ char *escaped = NULL;
        size_t escaped_size;
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_SHA256SUMS);
        ASSERT_OK(generate(&c, tfd, &escaped, &escaped_size));
        ASSERT_NOT_NULL(strstr(escaped, "\\2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881  a\\nb\n"));
        ASSERT_NOT_NULL(strstr(escaped, "  back\\\\slash\n"));

        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_SHA256SUMS);
        ASSERT_OK(verify_buffer(&c, tfd, escaped, escaped_size));

        /* Absolute paths and non-normalized paths are refused */
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_SHA256SUMS);
        const char *bad = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /etc/passwd\n";
        ASSERT_ERROR(verify_buffer(&c, tfd, bad, strlen(bad)), EINVAL);
        bad = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ../empty.txt\n";
        ASSERT_ERROR(verify_buffer(&c, tfd, bad, strlen(bad)), EINVAL);
}

TEST(manifest_mtree) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;
        _cleanup_free_ char *buf = NULL;
        size_t size;

        ASSERT_OK(tfd = make_tree(&t));

        _cleanup_(manifest_context_done) ManifestContext c;
        context_init(&c, MANIFEST_FORMAT_MTREE);
        ASSERT_OK(generate(&c, tfd, &buf, &size));

        ASSERT_TRUE(startswith(buf, "./ type=dir mode="));
        ASSERT_NOT_NULL(strstr(buf, "./regular.txt type=file mode=0644 uid="));
        ASSERT_NOT_NULL(strstr(buf, " size=11 sha256sum=b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9\n"));
        ASSERT_NOT_NULL(strstr(buf, "./symlink type=link uid="));
        ASSERT_NOT_NULL(strstr(buf, " link=regular.txt\n"));
        ASSERT_NOT_NULL(strstr(buf, "./fifo type=fifo mode=0600"));
        ASSERT_NULL(strstr(buf, "time="));

        /* Dropping fields drops them from the output, adding mtime adds it */
        _cleanup_free_ char *buf2 = NULL;
        size_t size2;
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_MTREE);
        c.fields = MANIFEST_FIELD_MTIME;
        ASSERT_OK(generate(&c, tfd, &buf2, &size2));
        ASSERT_NULL(strstr(buf2, "mode="));
        ASSERT_NULL(strstr(buf2, "uid="));
        ASSERT_NULL(strstr(buf2, "size="));
        ASSERT_NULL(strstr(buf2, "sha256sum="));
        ASSERT_NULL(strstr(buf2, "link="));
        ASSERT_NOT_NULL(strstr(buf2, "./regular.txt type=file time="));

        /* Verification of mtree is not supported */
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_MTREE);
        ASSERT_ERROR(verify_buffer(&c, tfd, buf, size), EOPNOTSUPP);
}

static sd_json_variant* find_object(const char *manifest, const char *name) {
        /* Parses a JSON-SEQ manifest from memory and returns the object with the specified name */

        const char *p = manifest;
        size_t left = strlen(manifest);

        for (;;) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                int r;

                ASSERT_OK(r = json_seq_extract(&p, &left, SD_JSON_PARSE_MUST_BE_OBJECT, /* eol= */ true, &v));
                if (r == 0)
                        return NULL;

                sd_json_variant *n = sd_json_variant_by_key(v, "name");
                if (!name) {
                        if (!n)
                                return TAKE_PTR(v);
                } else if (n && sd_json_variant_is_string(n) && streq(sd_json_variant_string(n), name))
                        return TAKE_PTR(v);
        }
}

TEST(manifest_uapi16) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;
        _cleanup_free_ char *buf = NULL;
        size_t size;

        ASSERT_OK(tfd = make_tree(&t));

        _cleanup_(manifest_context_done) ManifestContext c;
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        ASSERT_OK(generate(&c, tfd, &buf, &size));

        /* Each record starts with an RS byte */
        ASSERT_EQ(buf[0], 0x1e);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *root = find_object(buf, NULL);
        ASSERT_NOT_NULL(root);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(root, "mediaType")), UAPI16_MANIFEST_MEDIA_TYPE);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reg = find_object(buf, "regular.txt");
        ASSERT_NOT_NULL(reg);
        ASSERT_NULL(sd_json_variant_by_key(reg, "type"));
        ASSERT_EQ(sd_json_variant_unsigned(sd_json_variant_by_key(reg, "size")), 11U);
        ASSERT_EQ(sd_json_variant_unsigned(sd_json_variant_by_key(reg, "mode")), 0644U);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(reg, "sha256")), "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        ASSERT_NULL(sd_json_variant_by_key(reg, "inodeToken"));
        ASSERT_NULL(sd_json_variant_by_key(reg, "mTimeNSec"));
        ASSERT_NULL(sd_json_variant_by_key(reg, "extendedAttributes"));
        ASSERT_TRUE(sd_json_variant_is_normalized(reg)); /* Fields are sorted */

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *lnk = find_object(buf, "symlink");
        ASSERT_NOT_NULL(lnk);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(lnk, "type")), "lnk");
        ASSERT_NULL(sd_json_variant_by_key(lnk, "mode"));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ha = find_object(buf, "hardlink_a"), *hb = find_object(buf, "hardlink_b");
        ASSERT_NOT_NULL(ha);
        ASSERT_NOT_NULL(hb);
        ASSERT_EQ(sd_json_variant_unsigned(sd_json_variant_by_key(ha, "inodeToken")), 1U);
        ASSERT_EQ(sd_json_variant_unsigned(sd_json_variant_by_key(hb, "inodeToken")), 1U);

        /* Verification succeeds, from a pipe too */
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        ASSERT_OK(verify_pipe(&c, tfd, buf, size));

        /* Restricting the fields restricts the output */
        _cleanup_free_ char *buf2 = NULL;
        size_t size2;
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.fields = MANIFEST_FIELD_SIZE|MANIFEST_FIELD_MTIME;
        ASSERT_OK(generate(&c, tfd, &buf2, &size2));
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reg2 = find_object(buf2, "regular.txt");
        ASSERT_NOT_NULL(reg2);
        ASSERT_NULL(sd_json_variant_by_key(reg2, "mode"));
        ASSERT_NULL(sd_json_variant_by_key(reg2, "sha256"));
        ASSERT_NULL(sd_json_variant_by_key(reg2, "uid"));
        ASSERT_NOT_NULL(sd_json_variant_by_key(reg2, "size"));
        ASSERT_NOT_NULL(sd_json_variant_by_key(reg2, "mTimeNSec"));
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *hb2 = find_object(buf2, "hardlink_b");
        ASSERT_NOT_NULL(hb2);
        ASSERT_NULL(sd_json_variant_by_key(hb2, "inodeToken"));

        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.fields = MANIFEST_FIELD_SIZE|MANIFEST_FIELD_MTIME;
        ASSERT_OK(verify_buffer(&c, tfd, buf2, size2));

        /* Now break things: mode change is detected, but not if we don't care about the mode */
        ASSERT_OK_ERRNO(fchmodat(tfd, "subdir/nested.txt", 0600, 0));
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        ASSERT_ERROR(verify_buffer(&c, tfd, buf, size), EBADMSG);
        ASSERT_EQ(c.n_errors, 1U);

        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.fields = MANIFEST_FIELD_SIZE|MANIFEST_FIELD_HASH;
        ASSERT_OK(verify_buffer(&c, tfd, buf, size));
        ASSERT_OK_ERRNO(fchmodat(tfd, "subdir/nested.txt", 0644, 0));

        /* Replacing a hardlink by a separate file with identical contents is detected via the inode token */
        ASSERT_OK_ERRNO(unlinkat(tfd, "hardlink_b", 0));
        ASSERT_OK(write_string_file_at(tfd, "hardlink_b", "hardlinked content", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        ASSERT_OK_ERRNO(fchmodat(tfd, "hardlink_b", 0644, 0));
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        ASSERT_ERROR(verify_buffer(&c, tfd, buf, size), EBADMSG);
        ASSERT_EQ(c.n_errors, 1U);

        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.fields &= ~MANIFEST_FIELD_HARDLINK;
        ASSERT_OK(verify_buffer(&c, tfd, buf, size));

        /* Symlink target changes are detected */
        ASSERT_OK_ERRNO(unlinkat(tfd, "symlink", 0));
        ASSERT_OK_ERRNO(symlinkat("empty.txt", tfd, "symlink"));
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.fields &= ~MANIFEST_FIELD_HARDLINK;
        ASSERT_ERROR(verify_buffer(&c, tfd, buf, size), EBADMSG);
        ASSERT_EQ(c.n_errors, 1U);

        /* Objects of unknown media type are ignored, garbage is not */
        const char *trailer = strrchr(buf, 0x1e);
        ASSERT_NOT_NULL(trailer);
        const char *extra = "\x1e{\"mediaType\":\"application/vnd.example.unknown\",\"foo\":\"bar\"}\n";
        _cleanup_free_ char *head = strndup(buf, trailer - buf);
        ASSERT_NOT_NULL(head);
        _cleanup_free_ char *buf4 = strjoin(head, extra, trailer);
        ASSERT_NOT_NULL(buf4);
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.fields = MANIFEST_FIELD_SIZE|MANIFEST_FIELD_HASH;
        ASSERT_OK(verify_buffer(&c, tfd, buf4, strlen(buf4)));

        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        ASSERT_ERROR(verify_buffer(&c, tfd, "garbage", strlen("garbage")), EBADMSG);

        /* Names we cannot represent are skipped and counted, the caller decides what to make of that */
        ASSERT_OK(write_string_file_at(tfd, "\xff\xfe", "invalid", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        _cleanup_free_ char *buf5 = NULL;
        size_t size5;
        ASSERT_OK(generate(&c, tfd, &buf5, &size5));
        ASSERT_EQ(c.n_skipped, 1U);
        ASSERT_EQ(c.n_metadata_omitted, 0U);
}

TEST(manifest_omitted) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;

        ASSERT_OK(tfd = make_tree(&t));

        /* Inodes and metadata we cannot read are skipped or omitted and counted, the caller decides what to
         * make of that */
        ASSERT_OK_ERRNO(fchmodat(tfd, "regular.txt", 0000, 0));
        ASSERT_OK_ERRNO(fchmodat(tfd, "subdir", 0000, 0));
        _cleanup_close_ int probe_fd = openat(tfd, "regular.txt", O_RDONLY|O_CLOEXEC);
        if (probe_fd >= 0) {
                ASSERT_OK_ERRNO(fchmodat(tfd, "subdir", 0755, 0));
                return (void) log_tests_skipped("Privileged enough to read inaccessible files");
        }
        ASSERT_EQ(errno, EACCES);

        static const struct {
                ManifestFormat format;
                uint64_t n_skipped;
                uint64_t n_metadata_omitted;
        } table[] = {
                /* The inaccessible directory is skipped in all formats */
                { MANIFEST_FORMAT_LIST,       1, 0 },
                { MANIFEST_FORMAT_MTREE,      1, 1 },
                /* SHA256SUMS also skips the symlink and the fifo, and files it cannot hash */
                { MANIFEST_FORMAT_SHA256SUMS, 4, 0 },
                { MANIFEST_FORMAT_UAPI16,     1, 1 },
        };

        FOREACH_ELEMENT(i, table) {
                _cleanup_(manifest_context_done) ManifestContext c;
                _cleanup_free_ char *buf = NULL;
                size_t size;

                context_init(&c, i->format);
                ASSERT_OK(generate(&c, tfd, &buf, &size));
                ASSERT_EQ(c.n_skipped, i->n_skipped);
                ASSERT_EQ(c.n_metadata_omitted, i->n_metadata_omitted);
        }

        /* Make sure we can clean up */
        ASSERT_OK_ERRNO(fchmodat(tfd, "subdir", 0755, 0));
}

static int dispatch_one(const char *json, size_t n, Uapi16Object *ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        ASSERT_OK(sd_json_parse(json, /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        return dispatch_uapi16_object(v, n, SD_JSON_LOG, ret);
}

TEST(uapi16_dispatch) {
        _cleanup_(uapi16_object_done) Uapi16Object o = UAPI16_OBJECT_NULL;

        /* null is equivalent to an absent field */
        ASSERT_OK(dispatch_one("{\"name\":\"a\",\"type\":null,\"size\":null,\"mode\":null,\"sha256\":null,\"contents\":null,"
                               "\"extendedAttributes\":null,\"validSinceUSec\":null,\"validity\":null}", 1, &o));
        ASSERT_EQ(o.type, (mode_t) S_IFREG);
        ASSERT_EQ(o.size, UINT64_MAX);
        ASSERT_EQ(o.valid_since_usec, 0U);
        ASSERT_FALSE(o.user_xattrs_set);
        ASSERT_OK(uapi16_object_check_validity(&o));
        uapi16_object_done(&o);

        /* Validity window and enum */
        ASSERT_OK(dispatch_one("{\"name\":\"a\",\"validity\":\"frobnicated\"}", 1, &o));
        ASSERT_EQ(o.validity, UAPI16_GOOD); /* Unknown values are treated like "good" */
        uapi16_object_done(&o);
        ASSERT_OK(dispatch_one("{\"name\":\"a\",\"validity\":\"stepping-stone\"}", 1, &o));
        ASSERT_EQ(o.validity, UAPI16_GOOD); /* Dropped from the specification, hence unknown now */
        uapi16_object_done(&o);
        ASSERT_OK(dispatch_one("{\"name\":\"a\",\"validity\":\"revoked\"}", 1, &o));
        ASSERT_ERROR(uapi16_object_check_validity(&o), EHWPOISON);
        uapi16_object_done(&o);
        ASSERT_OK(dispatch_one("{\"name\":\"a\",\"validSinceUSec\":1,\"validUntilUSec\":2}", 1, &o));
        ASSERT_EQ(o.valid_since_usec, 1U);
        ASSERT_EQ(o.valid_until_usec, 2U);
        ASSERT_ERROR(uapi16_object_check_validity(&o), ESTALE);
        uapi16_object_done(&o);
        _cleanup_free_ char *future = asprintf_safe("{\"name\":\"a\",\"validSinceUSec\":" USEC_FMT "}", now(CLOCK_REALTIME) + USEC_PER_DAY);
        ASSERT_NOT_NULL(future);
        ASSERT_OK(dispatch_one(future, 1, &o));
        ASSERT_ERROR(uapi16_object_check_validity(&o), ESTALE);
        uapi16_object_done(&o);

        /* Fields not permitted on the inode type, or contradicting each other */
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"type\":\"fifo\",\"size\":1}", 1, &o), EBADMSG);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"type\":\"reg\",\"major\":1}", 1, &o), EBADMSG);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"type\":\"lnk\",\"mode\":420}", 1, &o), EBADMSG);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"type\":\"dir\",\"inodeToken\":1}", 1, &o), EBADMSG);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"type\":\"sock\",\"contents\":[{\"file\":\"b\"}]}", 1, &o), EBADMSG);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"type\":\"dir\",\"gptLabel\":\"foo\"}", 1, &o), EBADMSG);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"gptDiskUuid\":\"0fc63daf-8483-4772-8e79-3d69d8477de4\"}", 1, &o), EBADMSG);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"readOnly\":true,\"mode\":420}", 1, &o), EBADMSG);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"readOnly\":false,\"mode\":292}", 1, &o), EBADMSG);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"gptFlags\":0,\"gptFlagNoAuto\":true}", 1, &o), EBADMSG);

        ASSERT_OK(dispatch_one("{\"mediaType\":\"" UAPI16_MANIFEST_MEDIA_TYPE "\",\"gptDiskUuid\":\"0fc63daf-8483-4772-8e79-3d69d8477de4\"}", 0, &o));
        ASSERT_TRUE(o.gpt_disk_uuid_set);
        uapi16_object_done(&o);
        ASSERT_OK(dispatch_one("{\"name\":\"a\",\"readOnly\":true,\"mode\":292,\"gptFlags\":9223372036854775808,\"gptFlagNoAuto\":true}", 1, &o));
        uapi16_object_done(&o);

        /* The GPT label limit is in UTF-16 code units, not bytes */
        _cleanup_free_ char *label36 = NULL, *label37 = NULL;
        for (unsigned i = 0; i < 36; i++)
                ASSERT_NOT_NULL(strextend(&label36, "\xc3\xa4"));
        ASSERT_NOT_NULL(label37 = strjoin(label36, "x"));
        _cleanup_free_ char *j36 = strjoin("{\"name\":\"a\",\"gptLabel\":\"", label36, "\"}"),
                *j37 = strjoin("{\"name\":\"a\",\"gptLabel\":\"", label37, "\"}");
        ASSERT_NOT_NULL(j36);
        ASSERT_NOT_NULL(j37);
        ASSERT_OK(dispatch_one(j36, 1, &o));
        uapi16_object_done(&o);
        ASSERT_ERROR(dispatch_one(j37, 1, &o), EINVAL);

        /* An empty slice at the very end of the source is fine */
        ASSERT_OK(dispatch_one("{\"name\":\"a\",\"size\":0,\"contents\":[{\"file\":\"b\",\"offset\":5,\"originalSize\":5}]}", 1, &o));
        uapi16_object_done(&o);

        /* Encodings are case-insensitive, and no encoding is expressed by leaving the field unset, hence
         * HTTP's "identity" is refused */
        ASSERT_OK(dispatch_one("{\"name\":\"a\",\"contents\":[{\"file\":\"b\",\"encoding\":\"GZip\"}]}", 1, &o));
        ASSERT_EQ(o.n_contents, 1U);
        ASSERT_STREQ(o.contents[0].encoding, "gzip");
        uapi16_object_done(&o);
        ASSERT_OK(dispatch_one("{\"name\":\"a\",\"contents\":[{\"file\":\"b\",\"encoding\":null}]}", 1, &o));
        ASSERT_EQ(o.n_contents, 1U);
        ASSERT_NULL(o.contents[0].encoding);
        uapi16_object_done(&o);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"contents\":[{\"file\":\"b\",\"encoding\":\"identity\"}]}", 1, &o), EINVAL);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"contents\":[{\"file\":\"b\",\"encoding\":\"Identity\"}]}", 1, &o), EINVAL);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"contents\":[{\"file\":\"b\",\"encoding\":\"\"}]}", 1, &o), EINVAL);

        /* Extended attributes: sorted, both encodings, unknown namespaces ignored */
        ASSERT_OK(dispatch_one("{\"name\":\"a\",\"extendedAttributes\":{\"security\":{\"selinux\":{\"text\":\"foo\"}},"
                               "\"user\":{\"b\":{\"base64\":\"AAECAw==\"},\"a\":{\"text\":\"hello\"},\"e\":{\"text\":\"\"},\"u\":{\"base64\":\"-_8=\"}}}}", 1, &o));
        ASSERT_TRUE(o.user_xattrs_set);
        ASSERT_EQ(o.n_user_xattrs, 4U);
        ASSERT_STREQ(o.user_xattrs[0].name, "a");
        ASSERT_EQ(iovec_memcmp(&o.user_xattrs[0].value, &IOVEC_MAKE_STRING("hello")), 0);
        ASSERT_STREQ(o.user_xattrs[1].name, "b");
        ASSERT_EQ(iovec_memcmp(&o.user_xattrs[1].value, &IOVEC_MAKE("\x00\x01\x02\x03", 4)), 0);
        ASSERT_STREQ(o.user_xattrs[2].name, "e");
        ASSERT_EQ(o.user_xattrs[2].value.iov_len, 0U);
        ASSERT_STREQ(o.user_xattrs[3].name, "u");
        ASSERT_EQ(iovec_memcmp(&o.user_xattrs[3].value, &IOVEC_MAKE("\xfb\xff", 2)), 0);

        /* … and they round-trip */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *x = NULL;
        ASSERT_OK(uapi16_xattrs_build_json(o.user_xattrs, o.n_user_xattrs, &x));
        _cleanup_free_ char *xs = NULL;
        ASSERT_OK(sd_json_variant_format(x, /* flags= */ 0, &xs));
        ASSERT_STREQ(xs, "{\"user\":{\"a\":{\"text\":\"hello\"},\"b\":{\"base64\":\"AAECAw==\"},\"e\":{\"text\":\"\"},\"u\":{\"base64\":\"+/8=\"}}}");
        uapi16_object_done(&o);

        ASSERT_OK(dispatch_one("{\"name\":\"a\",\"extendedAttributes\":{\"user\":{}}}", 1, &o));
        ASSERT_TRUE(o.user_xattrs_set);
        ASSERT_EQ(o.n_user_xattrs, 0U);
        uapi16_object_done(&o);
        ASSERT_OK(dispatch_one("{\"name\":\"a\",\"extendedAttributes\":{\"user\":null}}", 1, &o));
        ASSERT_FALSE(o.user_xattrs_set);
        uapi16_object_done(&o);

        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"extendedAttributes\":{\"user\":{\"a\":{\"text\":\"x\",\"base64\":\"eA==\"}}}}", 1, &o), EINVAL);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"extendedAttributes\":{\"user\":{\"a\":{}}}}", 1, &o), EINVAL);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"extendedAttributes\":{\"user\":{\"\":{\"text\":\"x\"}}}}", 1, &o), EINVAL);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"extendedAttributes\":{\"user\":{\"a\\u0001\":{\"text\":\"x\"}}}}", 1, &o), EINVAL);
        ASSERT_ERROR(dispatch_one("{\"name\":\"a\",\"extendedAttributes\":{\"user\":[]}}", 1, &o), EINVAL);
}

static bool try_set_special_xattr(int dir_fd, const char *name) {
        int r;

        /* Traditionally Linux only allows "user." attributes on regular files and directories, but recently
         * gained support for them on sockets, and might extend this further. Hence try and see. */
        r = xsetxattr(dir_fd, name, /* at_flags= */ 0, "user.special", "yes");
        if (r == -EPERM || ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                log_info_errno(r, "Cannot set \"user.\" extended attribute on '%s', expecting none: %m", name);
                return false;
        }
        ASSERT_OK(r);
        return true;
}

static void assert_special_xattr(const char *buf, const char *name, bool have) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = find_object(buf, name);
        _cleanup_free_ char *s = NULL;

        ASSERT_NOT_NULL(v);
        ASSERT_OK(sd_json_variant_format(sd_json_variant_by_key(v, "extendedAttributes"), /* flags= */ 0, &s));
        ASSERT_STREQ(s, have ? "{\"user\":{\"special\":{\"text\":\"yes\"}}}" : "{\"user\":{}}");
}

TEST(manifest_uapi16_xattr) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;
        _cleanup_free_ char *buf = NULL;
        size_t size;
        int r;

        ASSERT_OK(tfd = make_tree(&t));

        r = xsetxattr(tfd, "regular.txt", /* at_flags= */ 0, "user.mime_type", "text/plain");
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return (void) log_tests_skipped_errno(r, "File system does not support user extended attributes");
        ASSERT_OK(r);
        ASSERT_OK(xsetxattr_full(tfd, "regular.txt", /* at_flags= */ 0, "user.blob", "\x00\x01\x02\x03", 4, /* xattr_flags= */ 0));
        ASSERT_OK(xsetxattr(tfd, "subdir", /* at_flags= */ 0, "user.dir", "yes"));

        /* Also try special inodes, a device node only if we are privileged enough to create one */
        ASSERT_OK_ERRNO(mknodat(tfd, "socket", S_IFSOCK|0600, 0));
        r = RET_NERRNO(mknodat(tfd, "null", S_IFCHR|0600, makedev(1, 3)));
        if (ERRNO_IS_NEG_PRIVILEGE(r))
                log_info_errno(r, "Cannot create device node, skipping: %m");
        else
                ASSERT_OK(r);
        bool have_devnode = r >= 0,
                fifo_xattr = try_set_special_xattr(tfd, "fifo"),
                socket_xattr = try_set_special_xattr(tfd, "socket"),
                devnode_xattr = have_devnode && try_set_special_xattr(tfd, "null");

        _cleanup_(manifest_context_done) ManifestContext c;
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.fields |= MANIFEST_FIELD_USER_XATTR;
        ASSERT_OK(generate(&c, tfd, &buf, &size));
        ASSERT_EQ(c.n_metadata_omitted, 0U);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reg = find_object(buf, "regular.txt");
        ASSERT_NOT_NULL(reg);
        ASSERT_TRUE(sd_json_variant_is_normalized(reg));
        _cleanup_free_ char *s = NULL;
        ASSERT_OK(sd_json_variant_format(sd_json_variant_by_key(reg, "extendedAttributes"), /* flags= */ 0, &s));
        ASSERT_STREQ(s, "{\"user\":{\"blob\":{\"base64\":\"AAECAw==\"},\"mime_type\":{\"text\":\"text/plain\"}}}");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *dir = find_object(buf, "subdir");
        ASSERT_NOT_NULL(dir);
        s = mfree(s);
        ASSERT_OK(sd_json_variant_format(sd_json_variant_by_key(dir, "extendedAttributes"), /* flags= */ 0, &s));
        ASSERT_STREQ(s, "{\"user\":{\"dir\":{\"text\":\"yes\"}}}");

        /* Inodes without attributes are listed with an empty namespace object, symlinks without any, since
         * they cannot carry "user." attributes */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *empty = find_object(buf, "empty.txt"),
                *lnk = find_object(buf, "symlink");
        ASSERT_NOT_NULL(empty);
        s = mfree(s);
        ASSERT_OK(sd_json_variant_format(sd_json_variant_by_key(empty, "extendedAttributes"), /* flags= */ 0, &s));
        ASSERT_STREQ(s, "{\"user\":{}}");
        ASSERT_NOT_NULL(lnk);
        ASSERT_NULL(sd_json_variant_by_key(lnk, "extendedAttributes"));

        assert_special_xattr(buf, "fifo", fifo_xattr);
        assert_special_xattr(buf, "socket", socket_xattr);
        if (have_devnode)
                assert_special_xattr(buf, "null", devnode_xattr);

        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.fields |= MANIFEST_FIELD_USER_XATTR;
        ASSERT_OK(verify_buffer(&c, tfd, buf, size));

        /* Changed, added and removed attributes are detected, but only if requested */
        ASSERT_OK(xsetxattr(tfd, "regular.txt", /* at_flags= */ 0, "user.mime_type", "text/x-c"));
        ASSERT_OK(xsetxattr(tfd, "empty.txt", /* at_flags= */ 0, "user.new", "x"));
        ASSERT_OK(xremovexattr(tfd, "subdir", /* at_flags= */ 0, "user.dir"));
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.fields |= MANIFEST_FIELD_USER_XATTR;
        ASSERT_ERROR(verify_buffer(&c, tfd, buf, size), EBADMSG);
        ASSERT_EQ(c.n_errors, 3U);

        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        ASSERT_OK(verify_buffer(&c, tfd, buf, size));

        /* Attribute names we cannot represent cause the attributes of the inode to be omitted */
        ASSERT_OK(xsetxattr(tfd, "empty.txt", /* at_flags= */ 0, "user.\x01", "x"));
        _cleanup_free_ char *buf2 = NULL;
        size_t size2;
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.fields |= MANIFEST_FIELD_USER_XATTR;
        ASSERT_OK(generate(&c, tfd, &buf2, &size2));
        ASSERT_EQ(c.n_metadata_omitted, 1U);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *empty2 = find_object(buf2, "empty.txt");
        ASSERT_NOT_NULL(empty2);
        ASSERT_NULL(sd_json_variant_by_key(empty2, "extendedAttributes"));
}

#if HAVE_OPENSSL
static const char test_ec_private_key[] =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUHtgg+jYlSw1SGHP\n"
        "9MZwkDvAeGK7C11MZqfDFEHu6PyhRANCAATAeBIb56cVcwPEpjmHtMgIP2emDuul\n"
        "Uss0MAUahizNuwsdCUADqP0p2ZtnsYBYNW11arZ/uDDjeT3Qk6xTEdGq\n"
        "-----END PRIVATE KEY-----\n";

static const char test_ec_certificate[] =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBoTCCAUegAwIBAgIUQCZpFz9fSaGCGZ0CXqkaWN5GKgswCgYIKoZIzj0EAwIw\n"
        "JTEjMCEGA1UEAwwac3lzdGVtZCB0ZXN0LW1hbmlmZXN0LXV0aWwwIBcNMjYwOTE0\n"
        "MTUwMzIzWhgPMjEyNjA4MjExNTAzMjNaMCUxIzAhBgNVBAMMGnN5c3RlbWQgdGVz\n"
        "dC1tYW5pZmVzdC11dGlsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwHgSG+en\n"
        "FXMDxKY5h7TICD9npg7rpVLLNDAFGoYszbsLHQlAA6j9KdmbZ7GAWDVtdWq2f7gw\n"
        "43k90JOsUxHRqqNTMFEwHQYDVR0OBBYEFOS6qnXKagStyWcbtRVVw5qKsk7DMB8G\n"
        "A1UdIwQYMBaAFOS6qnXKagStyWcbtRVVw5qKsk7DMA8GA1UdEwEB/wQFMAMBAf8w\n"
        "CgYIKoZIzj0EAwIDSAAwRQIgPUHB6or3asS2dntLwGDoQ2/LZ47ciHFy6br2+bfq\n"
        "e3MCIQCOsXGmxgfJQxkCVn1xvJIsw0o5uqgJSTmtQctPh+Du1Q==\n"
        "-----END CERTIFICATE-----\n";

static const char test_ed25519_private_key[] =
        "-----BEGIN PRIVATE KEY-----\n"
        "MC4CAQAwBQYDK2VwBCIEIGpz8IMVIuc/uA5D3DrtHeHjGit8aQ2+ef7nv0HNpp3a\n"
        "-----END PRIVATE KEY-----\n";

static const char test_ed25519_certificate[] =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBcTCCASOgAwIBAgIUQ7Rh+pqym8TUwFBLeAEqGobICbQwBQYDK2VwMC0xKzAp\n"
        "BgNVBAMMInN5c3RlbWQgdGVzdC1tYW5pZmVzdC11dGlsIGVkMjU1MTkwIBcNMjYw\n"
        "OTIyMTIyODM3WhgPMjEyNjA4MjkxMjI4MzdaMC0xKzApBgNVBAMMInN5c3RlbWQg\n"
        "dGVzdC1tYW5pZmVzdC11dGlsIGVkMjU1MTkwKjAFBgMrZXADIQC+4xo6+p15/YyR\n"
        "7m2F4udaXRtX7pZawZuZ8lkf/AC67aNTMFEwHQYDVR0OBBYEFBwqhFuJLeDXDTFC\n"
        "0eECXh1IAOouMB8GA1UdIwQYMBaAFBwqhFuJLeDXDTFC0eECXh1IAOouMA8GA1Ud\n"
        "EwEB/wQFMAMBAf8wBQYDK2VwA0EALekT5ufk7cYnbL0rRqEPT4QSwI4d1PxAhClV\n"
        "DRsBeyQmU7+JHOJyWB2zHtlOjq7EqJEvehJ5WTD5JQ3ZXVC5Bg==\n"
        "-----END CERTIFICATE-----\n";

static char* strip_ansi(const char *s) {
        _cleanup_free_ char *buf = NULL;
        size_t n = 0;

        /* Removes CSI sequences (ESC [ … final byte) */

        ASSERT_NOT_NULL(buf = new(char, strlen(s) + 1));

        for (const char *p = s; *p; p++) {
                if (p[0] == '\x1b' && p[1] == '[') {
                        p += 2;
                        while (*p && !(*p >= 0x40 && *p <= 0x7e))
                                p++;
                        if (!*p)
                                break;
                        continue;
                }

                buf[n++] = *p;
        }

        buf[n] = 0;
        return TAKE_PTR(buf);
}

static void load_key_pair(
                int tfd,
                const char *t,
                const char *private_key_pem,
                const char *certificate_pem,
                X509 **ret_certificate,
                EVP_PKEY **ret_private_key,
                OpenSSLAskPasswordUI **ret_ui) {

        _cleanup_free_ char *key_path = NULL, *cert_path = NULL;
        ASSERT_NOT_NULL(key_path = path_join(t, "key.pem"));
        ASSERT_NOT_NULL(cert_path = path_join(t, "cert.pem"));
        ASSERT_OK(write_string_file(key_path, private_key_pem, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MODE_0600));
        ASSERT_OK(write_string_file(cert_path, certificate_pem, WRITE_STRING_FILE_CREATE));

        ASSERT_OK(openssl_load_x509_certificate(OPENSSL_CERTIFICATE_SOURCE_FILE, NULL, cert_path, ret_certificate));
        ASSERT_OK(openssl_load_private_key(
                                  OPENSSL_KEY_SOURCE_FILE,
                                  NULL,
                                  key_path,
                                  &(AskPasswordRequest) {
                                          .tty_fd = -EBADF,
                                          .until = USEC_INFINITY,
                                          .hup_fd = -EBADF,
                                  },
                                  ret_private_key,
                                  ret_ui));

        /* The key and certificate files are not part of the manifest, hence remove them again */
        ASSERT_OK_ERRNO(unlinkat(tfd, "key.pem", 0));
        ASSERT_OK_ERRNO(unlinkat(tfd, "cert.pem", 0));
}

static int count_objects(Uapi16Object *o, size_t index, void *userdata) {
        size_t *n = ASSERT_PTR(userdata);

        ASSERT_NOT_NULL(o);
        if (index == 0)
                ASSERT_STREQ(o->media_type, UAPI16_MANIFEST_MEDIA_TYPE);

        (*n)++;
        return 0;
}

static int read_buffer(const char *buf, size_t size, X509 *const *certificates, size_t n_certificates, size_t *ret_n_objects) {
        _cleanup_fclose_ FILE *f = NULL;

        ASSERT_NOT_NULL(f = fmemopen_unlocked((void*) buf, size, "r"));

        *ret_n_objects = 0;
        return uapi16_manifest_read(f, certificates, n_certificates, count_objects, ret_n_objects);
}

static void test_signed_one(
                int tfd,
                X509 *certificate,
                EVP_PKEY *private_key,
                X509 *other_certificate) {

        _cleanup_(manifest_context_done) ManifestContext c;
        _cleanup_free_ char *buf = NULL;
        size_t size;

        /* Sign with the specified key */
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.certificate = certificate;
        c.private_key = private_key;
        ASSERT_OK(generate(&c, tfd, &buf, &size));

        /* The signature object is the second to last record, the trailer the last */
        char *trailer = strrchr(buf, 0x1e);
        ASSERT_NOT_NULL(trailer);
        ASSERT_NOT_NULL(strstr(trailer, "\"mediaType\":\"" UAPI16_TRAILER_MEDIA_TYPE "\""));

        _cleanup_free_ char *head = strndup(buf, trailer - buf);
        ASSERT_NOT_NULL(head);
        const char *signature = strrchr(head, 0x1e);
        ASSERT_NOT_NULL(signature);
        ASSERT_NOT_NULL(strstr(signature, "\"mediaType\":\"" UAPI16_SIGNATURE_MEDIA_TYPE "\""));
        ASSERT_NOT_NULL(strstr(signature, "\"mechanism\":\"pkcs7\""));

        uint8_t fp[X509_FINGERPRINT_SIZE];
        ASSERT_OK(x509_fingerprint(certificate, fp));
        _cleanup_free_ char *fp_hex = hexmem(fp, sizeof(fp));
        ASSERT_NOT_NULL(fp_hex);
        ASSERT_NOT_NULL(strstr(signature, fp_hex));

        /* Verifies with the right certificate, from a pipe too */
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.certificates = &certificate;
        c.n_certificates = 1;
        ASSERT_OK(verify_pipe(&c, tfd, buf, size));

        /* Verifies without certificate, signature is simply ignored then */
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        ASSERT_OK(verify_buffer(&c, tfd, buf, size));

        /* Does not verify with a different certificate */
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.certificates = &other_certificate;
        c.n_certificates = 1;
        ASSERT_ERROR(verify_buffer(&c, tfd, buf, size), EBADMSG);

        /* The generic reader accepts the signature if any of the specified certificates matches, and
         * reports all file objects (including the leading one) to the handler */
        size_t n_objects;
        ASSERT_OK(read_buffer(buf, size, (X509*[]) { other_certificate, certificate }, 2, &n_objects));
        ASSERT_GT(n_objects, 1U);
        size_t n_objects_unverified;
        ASSERT_OK(read_buffer(buf, size, /* certificates= */ NULL, /* n_certificates= */ 0, &n_objects_unverified));
        ASSERT_EQ(n_objects_unverified, n_objects);
        ASSERT_ERROR(read_buffer(buf, size, &other_certificate, 1, &n_objects), EBADMSG);

        /* An unsigned manifest does not verify if a certificate is specified */
        _cleanup_free_ char *unsigned_buf = NULL;
        size_t unsigned_size;
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        ASSERT_OK(generate(&c, tfd, &unsigned_buf, &unsigned_size));
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.certificates = &certificate;
        c.n_certificates = 1;
        ASSERT_ERROR(verify_buffer(&c, tfd, unsigned_buf, unsigned_size), EBADMSG);

        /* Flipping a byte in the payload breaks the signature (the tree still matches the modified
         * manifest, hence the mode 0644 → 0645 change is detected as mismatch too) */
        _cleanup_free_ char *tampered = NULL;
        ASSERT_NOT_NULL(tampered = strreplace(buf, "\"size\":11", "\"size\":12"));
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.certificates = &certificate;
        c.n_certificates = 1;
        ASSERT_ERROR(verify_buffer(&c, tfd, tampered, strlen(tampered)), EBADMSG);

        /* Objects between the signature object and the trailer are not covered by the signature, and
         * ignored if their media type is unknown */
        _cleanup_free_ char *inserted = strjoin(head, "\x1e{\"mediaType\":\"application/x-test-extra\",\"name\":\"extra.txt\"}\n", trailer);
        ASSERT_NOT_NULL(inserted);
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.certificates = &certificate;
        c.n_certificates = 1;
        ASSERT_OK(verify_buffer(&c, tfd, inserted, strlen(inserted)));

        /* OpenPGP signatures are not supported and ignored: if there's a PKCS#7 signature too, before or
         * after it, that one is used */
#define OPENPGP_SIGNATURE "\x1e{\"mediaType\":\"" UAPI16_SIGNATURE_MEDIA_TYPE "\",\"mechanism\":\"openpgp\",\"data\":\"AAEC\"}\n"
        _cleanup_free_ char *payload = strndup(head, signature - head);
        ASSERT_NOT_NULL(payload);
        _cleanup_free_ char *openpgp_after = strjoin(head, OPENPGP_SIGNATURE, trailer);
        ASSERT_NOT_NULL(openpgp_after);
        _cleanup_free_ char *openpgp_before = strjoin(payload, OPENPGP_SIGNATURE, signature, trailer);
        ASSERT_NOT_NULL(openpgp_before);
        _cleanup_free_ char *openpgp_only = strjoin(payload, OPENPGP_SIGNATURE, trailer);
        ASSERT_NOT_NULL(openpgp_only);
#undef OPENPGP_SIGNATURE

        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.certificates = &certificate;
        c.n_certificates = 1;
        ASSERT_OK(verify_buffer(&c, tfd, openpgp_after, strlen(openpgp_after)));
        ASSERT_OK(read_buffer(openpgp_before, strlen(openpgp_before), &certificate, 1, &n_objects));

        /* … and if there's only an OpenPGP signature this is as if there was no signature at all */
        ASSERT_ERROR(read_buffer(openpgp_only, strlen(openpgp_only), &certificate, 1, &n_objects), EBADMSG);
        ASSERT_OK(read_buffer(openpgp_only, strlen(openpgp_only), /* certificates= */ NULL, /* n_certificates= */ 0, &n_objects));

        /* But a file object after the signature is refused, and so is anything after the trailer */
        _cleanup_free_ char *file_after = strjoin(head, "\x1e{\"name\":\"extra.txt\"}\n", trailer);
        ASSERT_NOT_NULL(file_after);
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.certificates = &certificate;
        c.n_certificates = 1;
        ASSERT_ERROR(verify_buffer(&c, tfd, file_after, strlen(file_after)), EBADMSG);

        _cleanup_free_ char *appended = strjoin(buf, "\x1e{\"name\":\"extra.txt\"}\n");
        ASSERT_NOT_NULL(appended);
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.certificates = &certificate;
        c.n_certificates = 1;
        ASSERT_ERROR(verify_buffer(&c, tfd, appended, strlen(appended)), EBADMSG);

        /* A colored rendering carries the same signature, which covers the color-free bytes */
        _cleanup_free_ char *colored = NULL;
        size_t colored_size;
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.certificate = certificate;
        c.private_key = private_key;
        c.color = true;
        c.json_format_flags = SD_JSON_FORMAT_COLOR;
        ASSERT_OK(generate(&c, tfd, &colored, &colored_size));
        ASSERT_NOT_NULL(strchr(colored, '\x1b'));

        _cleanup_free_ char *stripped = strip_ansi(colored);
        ASSERT_NULL(strchr(stripped, '\x1b'));
        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.certificates = &certificate;
        c.n_certificates = 1;
        ASSERT_OK(verify_buffer(&c, tfd, stripped, strlen(stripped)));
}

TEST(manifest_uapi16_signed) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;
        _cleanup_free_ char *buf = NULL;
        size_t size;

        if (dlopen_libcrypto(LOG_INFO) < 0)
                return (void) log_tests_skipped("OpenSSL not available");

        ASSERT_OK(tfd = make_tree(&t));

        _cleanup_(X509_freep) X509 *ec_certificate = NULL, *ed25519_certificate = NULL;
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *ec_private_key = NULL, *ed25519_private_key = NULL;
        _cleanup_(openssl_ask_password_ui_freep) OpenSSLAskPasswordUI *ec_ui = NULL, *ed25519_ui = NULL;
        load_key_pair(tfd, t, test_ec_private_key, test_ec_certificate, &ec_certificate, &ec_private_key, &ec_ui);
        load_key_pair(tfd, t, test_ed25519_private_key, test_ed25519_certificate, &ed25519_certificate, &ed25519_private_key, &ed25519_ui);

        /* Signing (which is done if a private key is set) requires a certificate, and only works for uapi16 */
        _cleanup_(manifest_context_done) ManifestContext c;
        context_init(&c, MANIFEST_FORMAT_UAPI16);
        c.private_key = ec_private_key;
        ASSERT_ERROR(generate(&c, tfd, &buf, &size), EINVAL);

        manifest_context_done(&c);
        context_init(&c, MANIFEST_FORMAT_MTREE);
        c.certificate = ec_certificate;
        c.private_key = ec_private_key;
        ASSERT_ERROR(generate(&c, tfd, &buf, &size), EINVAL);

        /* ECDSA signs directly over the data, Ed25519 needs signed attributes (RFC 8419), exercise both */
        test_signed_one(tfd, ec_certificate, ec_private_key, ed25519_certificate);
        test_signed_one(tfd, ed25519_certificate, ed25519_private_key, ec_certificate);
}

TEST(uapi16_load_voa_certificates) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int rfd = -EBADF;
        X509 **certificates = NULL;
        size_t n_certificates = 0;

        CLEANUP_ARRAY(certificates, n_certificates, uapi16_certificates_free);

        if (dlopen_libcrypto(LOG_INFO) < 0)
                return (void) log_tests_skipped("OpenSSL not available");

        ASSERT_OK(rfd = mkdtemp_open("/tmp/test-manifest-voa.XXXXXX", O_PATH, &t));
        ASSERT_OK(write_string_file_at(rfd, "etc/os-release", "ID=foo\nVERSION_ID=47\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        /* Nothing installed */
        ASSERT_OK(uapi16_load_voa_certificates(rfd, "default", &certificates, &n_certificates));
        ASSERT_EQ(n_certificates, 0U);

        /* One certificate for the bare OS ID, one for the exact one, and one that is not a certificate */
        ASSERT_OK(write_string_file_at(rfd, "usr/share/voa/foo/manifest/default/x509/a-certificate.pem", test_ec_certificate, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));
        ASSERT_OK(write_string_file_at(rfd, "etc/voa/foo:47/manifest/default/x509/b-certificate.pem", test_ec_certificate, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));
        ASSERT_OK(write_string_file_at(rfd, "usr/share/voa/foo/manifest/default/x509/c-certificate.pem", "garbage\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));
        ASSERT_OK(uapi16_load_voa_certificates(rfd, "default", &certificates, &n_certificates));
        ASSERT_EQ(n_certificates, 2U);
        uapi16_certificates_free(TAKE_PTR(certificates), TAKE_GENERIC(n_certificates, size_t, 0));

        /* Other contexts are separate */
        ASSERT_OK(uapi16_load_voa_certificates(rfd, "sysupdate", &certificates, &n_certificates));
        ASSERT_EQ(n_certificates, 0U);

        /* A mask in any load path applies to all of them */
        ASSERT_OK(mkdirat_parents(rfd, "run/voa/foo/manifest/default/x509/a-certificate.pem", 0755));
        ASSERT_OK_ERRNO(symlinkat("/dev/null", rfd, "run/voa/foo/manifest/default/x509/a-certificate.pem"));
        ASSERT_OK(uapi16_load_voa_certificates(rfd, "default", &certificates, &n_certificates));
        ASSERT_EQ(n_certificates, 1U);
}
#endif

DEFINE_TEST_MAIN(LOG_DEBUG);
