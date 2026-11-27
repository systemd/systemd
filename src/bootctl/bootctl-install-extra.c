/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "bootctl-install.h"
#include "bootctl-install-extra.h"
#include "bootctl-util.h"
#include "chase.h"
#include "dirent-util.h"
#include "efi-api.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "json-util.h"
#include "log.h"
#include "manifest-util.h"
#include "memstream-util.h"
#include "path-util.h"
#include "sha256.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "uapi16-manifest.h"
#include "utf8.h"

void extra_file_array_free(ExtraFile *files, size_t n) {
        FOREACH_ARRAY(f, files, n) {
                free(f->path);
                free(f->source_path);
                safe_close(f->source_fd);
        }

        free(files);
}
static bool extra_path_equal(const char *a, const char *b) {
        assert(a);
        assert(b);

        /* VFAT is case insensitive, hence two paths that only differ in case name the same file.
         * strcasecmp() cannot be used for the comparison, because it follows the locale: in a Turkish
         * locale it does not treat "I" and "i" as the same letter. */
        return ascii_strcasecmp_nn(a, strlen(a), b, strlen(b)) == 0;
}

static const char* extra_path_startswith(const char *path, const char *prefix) {
        assert(path);
        assert(prefix);

        size_t n = strlen(prefix);
        if (strlen(path) < n || ascii_strcasecmp_n(path, prefix, n) != 0)
                return NULL;

        return path + n;
}

static bool extra_path_endswith(const char *path, const char *suffix) {
        assert(path);
        assert(suffix);

        size_t n = strlen(path), m = strlen(suffix);
        return n >= m && ascii_strcasecmp_n(path + n - m, suffix, m) == 0;
}

static bool extra_filename_is_valid(const char *name) {
        assert(name);

        /* The manifest only stores UTF-8 file names. */
        if (!filename_is_valid(name) || !utf8_is_valid(name))
                return false;

        /* VFAT refuses control characters and the characters listed below, and it strips trailing dots and
         * spaces from file names. */
        for (const char *p = name; *p; p++)
                if ((unsigned char) *p < 0x20 || *p == 0x7f || strchr("\"*:<>?\\|", *p))
                        return false;

        return !endswith(name, ".") && !endswith(name, " ");
}

static bool extra_path_is_valid(const char *path) {
        assert(path);

        if (path_is_absolute(path) || !path_is_normalized(path))
                return false;

        for (const char *p = path;;) {
                const char *e;
                int r;

                r = path_find_first_component(&p, /* accept_dot_dot= */ false, &e);
                if (r < 0)
                        return false;
                if (r == 0)
                        return true;

                _cleanup_free_ char *component = strndup(e, r);
                if (!component || !extra_filename_is_valid(component))
                        return false;
        }
}

static int extra_file_compare(const ExtraFile *a, const ExtraFile *b) {
        return ascii_strcasecmp_nn(a->path, strlen(a->path), b->path, strlen(b->path));
}

ExtraFile* extra_file_find(ExtraFile *files, size_t n, const char *path) {
        assert(path);

        path = skip_leading_slash(path);

        FOREACH_ARRAY(f, files, n)
                if (extra_path_equal(f->path, path))
                        return f;

        return NULL;
}

bool extra_manifest_lists(InstallContext *c, const char *path, const uint8_t hash[static SHA256_DIGEST_SIZE]) {
        assert(c);
        assert(path);

        path = skip_leading_slash(path);

        FOREACH_ARRAY(m, c->extra_manifest, c->n_extra_manifest)
                if (extra_path_equal(m->path, path) && memcmp(m->hash, hash, SHA256_DIGEST_SIZE) == 0)
                        return true;

        return false;
}

void extra_manifest_forget(InstallContext *c, const char *path) {
        assert(c);
        assert(path);

        path = skip_leading_slash(path);

        for (size_t i = 0; i < c->n_extra_manifest;) {
                ExtraFile *m = c->extra_manifest + i;

                if (!extra_path_equal(m->path, path)) {
                        i++;
                        continue;
                }

                free(m->path);
                memmove(m, m + 1, (c->n_extra_manifest - i - 1) * sizeof(ExtraFile));
                c->n_extra_manifest--;
        }
}

static void extra_manifest_retain(InstallContext *c, const char *path, const uint8_t hash[static SHA256_DIGEST_SIZE]) {
        assert(c);
        assert(path);

        /* The file in the ESP has the specified hash. Every other hash that the manifests list for the path
         * is outdated. */

        path = skip_leading_slash(path);

        for (size_t i = 0; i < c->n_extra_manifest;) {
                ExtraFile *m = c->extra_manifest + i;

                if (!extra_path_equal(m->path, path)) {
                        i++;
                        continue;
                }

                if (memcmp(m->hash, hash, SHA256_DIGEST_SIZE) == 0) {
                        m->pending = false;
                        i++;
                        continue;
                }

                free(m->path);
                memmove(m, m + 1, (c->n_extra_manifest - i - 1) * sizeof(ExtraFile));
                c->n_extra_manifest--;
        }
}

static bool extra_path_is_entry_point(const char *path) {
        const char *e;

        assert(path);

        /* The firmware starts EFI/BOOT/BOOT<ARCH>.EFI and the binary that is registered in the boot loader
         * list directly. install_extra_files() installs them after the files that they load. */
        e = extra_path_startswith(path, "EFI/BOOT/BOOT") ?: extra_path_startswith(path, "EFI/systemd/boot");
        return e && !strchr(e, '/') && extra_path_endswith(e, ".efi");
}

static int extra_files_add(
                InstallContext *c,
                const char *path,
                const char *source_path,
                int source_fd) {

        int r;

        assert(c);
        assert(path);
        assert(source_path);
        assert(source_fd >= 0);

        if (c->n_extra_files >= EXTRA_FILES_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG),
                                       "More than %u files below '%s', refusing.", EXTRA_FILES_MAX, EXTRA_FILES_DIR);

        /* bootctl installs the systemd-boot binaries as EFI/systemd/systemd-boot*, and it writes the
         * manifests. An extra file must not replace them. */
        if (extra_path_startswith(path, "EFI/systemd/systemd-boot") ||
            extra_path_equal(path, INSTALL_MANIFEST_DIR "/" INSTALL_MANIFEST_NAME) ||
            extra_path_equal(path, INSTALL_MANIFEST_DIR "/" INSTALL_MANIFEST_PENDING_NAME))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "'%s' uses a file name that is reserved for systemd-boot, refusing.", source_path);

        /* A UAPI.16 manifest cannot list a file in the root directory whose name starts with
         * "Uapi16Manifest". */
        if (!uapi16_name_is_valid(path))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "The manifest of the installed files cannot list '%s', refusing.", source_path);

        _cleanup_free_ char *p = strdup(path), *sp = strdup(source_path);
        if (!p || !sp)
                return log_oom();

        _cleanup_close_ int fd = fd_reopen(source_fd, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open '%s': %m", source_path);

        uint8_t hash[SHA256_DIGEST_SIZE];
        r = sha256_fd(fd, UINT64_MAX, hash);
        if (r < 0)
                return log_error_errno(r, "Failed to hash '%s': %m", source_path);

        if (!GREEDY_REALLOC(c->extra_files, c->n_extra_files + 1))
                return log_oom();

        ExtraFile *f = c->extra_files + c->n_extra_files++;
        *f = (ExtraFile) {
                .path = TAKE_PTR(p),
                .source_path = TAKE_PTR(sp),
                .source_fd = TAKE_FD(fd),
        };
        memcpy(f->hash, hash, sizeof(hash));

        return 0;
}

static int load_extra_directory(
                InstallContext *c,
                int root_fd,
                const char *source,
                const char *prefix,
                unsigned depth) {

        int r;

        assert(c);
        assert(source);

        /* Symlinks are followed, so that a package can link the files of another package into
         * EXTRA_FILES_DIR. A symlink to a parent directory hence makes the hierarchy infinitely deep. */
        if (depth > EXTRA_FILES_DEPTH_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(ELOOP),
                                       "Directory '%s' is nested more than %u levels deep, refusing.", source, EXTRA_FILES_DEPTH_MAX);

        _cleanup_closedir_ DIR *d = NULL;
        r = chase_and_opendirat(root_fd, root_fd, source, CHASE_MUST_BE_DIRECTORY, /* ret_path= */ NULL, &d);
        if (r < 0)
                return log_error_errno(r, "Failed to open directory '%s': %m", source);

        FOREACH_DIRENT_ALL(de, d, return log_error_errno(errno, "Failed to read directory '%s': %m", source)) {
                if (dot_or_dot_dot(de->d_name))
                        continue;

                _cleanup_free_ char *child = path_join(source, de->d_name);
                if (!child)
                        return log_oom();

                if (!extra_filename_is_valid(de->d_name))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "'%s' is not a valid file name for the ESP, refusing.", child);

                _cleanup_free_ char *path = path_join(prefix, de->d_name);
                if (!path)
                        return log_oom();

                /* install_binaries() installs systemd-boot<arch>.efi.signed as systemd-boot<arch>.efi, and
                 * it skips systemd-boot<arch>.efi if the .efi.signed file exists. The extra files follow
                 * the same rule. */
                if (extra_path_endswith(de->d_name, ".efi")) {
                        _cleanup_free_ char *signed_child = strjoin(child, ".signed");
                        if (!signed_child)
                                return log_oom();

                        struct stat signed_st;
                        r = chase_and_statat(root_fd, root_fd, signed_child, /* chase_flags= */ 0, /* ret_path= */ NULL, &signed_st);
                        if (r < 0 && r != -ENOENT)
                                return log_error_errno(r, "Failed to stat '%s': %m", signed_child);
                        if (r >= 0 && S_ISREG(signed_st.st_mode)) {
                                log_debug("'%s' exists, not installing '%s'.", signed_child, child);
                                continue;
                        }
                }

                /* A directory keeps its name even if the name ends in ".efi.signed". */
                _cleanup_free_ char *unsigned_path = NULL;
                if (extra_path_endswith(path, ".efi.signed")) {
                        unsigned_path = strndup(path, strlen(path) - STRLEN(".signed"));
                        if (!unsigned_path)
                                return log_oom();
                }

                struct stat st;
                if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", child);

                /* If the target of a symlink does not exist, chaseat() returns the path of the target and
                 * no file descriptor. */
                _cleanup_free_ char *resolved = NULL;
                _cleanup_close_ int fd = -EBADF;
                r = chaseat(root_fd, root_fd, child, CHASE_NONEXISTENT, &resolved, &fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve '%s': %m", child);

                /* A symlink cannot name whichever of "<name>.efi" and "<name>.efi.signed" exists. If the
                 * target of a symlink is called "<name>.efi" and "<name>.efi.signed" exists next to the
                 * target, the signed file is hence installed under the name of the symlink. */
                if (S_ISLNK(st.st_mode) && extra_path_endswith(resolved, ".efi")) {
                        _cleanup_free_ char *signed_path = strjoin(resolved, ".signed");
                        if (!signed_path)
                                return log_oom();

                        _cleanup_close_ int signed_fd = chase_and_openat(
                                        root_fd,
                                        root_fd,
                                        signed_path,
                                        CHASE_MUST_BE_REGULAR,
                                        O_RDONLY|O_CLOEXEC|O_NOCTTY,
                                        /* ret_path= */ NULL);
                        if (signed_fd >= 0) {
                                log_debug("'%s' points to '%s', installing '%s' instead.", child, resolved, signed_path);

                                r = extra_files_add(c, unsigned_path ?: path, signed_path, signed_fd);
                                if (r < 0)
                                        return r;

                                continue;
                        }
                        if (signed_fd != -ENOENT)
                                return log_error_errno(signed_fd, "Failed to open '%s': %m", signed_path);
                }

                if (fd < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "'%s' points to '%s', which does not exist, refusing.", child, resolved);

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", child);

                if (S_ISDIR(st.st_mode))
                        r = load_extra_directory(c, root_fd, child, path, depth + 1);
                else if (S_ISREG(st.st_mode))
                        r = extra_files_add(c, unsigned_path ?: path, child, fd);
                else
                        r = log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                            "'%s' is neither a regular file nor a directory, refusing.", child);
                if (r < 0)
                        return r;
        }

        return 0;
}

int load_extra_files(InstallContext *c) {
        int r;

        assert(c);
        assert(c->n_extra_files == 0);

        /* The extra files are taken from the root directory that contains the systemd-boot binaries. If
         * open_source_directory() found no systemd-boot to install, for example because the package that
         * contains BOOTLIBDIR was removed, the extra files in the ESP are left alone. A
         * missing BOOTLIBDIR must not be mistaken for an EXTRA_FILES_DIR without files. */
        if (!c->source_dir) {
                log_debug("No systemd-boot binaries to install, leaving the extra files in the ESP alone.");
                return 0;
        }

        int root_fd = c->source_from_image ? c->root_fd : XAT_FDROOT;

        r = chase_and_accessat(root_fd, root_fd, EXTRA_FILES_DIR, CHASE_MUST_BE_DIRECTORY, F_OK, /* ret_path= */ NULL);
        if (r == -ENOENT) {
                /* A symlink whose target does not exist must not be mistaken for a missing directory,
                 * because the extra files in the ESP would be removed. */
                struct stat st;
                if (fstatat(dirfd(c->source_dir), EXTRA_FILES_DIR_NAME, &st, AT_SYMLINK_NOFOLLOW) >= 0)
                        return log_error_errno(r, "'%s' points to a directory that does not exist, refusing.", EXTRA_FILES_DIR);
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to stat '%s': %m", EXTRA_FILES_DIR);

                log_debug("Directory '%s' does not exist, not installing any extra files.", EXTRA_FILES_DIR);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to check for '%s': %m", EXTRA_FILES_DIR);

        r = load_extra_directory(c, root_fd, EXTRA_FILES_DIR, /* prefix= */ NULL, /* depth= */ 0);
        if (r < 0)
                return r;

        typesafe_qsort(c->extra_files, c->n_extra_files, extra_file_compare);

        /* Refuse collisions before the ESP is modified. */
        FOREACH_ARRAY(a, c->extra_files, c->n_extra_files)
                FOREACH_ARRAY(b, c->extra_files, c->n_extra_files) {
                        if (a >= b)
                                continue;

                        if (extra_path_equal(a->path, b->path))
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "'%s' and '%s' only differ in case and are the same file in the ESP, refusing.",
                                                       a->source_path, b->source_path);

                        const char *e = extra_path_startswith(b->path, a->path) ?: extra_path_startswith(a->path, b->path);
                        if (e && e[0] == '/')
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "'%s' and '%s' need a file and a directory of the same name in the ESP, refusing.",
                                                       a->source_path, b->source_path);
                }

        return 0;
}

static int extra_file_array_add(
                ExtraFile **files,
                size_t *n,
                const char *path,
                const uint8_t hash[static SHA256_DIGEST_SIZE],
                bool pending) {

        assert(files);
        assert(n);
        assert(path);

        _cleanup_free_ char *p = strdup(path);
        if (!p)
                return log_oom();

        if (!GREEDY_REALLOC(*files, *n + 1))
                return log_oom();

        ExtraFile *f = *files + (*n)++;
        *f = (ExtraFile) {
                .path = TAKE_PTR(p),
                .source_fd = -EBADF,
                .pending = pending,
        };
        memcpy(f->hash, hash, SHA256_DIGEST_SIZE);

        return 0;
}

typedef struct ExtraManifestReader {
        InstallContext *context;
        const char *name;
        bool pending;
} ExtraManifestReader;

static int extra_manifest_read_object(Uapi16Object *o, size_t index, void *userdata) {
        ExtraManifestReader *reader = ASSERT_PTR(userdata);
        InstallContext *c = ASSERT_PTR(reader->context);

        assert(o);

        /* The root object and the objects of the directories do not describe a file that bootctl installed. */
        if (index == 0 || o->type == S_IFDIR)
                return 0;

        /* The paths are used to delete files in the ESP, hence only accept what bootctl writes. */
        if (o->type != S_IFREG ||
            o->sha256.iov_len != SHA256_DIGEST_SIZE ||
            !extra_path_is_valid(o->name) ||
            c->n_extra_manifest >= 2 * EXTRA_FILES_MAX) {
                log_warning("Ignoring invalid entry '%s' in '%s/%s' in the ESP.", o->name, INSTALL_MANIFEST_DIR, reader->name);
                c->extra_manifest_damaged = true;
                return 0;
        }

        if (extra_manifest_lists(c, o->name, o->sha256.iov_base))
                return 0;

        return extra_file_array_add(&c->extra_manifest, &c->n_extra_manifest, o->name, o->sha256.iov_base, reader->pending);
}

static int load_extra_manifest_file(InstallContext *c, const char *name, bool pending) {
        int r;

        assert(c);
        assert(name);

        _cleanup_free_ char *path = path_join(INSTALL_MANIFEST_DIR, name);
        if (!path)
                return log_oom();

        _cleanup_fclose_ FILE *f = NULL;
        r = chase_and_fopenat_unlocked(
                        c->esp_fd,
                        c->esp_fd,
                        path,
                        CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_REGULAR,
                        "re",
                        /* ret_path= */ NULL,
                        &f);
        if (r == -ENOENT)
                return 0;
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                /* A manifest that cannot be read is handled like a manifest that cannot be parsed. It must
                 * block neither the installation of systemd-boot nor "bootctl remove". */
                log_warning_errno(r, "Failed to open '%s' in the ESP, ignoring: %m", path);
                c->extra_manifest_damaged = true;
                return 0;
        }

        ExtraManifestReader reader = {
                .context = c,
                .name = name,
                .pending = pending,
        };
        r = uapi16_manifest_read(f, /* certificates= */ NULL, /* n_certificates= */ 0, extra_manifest_read_object, &reader);
        if (r == -ENOMEM)
                return r;
        if (r < 0) {
                /* uapi16_manifest_read() logged the reason. The entries that it read before the error are
                 * kept, so that "bootctl remove" still removes the files that they list. run_install() does
                 * not rewrite a damaged manifest during an update, because bootctl would not manage the
                 * files that the rest of the manifest lists anymore. */
                log_warning("Ignoring the rest of '%s' in the ESP.", path);
                c->extra_manifest_damaged = true;
        }

        return 0;
}

int load_extra_manifest(InstallContext *c) {
        int r;

        assert(c);
        assert(c->n_extra_manifest == 0);

        if (c->esp_fd < 0)
                return c->esp_fd;

        r = load_extra_manifest_file(c, INSTALL_MANIFEST_NAME, /* pending= */ false);
        if (r < 0)
                return r;

        return load_extra_manifest_file(c, INSTALL_MANIFEST_PENDING_NAME, /* pending= */ true);
}

static int extra_file_compare_path(ExtraFile * const *a, ExtraFile * const *b) {
        assert(a);
        assert(b);

        return path_compare((*a)->path, (*b)->path);
}

static int format_extra_manifest(ExtraFile *files, size_t n, bool pending, char **ret) {
        int r;

        assert(files || n == 0);
        assert(ret);

        /* format_extra_manifest() returns NULL in ret if no entry of the array belongs to the manifest. */

        _cleanup_free_ ExtraFile **sorted = new(ExtraFile*, MAX(n, 1U));
        if (!sorted)
                return log_oom();

        size_t n_sorted = 0;
        FOREACH_ARRAY(f, files, n)
                if (f->pending == pending)
                        sorted[n_sorted++] = f;

        if (n_sorted == 0) {
                *ret = NULL;
                return 0;
        }

        /* The manifest declares the code point ordering, which path_compare() implements. */
        typesafe_qsort(sorted, n_sorted, extra_file_compare_path);

        _cleanup_(memstream_done) MemStream m = {};
        FILE *f = memstream_init(&m);
        if (!f)
                return log_oom();

        _cleanup_(manifest_context_done) ManifestContext mc = MANIFEST_CONTEXT_NULL;
        mc.format = MANIFEST_FORMAT_UAPI16;
        mc.output = f;

        r = manifest_uapi16_begin(&mc);
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *features = NULL, *v = NULL;
        r = uapi16_features_build_json(MANIFEST_FIELD_HASH, &features);
        if (r < 0)
                return log_error_errno(r, "Failed to build features JSON array: %m");

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR("mediaType", JSON_BUILD_CONST_STRING(UAPI16_MANIFEST_MEDIA_TYPE)),
                        SD_JSON_BUILD_PAIR_STRING("order", uapi16_order_to_string(UAPI16_ORDER_CODEPOINT)),
                        SD_JSON_BUILD_PAIR_VARIANT("features", features));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON object: %m");

        r = manifest_uapi16_write_object(&mc, v);
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **dirs = NULL;
        const char *previous = NULL;
        FOREACH_ARRAY(i, sorted, n_sorted) {
                const char *path = (*i)->path;

                if (previous && path_equal(previous, path))
                        continue;
                previous = path;

                /* A UAPI.16 manifest lists every directory before the files that the directory contains. */
                for (const char *slash = strchr(path, '/'); slash; slash = strchr(slash + 1, '/')) {
                        _cleanup_free_ char *dir = strndup(path, slash - path);
                        if (!dir)
                                return log_oom();

                        if (strv_contains(dirs, dir))
                                continue;

                        v = sd_json_variant_unref(v);
                        r = sd_json_buildo(
                                        &v,
                                        SD_JSON_BUILD_PAIR_STRING("name", dir),
                                        SD_JSON_BUILD_PAIR_STRING("type", inode_type_to_string(S_IFDIR)));
                        if (r < 0)
                                return log_error_errno(r, "Failed to build JSON object: %m");

                        r = manifest_uapi16_write_object(&mc, v);
                        if (r < 0)
                                return r;

                        r = strv_consume(&dirs, TAKE_PTR(dir));
                        if (r < 0)
                                return log_oom();
                }

                v = sd_json_variant_unref(v);
                r = sd_json_buildo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("name", path),
                                SD_JSON_BUILD_PAIR_HEX("sha256", (*i)->hash, SHA256_DIGEST_SIZE));
                if (r < 0)
                        return log_error_errno(r, "Failed to build JSON object: %m");

                r = manifest_uapi16_write_object(&mc, v);
                if (r < 0)
                        return r;
        }

        r = manifest_uapi16_end(&mc);
        if (r < 0)
                return r;

        _cleanup_free_ char *text = NULL;
        r = memstream_finalize(&m, &text, /* ret_size= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to format the manifest of the installed files: %m");

        *ret = TAKE_PTR(text);
        return 0;
}

static int write_extra_manifest_file(int dir_fd, const char *name, ExtraFile *files, size_t n, bool pending) {
        int r;

        assert(dir_fd >= 0);
        assert(name);

        _cleanup_free_ char *text = NULL;
        r = format_extra_manifest(files, n, pending, &text);
        if (r < 0)
                return r;

        if (!text) {
                /* unlinkat() fails with EROFS for a file that does not exist if the ESP is read-only. */
                if (faccessat(dir_fd, name, F_OK, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT)
                        return 0;

                if (unlinkat(dir_fd, name, 0) < 0 && errno != ENOENT)
                        return log_error_errno(errno, "Failed to remove '%s/%s' in the ESP: %m", INSTALL_MANIFEST_DIR, name);

                return 0;
        }

        /* "bootctl update" runs on every boot. Do not write to the ESP if the manifest is unchanged. */
        _cleanup_free_ char *old_text = NULL;
        if (read_full_file_at(dir_fd, name, &old_text, /* ret_size= */ NULL) >= 0 && streq(old_text, text))
                return 0;

        r = write_string_file_at(
                        dir_fd,
                        name,
                        text,
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_SYNC|WRITE_STRING_FILE_AVOID_NEWLINE);
        if (r < 0)
                return log_error_errno(r, "Failed to write '%s/%s' in the ESP: %m", INSTALL_MANIFEST_DIR, name);

        return 0;
}

static int write_extra_manifest(InstallContext *c, ExtraFile *files, size_t n) {
        int r;

        assert(c);
        assert(files || n == 0);

        _cleanup_close_ int dir_fd = -EBADF;
        r = chaseat(c->esp_fd,
                    c->esp_fd,
                    INSTALL_MANIFEST_DIR,
                    CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_DIRECTORY|(n > 0 ? CHASE_MKDIR_0755 : 0),
                    /* ret_path= */ NULL,
                    &dir_fd);
        if (r == -ENOENT && n == 0)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to open '%s' in the ESP: %m", INSTALL_MANIFEST_DIR);

        /* INSTALL_MANIFEST_NAME is written first. If bootctl is interrupted afterwards,
         * INSTALL_MANIFEST_PENDING_NAME still lists the files that were copied. */
        r = write_extra_manifest_file(dir_fd, INSTALL_MANIFEST_NAME, files, n, /* pending= */ false);
        if (r < 0)
                return r;

        return write_extra_manifest_file(dir_fd, INSTALL_MANIFEST_PENDING_NAME, files, n, /* pending= */ true);
}

static int find_name_no_case(int dir_fd, const char *name, char **ret) {
        assert(dir_fd >= 0);
        assert(name);
        assert(ret);

        /* VFAT matches file names case insensitively, but the file systems that the ESP is assembled on
         * when an image is built do not. Look for an existing entry that only differs in case, so that
         * "EFI/Boot" and "EFI/BOOT" are the same directory on any file system. */

        if (faccessat(dir_fd, name, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                return strdup_to_full(ret, name);
        if (errno != ENOENT)
                return -errno;

        _cleanup_close_ int fd = fd_reopen(dir_fd, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        _cleanup_closedir_ DIR *d = take_fdopendir(&fd);
        if (!d)
                return -errno;

        FOREACH_DIRENT_ALL(de, d, return -errno)
                if (extra_path_equal(de->d_name, name))
                        return strdup_to_full(ret, de->d_name);

        *ret = NULL;
        return 0;
}

static int extra_open_parent(
                InstallContext *c,
                const char *path,
                bool create,
                int *ret_dir_fd,
                char **ret_filename,
                char **ret_path) {

        int r;

        assert(c);
        assert(path);
        assert(ret_dir_fd);
        assert(ret_filename);
        assert(ret_path);

        /* extra_open_parent() opens the directory in the ESP that contains the specified file. It returns the
         * path in ret_path, spelled like the existing directories and files in the ESP. */

        if (c->esp_fd < 0)
                return c->esp_fd;

        _cleanup_close_ int dir_fd = fd_reopen(c->esp_fd, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (dir_fd < 0)
                return dir_fd;

        _cleanup_free_ char *actual_path = NULL;
        for (const char *p = path;;) {
                const char *e;

                r = path_find_first_component(&p, /* accept_dot_dot= */ false, &e);
                if (r <= 0)
                        return r < 0 ? r : -EINVAL;

                _cleanup_free_ char *component = strndup(e, r);
                if (!component)
                        return -ENOMEM;

                _cleanup_free_ char *actual = NULL;
                r = find_name_no_case(dir_fd, component, &actual);
                if (r < 0)
                        return r;

                bool last = isempty(p);
                if (r == 0) {
                        if (!last) {
                                if (!create)
                                        return -ENOENT;

                                if (mkdirat(dir_fd, component, 0755) < 0 && errno != EEXIST)
                                        return -errno;
                        }

                        actual = TAKE_PTR(component);
                }

                if (!path_extend(&actual_path, actual))
                        return -ENOMEM;

                if (last) {
                        *ret_dir_fd = TAKE_FD(dir_fd);
                        *ret_filename = TAKE_PTR(actual);
                        *ret_path = TAKE_PTR(actual_path);
                        return 0;
                }

                int fd = xopenat(dir_fd, actual, O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
                if (fd < 0)
                        return fd;

                close_and_replace(dir_fd, fd);
        }
}

static int remove_extra_file(InstallContext *c, const ExtraFile *f, bool remove_directories) {
        int r;

        assert(c);
        assert(f);

        _cleanup_free_ char *j = path_join(c->root, c->esp_path);
        if (!j)
                return log_oom();

        _cleanup_free_ char *filename = NULL, *path = NULL;
        _cleanup_close_ int dir_fd = -EBADF;
        r = extra_open_parent(c, f->path, /* create= */ false, &dir_fd, &filename, &path);
        if (r == -ENOENT)
                return 0;
        if (IN_SET(r, -ENOTDIR, -ELOOP)) {
                log_notice("Not removing '%s/%s', a directory in its path was replaced since it was installed.", j, f->path);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open the directory of '%s/%s': %m", j, f->path);

        _cleanup_close_ int fd = xopenat_full(dir_fd, filename, O_RDONLY|O_NOCTTY|O_NOFOLLOW, XO_REGULAR, MODE_INVALID);
        if (fd == -ENOENT)
                return 0;
        if (IN_SET(fd, -EISDIR, -ELOOP, -EBADFD)) {
                log_notice("Not removing '%s/%s', it was replaced by something that is not a regular file.", j, path);
                return 0;
        }
        if (fd < 0)
                return log_error_errno(fd, "Failed to open '%s/%s': %m", j, path);

        uint8_t hash[SHA256_DIGEST_SIZE];
        r = sha256_fd(fd, UINT64_MAX, hash);
        if (r < 0)
                return log_error_errno(r, "Failed to hash '%s/%s': %m", j, path);

        /* Another boot loader or the user replaced the file if its contents changed since it was installed. */
        if (!extra_manifest_lists(c, f->path, hash)) {
                log_notice("Not removing '%s/%s', it was modified since it was installed.", j, path);
                return 0;
        }

        if (unlinkat(dir_fd, filename, 0) < 0)
                return log_error_errno(errno, "Failed to remove '%s/%s': %m", j, path);

        log_info("Removed \"%s/%s\".", j, path);
        c->changed = true;

        if (!remove_directories)
                return 0;

        for (;;) {
                _cleanup_free_ char *parent = NULL;

                r = path_extract_directory(path, &parent);
                if (r < 0) /* The file was located in the root directory of the ESP. */
                        return 0;

                if (unlinkat(c->esp_fd, parent, AT_REMOVEDIR) < 0) {
                        if (!IN_SET(errno, ENOTEMPTY, EEXIST, ENOENT))
                                log_debug_errno(errno, "Failed to remove directory '%s/%s', ignoring: %m", j, parent);
                        return 0;
                }

                log_info("Removed directory \"%s/%s\".", j, parent);
                free_and_replace(path, parent);
        }
}

static int plan_extra_file(InstallContext *c, ExtraFile *f) {
        int r;

        assert(c);
        assert(f);

        /* plan_extra_file() sets f->action without modifying the ESP. "bootctl install" replaces every file.
         * "bootctl update" only replaces a file that bootctl manages. */

        f->action = EXTRA_ACTION_COPY;
        f->dest_managed = false;

        _cleanup_free_ char *j = path_join(c->root, c->esp_path);
        if (!j)
                return log_oom();

        _cleanup_free_ char *filename = NULL, *path = NULL;
        _cleanup_close_ int dir_fd = -EBADF;
        r = extra_open_parent(c, f->path, /* create= */ false, &dir_fd, &filename, &path);
        if (r == -ENOENT) {
                extra_manifest_forget(c, f->path);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open the directory of '%s/%s': %m", j, f->path);

        /* extra_open_parent() returns the path as it is spelled in the ESP. */
        free_and_replace(f->path, path);

        _cleanup_free_ char *dest_path = path_join(j, f->path);
        if (!dest_path)
                return log_oom();

        _cleanup_close_ int dest_fd = xopenat_full(dir_fd, filename, O_RDONLY|O_NOCTTY|O_NOFOLLOW, XO_REGULAR, MODE_INVALID);
        if (dest_fd == -ENOENT) {
                extra_manifest_forget(c, f->path);
                return 0;
        }
        if (dest_fd < 0)
                return log_error_errno(dest_fd, "Failed to open '%s': %m", dest_path);

        r = sha256_fd(dest_fd, UINT64_MAX, f->dest_hash);
        if (r < 0)
                return log_error_errno(r, "Failed to hash '%s': %m", dest_path);

        /* The manifests list at most two hashes per path. Drop the hash that the file in the ESP does not
         * have, so that install_extra_files() can add the hash of the file that it is about to copy. */
        extra_manifest_retain(c, f->path, f->dest_hash);

        bool listed = extra_manifest_lists(c, f->path, f->dest_hash),
                same = memcmp(f->dest_hash, f->hash, SHA256_DIGEST_SIZE) == 0;

        /* "bootctl install" replaces the file in any case. If the copy fails, install_extra_files() keeps
         * a file that the manifest lists in the manifest. */
        if (c->operation == INSTALL_NEW) {
                f->dest_managed = listed;
                return 0;
        }

        if (!listed) {
                if (same)
                        log_debug("\"%s\" is up-to-date, but was not installed by bootctl, leaving it alone.", dest_path);
                else
                        log_notice("Skipping \"%s\", it was not installed by bootctl or was modified since. Use \"bootctl install\" to replace it.", dest_path);

                f->action = EXTRA_ACTION_SKIP;
                return 0;
        }

        /* A file that bootctl manages is replaced whenever its contents differ. The version of a binary is
         * not compared. The version of a binary based on systemd-stub is the version of the stub, which
         * does not change when the kernel or the initrd inside of a UKI changes. */
        f->dest_managed = true;
        if (same) {
                log_debug("\"%s\" is up-to-date.", dest_path);
                f->action = EXTRA_ACTION_KEEP;
        }

        return 0;
}

static int install_extra_file(InstallContext *c, ExtraFile *f) {
        int r;

        assert(c);
        assert(f);

        _cleanup_free_ char *j = path_join(c->root, c->esp_path);
        if (!j)
                return log_oom();

        _cleanup_free_ char *filename = NULL, *path = NULL;
        _cleanup_close_ int dir_fd = -EBADF;
        r = extra_open_parent(c, f->path, /* create= */ true, &dir_fd, &filename, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to open the directory of '%s/%s': %m", j, f->path);

        /* extra_open_parent() returns the path as it is spelled in the ESP. */
        free_and_replace(f->path, path);

        _cleanup_free_ char *dest_path = path_join(j, f->path);
        if (!dest_path)
                return log_oom();

        r = copy_file_with_version_check(f->source_path, f->source_fd, dest_path, dir_fd, filename, /* dest_fd= */ -EBADF, /* force= */ true);
        if (r < 0)
                return r;

        c->changed = true;
        return 0;
}

static int remove_extra_conflicts(InstallContext *c) {
        int r;

        assert(c);

        /* A path can be a file in one version of EXTRA_FILES_DIR and a directory in the next version. The
         * file or the directory in the ESP then has to be removed before the new files are copied, although
         * install_extra_files() removes every other file that is not provided anymore afterwards. */

        for (size_t i = 0; i < c->n_extra_manifest;) {
                ExtraFile *m = c->extra_manifest + i;
                bool conflict = false;

                FOREACH_ARRAY(f, c->extra_files, c->n_extra_files) {
                        const char *e = extra_path_startswith(f->path, m->path) ?: extra_path_startswith(m->path, f->path);
                        if (e && e[0] == '/') {
                                conflict = true;
                                break;
                        }
                }
                if (!conflict) {
                        i++;
                        continue;
                }

                r = remove_extra_file(c, m, /* remove_directories= */ true);
                if (r < 0)
                        return r;

                /* extra_manifest_forget() removes every entry of the path, including the entry at i. */
                _cleanup_free_ char *path = strdup(m->path);
                if (!path)
                        return log_oom();

                extra_manifest_forget(c, path);
        }

        /* An earlier invocation might have left an empty directory behind where a file is provided now. */
        FOREACH_ARRAY(f, c->extra_files, c->n_extra_files) {
                _cleanup_free_ char *filename = NULL, *path = NULL;
                _cleanup_close_ int dir_fd = -EBADF;

                if (extra_open_parent(c, f->path, /* create= */ false, &dir_fd, &filename, &path) < 0)
                        continue;

                (void) unlinkat(dir_fd, filename, AT_REMOVEDIR);
        }

        return 0;
}

static bool extra_entry_point_is_registered(InstallContext *c, const char *path) {
        assert(c);
        assert(path);

        const char *entry_point = strjoina("EFI/systemd/boot", get_efi_arch(), ".efi");
        if (!extra_path_equal(path, entry_point))
                return false;

        uint16_t slot;
        return find_slot(c->esp_uuid, strjoina("/", entry_point), &slot) > 0;
}

static int list_boot_binary_paths(InstallContext *c, const char *arch, char ***ret) {
        int r;

        assert(c);
        assert(c->source_dir);
        assert(ret);

        /* list_boot_binary_paths() returns the paths in the ESP under which install_binaries() installs
         * the binaries in BOOTLIBDIR. */

        const char *suffix = strjoina(strempty(arch), ".efi");
        const char *suffix_signed = strjoina(strempty(arch), ".efi.signed");

        _cleanup_strv_free_ char **l = NULL;
        rewinddir(c->source_dir);
        FOREACH_DIRENT(de, c->source_dir, return log_error_errno(errno, "Failed to read \"%s\": %m", c->source_path)) {
                if (!endswith_no_case(de->d_name, suffix) && !endswith_no_case(de->d_name, suffix_signed))
                        continue;

                _cleanup_free_ char *name = strdup(de->d_name);
                if (!name)
                        return log_oom();

                char *s = endswith_no_case(name, ".signed");
                if (s)
                        *s = 0;

                r = strv_extendf(&l, "EFI/systemd/%s", name);
                if (r < 0)
                        return log_oom();

                const char *e = startswith(name, "systemd-boot");
                if (!e)
                        continue;

                _cleanup_free_ char *boot_dot_efi = strjoin("BOOT", e);
                if (!boot_dot_efi)
                        return log_oom();

                r = strv_extendf(&l, "EFI/systemd/systemd-boot-fallback%s", e);
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&l, "EFI/BOOT/%s", ascii_strupper(boot_dot_efi));
                if (r < 0)
                        return log_oom();
        }

        *ret = strv_uniq(TAKE_PTR(l));
        return 0;
}

static int record_boot_binary(InstallContext *c, const char *path) {
        int r;

        assert(c);
        assert(path);

        /* record_boot_binary() adds a systemd-boot binary in the ESP to c->extra_installed. install_binaries()
         * decides with the version of the binary whether it replaces the binary, not with the manifest.
         * The binary is hence listed with the hash that it has now, no matter which invocation installed
         * it. */

        _cleanup_free_ char *filename = NULL, *actual_path = NULL;
        _cleanup_close_ int dir_fd = -EBADF;
        r = extra_open_parent(c, path, /* create= */ false, &dir_fd, &filename, &actual_path);
        if (IN_SET(r, -ENOENT, -ENOTDIR, -ELOOP))
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to open the directory of '%s' in the ESP: %m", path);

        _cleanup_close_ int fd = xopenat_full(dir_fd, filename, O_RDONLY|O_NOCTTY|O_NOFOLLOW, XO_REGULAR, MODE_INVALID);
        if (IN_SET(fd, -ENOENT, -EISDIR, -ELOOP, -EBADFD))
                return 0;
        if (fd < 0)
                return log_error_errno(fd, "Failed to open '%s' in the ESP: %m", actual_path);

        /* Another boot loader can be installed as EFI/BOOT/BOOT<ARCH>.EFI. bootctl does not manage it. */
        _cleanup_free_ char *version = NULL;
        r = get_file_version(fd, &version);
        if (r < 0 || !startswith(version, "systemd-boot ")) {
                log_debug("'%s' in the ESP is not systemd-boot, not listing it in the manifest.", actual_path);
                return 0;
        }

        uint8_t hash[SHA256_DIGEST_SIZE];
        r = sha256_fd(fd, UINT64_MAX, hash);
        if (r < 0)
                return log_error_errno(r, "Failed to hash '%s' in the ESP: %m", actual_path);

        return extra_file_array_add(&c->extra_installed, &c->n_extra_installed, actual_path, hash, /* pending= */ false);
}

int install_extra_files(InstallContext *c, const char *arch, bool update_variables) {
        int r, ret = 0;

        assert(c);
        assert(c->n_extra_installed == 0);

        /* The manifest also lists the systemd-boot binaries that an earlier invocation found in the ESP.
         * The binaries are not extra files, hence the entries must not be handled as extra files that are
         * not provided anymore. record_boot_binary() lists the binaries again below. The entry of
         * EFI/BOOT/BOOT<ARCH>.EFI is kept if EXTRA_FILES_DIR provides that file now, so that an update
         * replaces a systemd-boot that bootctl installed under that name. */
        _cleanup_strv_free_ char **boot_paths = NULL;
        r = list_boot_binary_paths(c, arch, &boot_paths);
        if (r < 0)
                return r;

        STRV_FOREACH(p, boot_paths)
                if (!extra_file_find(c->extra_files, c->n_extra_files, *p))
                        extra_manifest_forget(c, *p);

        r = remove_extra_conflicts(c);
        if (r < 0)
                return r;

        bool failed = false, copy = false;
        FOREACH_ARRAY(f, c->extra_files, c->n_extra_files) {
                r = plan_extra_file(c, f);
                if (r < 0) {
                        f->action = EXTRA_ACTION_FAILED;
                        failed = true;
                        RET_GATHER(ret, r);
                }

                if (f->action != EXTRA_ACTION_COPY || extra_manifest_lists(c, f->path, f->hash))
                        continue;

                r = extra_file_array_add(&c->extra_manifest, &c->n_extra_manifest, f->path, f->hash, /* pending= */ true);
                if (r < 0)
                        return r;

                copy = true;
        }

        /* INSTALL_MANIFEST_PENDING_NAME is written with the hashes of the files that are about to be
         * copied before the first file is copied. If bootctl is interrupted, the next invocation hence
         * still recognizes the files that were copied as files that bootctl installed. */
        if (copy) {
                r = write_extra_manifest(c, c->extra_manifest, c->n_extra_manifest);
                if (r < 0)
                        return r;
        }

        /* A boot loader that the firmware starts may load other extra files. The entry points are installed
         * last, and only if every other file was installed. An interrupted or failed update hence does not
         * combine a new entry point with the old version of a file that it loads. */
        for (int entry_points = 0; entry_points <= 1; entry_points++)
                FOREACH_ARRAY(f, c->extra_files, c->n_extra_files) {
                        if (extra_path_is_entry_point(f->path) != !!entry_points)
                                continue;

                        const uint8_t *hash = NULL;
                        switch (f->action) {

                        case EXTRA_ACTION_SKIP:
                                break;

                        case EXTRA_ACTION_KEEP:
                                hash = f->dest_hash;
                                break;

                        case EXTRA_ACTION_COPY:
                                if (entry_points && failed) {
                                        log_warning("Not installing '%s', because another extra file could not be installed.", f->source_path);
                                        r = -ECANCELED;
                                } else
                                        r = install_extra_file(c, f);
                                if (r >= 0) {
                                        hash = f->hash;
                                        break;
                                }

                                failed = true;
                                RET_GATHER(ret, r);

                                /* The copy can fail after the new file replaced the old file. Keep the
                                 * hash of the new file in INSTALL_MANIFEST_PENDING_NAME and the hash
                                 * of the file that an earlier invocation installed in
                                 * INSTALL_MANIFEST_NAME, so that a later invocation can replace or
                                 * remove either file. */
                                if (r != -ECANCELED) {
                                        r = extra_file_array_add(&c->extra_installed, &c->n_extra_installed, f->path, f->hash, /* pending= */ true);
                                        if (r < 0)
                                                return r;
                                }
                                if (f->dest_managed)
                                        hash = f->dest_hash;
                                break;

                        case EXTRA_ACTION_FAILED:
                                /* The state of the file in the ESP is unknown, hence keep every hash that
                                 * the manifests list for it. */
                                FOREACH_ARRAY(m, c->extra_manifest, c->n_extra_manifest)
                                        if (extra_path_equal(m->path, f->path)) {
                                                r = extra_file_array_add(&c->extra_installed, &c->n_extra_installed, m->path, m->hash, m->pending);
                                                if (r < 0)
                                                        return r;
                                        }
                                break;

                        default:
                                assert_not_reached();
                        }

                        if (hash) {
                                r = extra_file_array_add(&c->extra_installed, &c->n_extra_installed, f->path, hash, /* pending= */ false);
                                if (r < 0)
                                        return r;
                        }
                }

        /* The files that EXTRA_FILES_DIR does not contain anymore are removed after the new files are in
         * place. If a file could not be installed, the old entry points are still in the ESP. An old entry
         * point might load a file that is not provided anymore, hence no file is removed then. */
        FOREACH_ARRAY(m, c->extra_manifest, c->n_extra_manifest) {
                if (extra_file_find(c->extra_files, c->n_extra_files, m->path))
                        continue;

                if (failed)
                        log_debug("Not removing '%s' from the ESP, because an extra file could not be installed.", m->path);
                else if (!update_variables && extra_entry_point_is_registered(c, m->path))
                        /* The firmware would skip a boot entry whose file does not exist. The file is
                         * removed by the next invocation that also updates the boot entry. */
                        log_notice("Not removing '%s' from the ESP, because the firmware's boot loader list refers to it and is not updated now.", m->path);
                else {
                        r = remove_extra_file(c, m, /* remove_directories= */ false);
                        if (r >= 0)
                                continue;

                        RET_GATHER(ret, r);
                }

                r = extra_file_array_add(&c->extra_installed, &c->n_extra_installed, m->path, m->hash, m->pending);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(p, boot_paths) {
                if (extra_file_find(c->extra_files, c->n_extra_files, *p))
                        continue;

                r = record_boot_binary(c, *p);
                if (r < 0)
                        return r;
        }

        return RET_GATHER(ret, write_extra_manifest(c, c->extra_installed, c->n_extra_installed));
}

int remove_extra_files(InstallContext *c) {
        int r;

        assert(c);

        r = load_extra_manifest(c);
        if (r < 0)
                return r;

        FOREACH_ARRAY(m, c->extra_manifest, c->n_extra_manifest) {
                /* remove_binaries() deletes EFI/systemd/ with everything in it. */
                if (extra_path_startswith(m->path, INSTALL_MANIFEST_DIR "/"))
                        continue;

                RET_GATHER(r, remove_extra_file(c, m, /* remove_directories= */ true));
        }

        return r;
}
