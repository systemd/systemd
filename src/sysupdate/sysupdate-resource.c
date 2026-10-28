/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "build-path.h"
#include "chase.h"
#include "compress.h"
#include "device-util.h"
#include "dirent-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "extension-util.h"
#include "fd-util.h"
#include "fdisk-util.h"
#include "fileio.h"
#include "find-esp.h"
#include "glyph-util.h"
#include "gpt.h"
#include "import-util.h"
#include "iovec-util.h"
#include "os-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "sha256.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "strv.h"
#include "sysupdate-cache.h"
#include "sysupdate-instance.h"
#include "sysupdate-partition.h"
#include "sysupdate-pattern.h"
#include "sysupdate-resource.h"
#include "time-util.h"
#include "manifest-util.h"
#include "uapi16-manifest.h"
#include "web-util.h"
#include "xattr-match.h"

void resource_destroy(Resource *rr) {
        assert(rr);

        free(rr->path);
        free(rr->manifest_path);
        strv_free(rr->patterns);

        for (size_t i = 0; i < rr->n_instances; i++)
                instance_free(rr->instances[i]);
        free(rr->instances);
}

bool resource_has_glob_directory_pattern(Resource *rr) {
        assert(rr);

        STRV_FOREACH(p, rr->patterns) {
                const char *pat = *p;

                if (pattern_skip_glob_directory_prefix(&pat))
                        return true;
        }
        return false;
}

unsigned resource_xattr_match_mask(const Resource *rr) {
        assert(rr);

        return rr->match_xattr ? XATTR_MATCH_MASK_ALL : 0;
}

static int resource_add_instance(
                Resource *rr,
                const char *path,
                const InstanceMetadata *f,
                Instance **ret) {

        Instance *i;
        int r;

        assert(rr);
        assert(path);
        assert(f);
        assert(f->version);

        if (!GREEDY_REALLOC(rr->instances, rr->n_instances + 1))
                return log_oom();

        r = instance_new(rr, path, f, &i);
        if (r < 0)
                return r;

        rr->instances[rr->n_instances++] = i;

        if (ret)
                *ret = i;

        return 0;
}

static int resource_load_from_directory_recursive(
                Resource *rr,
                DIR* d,
                const char* relpath,
                const char* relpath_for_matching,
                mode_t m,
                bool ancestor_is_partial,
                bool ancestor_is_pending,
                const XAttrMatchFilter *filter) {
        int r;

        for (;;) {
                _cleanup_(instance_metadata_destroy) InstanceMetadata extracted_fields = INSTANCE_METADATA_NULL;
                _cleanup_free_ char *joined = NULL, *rel_joined = NULL;
                _cleanup_free_ char *rel_joined_for_matching = NULL;
                Instance *instance;
                struct dirent *de;
                const char *de_d_name_stripped;
                struct stat st;
                bool is_partial = ancestor_is_partial, is_pending = ancestor_is_pending;
                const char *stripped;

                errno = 0;
                de = readdir_no_dot(d);
                if (!de) {
                        if (errno != 0)
                                return log_error_errno(errno, "Failed to read directory '%s': %m", rr->path);
                        break;
                }

                switch (de->d_type) {

                case DT_UNKNOWN:
                        break;

                case DT_DIR:
                        if (!IN_SET(m, S_IFDIR, S_IFREG))
                                continue;

                        break;

                case DT_REG:
                        if (m != S_IFREG)
                                continue;
                        break;

                default:
                        continue;
                }

                if (fstatat(dirfd(d), de->d_name, &st, AT_NO_AUTOMOUNT|AT_SYMLINK_NOFOLLOW) < 0) {
                        if (errno == ENOENT) /* Gone by now? */
                                continue;

                        return log_error_errno(errno, "Failed to stat %s/%s: %m", rr->path, de->d_name);
                }

                if (!(S_ISDIR(st.st_mode) && S_ISREG(m)) && ((st.st_mode & S_IFMT) != m))
                        continue;

                if ((stripped = startswith(de->d_name, ".sysupdate.partial."))) {
                        de_d_name_stripped = stripped;
                        is_partial = true;
                        is_pending = false;
                } else if ((stripped = startswith(de->d_name, ".sysupdate.pending."))) {
                        de_d_name_stripped = stripped;
                        is_pending = true;
                        is_partial = false;
                } else
                        de_d_name_stripped = de->d_name;

                rel_joined = path_join(relpath, de->d_name);
                if (!rel_joined)
                        return log_oom();

                /* Match against the filename with any `.sysupdate.partial.` (etc.) prefix stripped, so the
                 * user’s patterns still apply. But don’t use the stripped version in any paths or recursion. */
                rel_joined_for_matching = path_join(relpath_for_matching, de_d_name_stripped);
                if (!rel_joined_for_matching)
                        return log_oom();

                /* If any pattern has the glob directory prefix descend into subdirectories when looking for
                 * regular files */
                bool descend = S_ISDIR(st.st_mode) && S_ISREG(m) && resource_has_glob_directory_pattern(rr);

                if (!descend) {
                        r = pattern_match_many(rr->patterns, rel_joined_for_matching, &extracted_fields);
                        if (r < 0)
                                return log_error_errno(r, "Failed to match pattern: %m");
                        if (r == PATTERN_MATCH_NO)
                                continue;
                        /* Here we descend when the match pattern itself uses subdirectories */
                        if (r == PATTERN_MATCH_RETRY) {
                                if (!S_ISDIR(st.st_mode)) /* The pattern continues with '/' but this is no directory */
                                        continue;
                                descend = true;
                        } else if (r == PATTERN_MATCH_YES_AND_RETRY && S_ISDIR(st.st_mode) && m != S_IFDIR)
                                /* The direct match is unusable since a directory can't be an instance here,
                                 * but another pattern wants to descend, so do that instead */
                                descend = true;
                }

                if (descend) {
                        _cleanup_closedir_ DIR *subdir = NULL;

                        subdir = xopendirat(dirfd(d), de->d_name, O_NOFOLLOW);
                        if (!subdir) {
                                if (errno == ENOENT) /* Gone by now? */
                                        continue;

                                return log_error_errno(errno, "Failed to open directory %s/%s: %m", rr->path, rel_joined);
                        }

                        r = resource_load_from_directory_recursive(rr, subdir, rel_joined, rel_joined_for_matching, m, is_partial, is_pending, filter);
                        if (r < 0)
                                return r;
                        continue;
                }

                if (S_ISDIR(st.st_mode) && m != S_IFDIR)
                        continue;

                /* Skip instances restricted to other systems via extended attributes */
                r = xattr_match_filter_test_inode(filter, dirfd(d), de->d_name);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                joined = path_join(rr->path, rel_joined);
                if (!joined)
                        return log_oom();

                r = resource_add_instance(rr, joined, &extracted_fields, &instance);
                if (r < 0)
                        return r;

                /* Inherit these from the source, if not explicitly overwritten */
                if (instance->metadata.mtime == USEC_INFINITY)
                        instance->metadata.mtime = timespec_load(&st.st_mtim) ?: USEC_INFINITY;

                if (instance->metadata.mode == MODE_INVALID)
                        instance->metadata.mode = st.st_mode & 0775; /* mask out world-writability and suid and stuff, for safety */

                /* Can’t be both partial and pending. */
                assert(!(is_partial && is_pending));

                instance->is_partial = is_partial;
                instance->is_pending = is_pending;
        }

        return 0;
}

static int resource_load_from_directory(
                Resource *rr,
                mode_t m,
                const XAttrMatchFilter *filter) {
        _cleanup_closedir_ DIR *d = NULL;

        assert(rr);
        assert(IN_SET(rr->type, RESOURCE_TAR, RESOURCE_REGULAR_FILE, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME));
        assert(IN_SET(m, S_IFREG, S_IFDIR));

        d = opendir(rr->path);
        if (!d) {
                if (errno == ENOENT) {
                        log_debug_errno(errno, "Directory %s does not exist, not loading any resources: %m", rr->path);
                        return 0;
                }

                return log_error_errno(errno, "Failed to open directory '%s': %m", rr->path);
        }

        return resource_load_from_directory_recursive(
                        rr,
                        d,
                        /* relpath= */ NULL,
                        /* relpath_for_matching= */ NULL,
                        m,
                        /* ancestor_is_partial= */ false,
                        /* ancestor_is_pending= */ false,
                        filter);
}

static int resource_load_from_blockdev(Resource *rr) {
        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_(fdisk_unref_tablep) struct fdisk_table *t = NULL;
        size_t n_partitions;
        int r;

        assert(rr);

        r = dlopen_fdisk(LOG_DEBUG);
        if (r < 0)
                return r;

        r = fdisk_new_context_at(AT_FDCWD, rr->path, /* read_only= */ true, /* sector_size= */ UINT32_MAX, &c);
        if (r < 0)
                return log_error_errno(r, "Failed to create fdisk context from '%s': %m", rr->path);

        if (!sym_fdisk_is_labeltype(c, FDISK_DISKLABEL_GPT))
                return log_error_errno(SYNTHETIC_ERRNO(EHWPOISON), "Disk %s has no GPT disk label, not suitable.", rr->path);

        r = sym_fdisk_get_partitions(c, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire partition table: %m");

        n_partitions = sym_fdisk_table_get_nents(t);
        for (size_t i = 0; i < n_partitions; i++)  {
                _cleanup_(instance_metadata_destroy) InstanceMetadata extracted_fields = INSTANCE_METADATA_NULL;
                _cleanup_(partition_info_destroy) PartitionInfo pinfo = PARTITION_INFO_NULL;
                Instance *instance;
                bool is_partial = false, is_pending = false;

                r = read_partition_info(c, t, i, &pinfo);
                if (r < 0)
                        return r;
                if (r == 0) /* not assigned */
                        continue;

                /* Check if partition type matches, either directly or via derived partial/pending type
                 * UUIDs. The derived UUIDs are computed from the configured partition type by hashing it
                 * with a fixed app-specific ID, so we can detect the state without relying on label
                 * prefixes. */
                if (rr->partition_type_set) {
                        sd_id128_t partial_type, pending_type;

                        r = gpt_partition_type_uuid_for_sysupdate_partial(rr->partition_type.uuid, &partial_type);
                        if (r < 0)
                                return log_error_errno(r, "Failed to derive partial partition type UUID: %m");

                        r = gpt_partition_type_uuid_for_sysupdate_pending(rr->partition_type.uuid, &pending_type);
                        if (r < 0)
                                return log_error_errno(r, "Failed to derive pending partition type UUID: %m");

                        if (sd_id128_equal(pinfo.type, partial_type))
                                is_partial = true;
                        else if (sd_id128_equal(pinfo.type, pending_type))
                                is_pending = true;
                        else if (!sd_id128_equal(pinfo.type, rr->partition_type.uuid))
                                continue;
                }

                /* A label of "_empty" means "not used so far" for us */
                if (streq_ptr(pinfo.label, "_empty")) {
                        rr->n_empty++;
                        continue;
                }

                r = pattern_match_many(rr->patterns, pinfo.label, &extracted_fields);
                if (r < 0)
                        return log_error_errno(r, "Failed to match pattern: %m");
                if (IN_SET(r, PATTERN_MATCH_NO, PATTERN_MATCH_RETRY))
                        continue;

                r = resource_add_instance(rr, pinfo.device, &extracted_fields, &instance);
                if (r < 0)
                        return r;

                instance->partition_info = pinfo;
                pinfo = (PartitionInfo) PARTITION_INFO_NULL;

                /* Inherit data from source if not configured explicitly */
                if (!instance->metadata.partition_uuid_set) {
                        instance->metadata.partition_uuid = instance->partition_info.uuid;
                        instance->metadata.partition_uuid_set = true;
                }

                if (!instance->metadata.partition_flags_set) {
                        instance->metadata.partition_flags = instance->partition_info.flags;
                        instance->metadata.partition_flags_set = true;
                }

                if (instance->metadata.read_only < 0)
                        instance->metadata.read_only = instance->partition_info.read_only;

                /* Can’t be both partial and pending. */
                assert(!(is_partial && is_pending));

                instance->is_partial = is_partial;
                instance->is_pending = is_pending;
        }

        return 0;
}

static const char* const resource_manifest_filename_table[_MANIFEST_FORMAT_MAX] = {
        [MANIFEST_FORMAT_SHA256SUMS] = "SHA256SUMS",
        [MANIFEST_FORMAT_UAPI16]     = UAPI16_MANIFEST_FILENAME,
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(resource_manifest_filename, ManifestFormat);

static bool resource_manifest_has_inline_signatures(ManifestFormat style) {
        return style == MANIFEST_FORMAT_UAPI16;
}

static int resource_manifest_url(Resource *rr, char **ret) {
        int r;

        assert(rr);
        assert(IN_SET(rr->manifest_format, MANIFEST_FORMAT_SHA256SUMS, MANIFEST_FORMAT_UAPI16));
        assert(ret);

        /* Returns the URL to acquire the manifest from: either the one explicitly configured, or the
         * default file name for the manifest format, below the resource's URL. */

        if (rr->manifest_path) {
                r = strdup_to(ret, rr->manifest_path);
                if (r < 0)
                        return log_oom();

                return 0;
        }

        const char *fn = resource_manifest_filename_to_string(rr->manifest_format);
        r = import_url_append_component(rr->path, fn, ret);
        if (r < 0)
                return log_error_errno(r, "Failed to append '%s' to URL '%s': %m", fn, rr->path);

        return 0;
}

static int download_manifest(
                ManifestFormat manifest_format,
                const char *manifest_url,
                bool verify_signature,
                struct iovec *ret) {

        int r;

        assert(IN_SET(manifest_format, MANIFEST_FORMAT_SHA256SUMS, MANIFEST_FORMAT_UAPI16));
        assert(manifest_url);
        assert(ret);

        /* Download a SHA256SUMS/Uapi16Manifest file as manifest */

        _cleanup_close_pair_ int pfd[2] = EBADF_PAIR;
        if (pipe2(pfd, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to allocate pipe: %m");

        log_info("%s Acquiring manifest file %s%s", glyph(GLYPH_DOWNLOAD),
                 manifest_url, glyph(GLYPH_ELLIPSIS));

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork_full(
                        "(sd-pull)",
                        (int[]) { -EBADF, pfd[1], STDERR_FILENO },
                        NULL, 0,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_LOG,
                        &pidref);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */

                const char *cmdline[] = {
                        SYSTEMD_PULL_PATH,
                        "raw",
                        "--direct",                        /* just download the specified URL, don't download anything else */
                        "--verify", verify_signature && !resource_manifest_has_inline_signatures(manifest_format) ? "signature" : "no", /* verify the manifest file */
                        manifest_url,
                        "-",                               /* write to stdout */
                        NULL
                };

                r = invoke_callout_binary(SYSTEMD_PULL_PATH, (char *const*) cmdline);
                log_error_errno(r, "Failed to execute %s tool: %m", SYSTEMD_PULL_PATH);
                _exit(EXIT_FAILURE);
        };

        pfd[1] = safe_close(pfd[1]);

        /* We'll first load the entire manifest into memory before parsing it. That's because the
         * systemd-pull tool can validate the download only after its completion, but still pass the data to
         * us as it runs. We thus need to check the return value of the process *before* parsing, to be
         * reasonably safe. */

        _cleanup_fclose_ FILE *manifest = NULL;
        r = take_fdopen_unlocked(pfd+0, "r", &manifest);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate FILE object for manifest file: %m");

        _cleanup_(iovec_done) struct iovec buffer = {};
        r = read_full_stream(manifest, (char**) &buffer.iov_base, &buffer.iov_len);
        if (r < 0)
                return log_error_errno(r, "Failed to read manifest file from child: %m");

        manifest = safe_fclose(manifest);

        r = pidref_wait_for_terminate_and_check("(sd-pull)", &pidref, WAIT_LOG);
        if (r < 0)
                return r;
        if (r != 0)
                return -EPROTO;

        *ret = TAKE_STRUCT(buffer);
        return 0;
}

static bool verify_freshness(void) {
        static int cache = -1;
        int r;

        if (cache >= 0)
                return cache;

        r = secure_getenv_bool("SYSTEMD_SYSUPDATE_VERIFY_FRESHNESS");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_SYSUPDATE_VERIFY_FRESHNESS, ignoring: %m");

        return (cache = r != 0);
}

static int sha256sums_process_magic_file(
                size_t line_nr,
                const char *fn,
                const struct iovec *hash) {

        int r;

        assert(fn);
        assert(iovec_is_set(hash));

        /* Magic files can't be in subdirectories */
        if (is_path(fn)) {
                if (startswith(last_path_component(fn), "BEST-BEFORE-"))
                        log_warning("Ignoring best-before marker '%s' in subdirectory at manifest line %zu.", fn, line_nr);

                return 0;
        }

        /* Validates "BEST-BEFORE-*" magic files we find in SHA256SUMS manifests. For now we ignore the
         * contents of such files (which might change one day), and only look at the file name.
         *
         * Note that if multiple BEST-BEFORE-* files exist in the same listing we'll honour them all, and
         * fail whenever *any* of them indicate a date that's already in the past. */

        const char *e = startswith(fn, "BEST-BEFORE-");
        if (!e)
                return 0;

        /* Even if we ignore if people have non-empty files for this file, let's nonetheless warn about it,
         * so that people fix it. After all we want to retain liberty to maybe one day place some useful data
         * inside it */
        if (!iovec_equal(&IOVEC_MAKE(SHA256_EMPTY, SHA256_DIGEST_SIZE), hash)) /* Expect the hash of an empty file */
                log_warning("Hash of best before marker file '%s' has unexpected value, proceeding anyway.", fn);

        usec_t best_before;
        r = parse_calendar_date(e, &best_before);
        if (r < 0) {
                log_warning_errno(r, "Found best before marker with an invalid date, ignoring: %s", fn);
                return 0;
        }

        usec_t nw = now(CLOCK_REALTIME);
        if (best_before < nw) {
                /* We are past the best before date! Yikes! */

                if (!verify_freshness()) {
                        log_warning("Best before marker indicates out-of-date file list, but told to ignore this, hence ignoring (%s < %s).",
                                    FORMAT_TIMESTAMP(best_before), FORMAT_TIMESTAMP(nw));
                        return 1; /* we processed this line, don't use for pattern matching */
                }

                return log_error_errno(
                                SYNTHETIC_ERRNO(ESTALE),
                                "Best before marker indicates out-of-date file list, refusing (%s < %s).",
                                FORMAT_TIMESTAMP(best_before), FORMAT_TIMESTAMP(nw));
        }

        log_info("Found best before marker, and it checks out, proceeding.");
        return 1; /* we processed this line, don't use for pattern matching */
}

static int sha256sums_line(
                Resource *rr,
                size_t line_nr,
                const char *fn,
                const struct iovec *h) {

        int r;

        assert(rr);
        assert(fn);
        assert(iovec_is_set(h));
        assert(h->iov_len == sizeof_field(InstanceMetadata, sha256sum));

        /* Reject "%" as it is added to the URL verbatim and curl would percent-decode it, which could lead to
         * ".." after the normalization check. */
        if (strchr(fn, '%'))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid filename specified at manifest line %zu, refusing.", line_nr);
        if (string_has_cc(fn, NULL))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Filename contains control characters at manifest line %zu, refusing.", line_nr);

        r = sha256sums_process_magic_file(line_nr, fn, h);
        if (r < 0)
                return r;
        if (r > 0)
                return 0;

        /* If this isn't a magic file, then do the pattern matching */
        _cleanup_(instance_metadata_destroy) InstanceMetadata extracted_fields = INSTANCE_METADATA_NULL;
        r = pattern_match_many(rr->patterns, fn, &extracted_fields);
        if (r < 0)
                return log_error_errno(r, "Failed to match pattern: %m");
        if (!IN_SET(r, PATTERN_MATCH_YES, PATTERN_MATCH_YES_AND_RETRY))
                return 0;

        _cleanup_free_ char *path = NULL;
        r = import_url_append_component(rr->path, fn, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to build instance URL: %m");

        Instance *instance;
        r = resource_add_instance(rr, path, &extracted_fields, &instance);
        if (r < 0)
                return r;

        if (instance->metadata.sha256sum_set) {
                if (memcmp(instance->metadata.sha256sum, h->iov_base, h->iov_len) != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "SHA256 sum parsed from filename and manifest don't match at line %zu, refusing.", line_nr);
        } else {
                memcpy(instance->metadata.sha256sum, h->iov_base, h->iov_len);
                instance->metadata.sha256sum_set = true;
        }

        return 0;
}

static int sha256sums_process(
                Resource *rr,
                const struct iovec *manifest) {

        int r;

        assert(rr);
        assert(manifest);

        _cleanup_fclose_ FILE *f = fmemopen_unlocked(manifest->iov_base, manifest->iov_len, "r");
        if (!f)
                return log_error_errno(errno, "Failed to open manifest buffer: %m");

        for (size_t line_nr = 0;;) {
                _cleanup_free_ char *fn = NULL;
                _cleanup_(iovec_done) struct iovec h = {};
                r = manifest_parse_sums(f, &line_nr, &fn, &h);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 0;

                r = sha256sums_line(rr, line_nr, fn, &h);
                if (r < 0)
                        return r;
        }
}

static int instance_copy_uapi16(Instance *instance, const Uapi16Object *object) {
        assert(instance);
        assert(object);

        /* We verified earlier that these fields are definitely set in the UAPI 16 objects */
        assert(object->type == S_IFREG);
        assert(iovec_is_set(&object->sha256));
        assert(object->size != UINT64_MAX);

        if (instance->metadata.sha256sum_set) {
                if (memcmp_nn(instance->metadata.sha256sum, SHA256_DIGEST_SIZE, object->sha256.iov_base, object->sha256.iov_len) != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "SHA256 sum parsed from filename and manifest don't match, refusing.");
        } else {
                assert(object->sha256.iov_len == SHA256_DIGEST_SIZE);
                memcpy(instance->metadata.sha256sum, object->sha256.iov_base, SHA256_DIGEST_SIZE);
                instance->metadata.sha256sum_set = true;
        }

        if (instance->metadata.size != UINT64_MAX) {
                if (instance->metadata.size != object->size)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Size parsed from filename and manifest don't match, refusing.");
        } else
                instance->metadata.size = object->size;

        if (instance->metadata.mode == MODE_INVALID)
                instance->metadata.mode = object->mode;
        if (instance->metadata.mtime == USEC_INFINITY && object->mtime_nsec < (NSEC_INFINITY / NSEC_PER_USEC) * NSEC_PER_USEC)
                instance->metadata.mtime = object->mtime_nsec / NSEC_PER_USEC;
        if (!instance->metadata.partition_uuid_set && object->gpt_uuid_set) {
                instance->metadata.partition_uuid = object->gpt_uuid;
                instance->metadata.partition_uuid_set = true;
        }

        if (!instance->metadata.partition_flags_set && object->gpt_flags_set) {
                instance->metadata.partition_flags = object->gpt_flags;
                instance->metadata.partition_flags_set = true;
        }

        if (instance->metadata.no_auto < 0 && object->gpt_no_auto >= 0)
                instance->metadata.no_auto = object->gpt_no_auto;
        if (instance->metadata.growfs < 0 && object->gpt_growfs >= 0)
                instance->metadata.growfs = object->gpt_growfs;
        if (instance->metadata.read_only < 0 && object->read_only >= 0)
                instance->metadata.read_only = object->read_only;

        return 0;
}

static bool uapi16_encoding_is_supported(const char *encoding) {
        /* The compression algorithms systemd-pull and systemd-import can decode, by their canonical names,
         * which is what we pass on to them via --compression= */
        Compression c = compression_from_string(encoding);
        return c >= 0 && c != COMPRESSION_NONE && compression_supported(c);
}

static int uapi16_object_resolve_sources(Resource *rr, Uapi16Object *o) {
        size_t n = 0;
        int r;

        assert(rr);
        assert(o);

        /* Validates the "contents" array of a file object, i.e. the list of alternative sources the file may
         * be acquired from. Resolves relative "file" references into absolute URLs, and drops entries we
         * cannot make use of. Returns > 0 if the object is usable (i.e. at least one source remains, or none
         * was listed to begin with, in which case the file is acquired by its name), and 0 if it shall be
         * skipped. */

        for (size_t k = 0; k < o->n_contents; k++) {
                Uapi16Contents *c = o->contents + k;
                bool usable = true;

                if (c->file) {
                        /* Refuse "%" for the same reason as in sha256sums_line() */
                        if (!uapi16_name_is_valid(c->file) || strchr(c->file, '%')) {
                                log_warning("File '%s' refers to invalid file name '%s' in its contents, ignoring source.", o->name, c->file);
                                usable = false;
                        } else {
                                /* "file" references are relative to the location of the manifest file itself */
                                _cleanup_free_ char *url = NULL;
                                if (rr->manifest_path)
                                        r = import_url_change_last_component(rr->manifest_path, c->file, &url);
                                else
                                        r = import_url_append_component(rr->path, c->file, &url);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to build URL for '%s': %m", c->file);

                                free_and_replace(c->url, url);
                                c->file = mfree(c->file);
                        }

                } else if (c->url) {
                        if (!http_url_is_valid(c->url) && !file_url_is_valid(c->url)) {
                                log_warning("File '%s' refers to invalid URL '%s' in its contents, ignoring source.", o->name, c->url);
                                usable = false;
                        }

                } else if (!iovec_is_set(&c->literal)) {
                        log_warning("File '%s' has a contents entry without any source, ignoring it.", o->name);
                        usable = false;
                }

                if (usable && c->encoding && !uapi16_encoding_is_supported(c->encoding)) {
                        log_warning("File '%s' has a source with unsupported encoding '%s', ignoring source.", o->name, c->encoding);
                        usable = false;
                }

                if (usable && c->url) {
                        /* We can only download sources as a whole, i.e. the source must consist of the file
                         * and nothing else. (Literal data we can cut the file out of, hence no such
                         * restriction there.) */
                        if (c->offset != 0 || (c->original_size != UINT64_MAX && c->original_size != o->size)) {
                                log_warning("File '%s' is only a part of source '%s', partial downloads are not supported, ignoring source.", o->name, c->url);
                                usable = false;
                        } else if (!iovec_is_set(&c->encoded_sha256)) {
                                /* Without the digest of the downloaded bytes we cannot verify the download. If
                                 * the source is not encoded it is identical to the file though, and we can
                                 * use the file's digest. */
                                if (c->encoding) {
                                        log_warning("File '%s' has an encoded source without SHA256 digest, ignoring source.", o->name);
                                        usable = false;
                                } else if (!iovec_memdup(&o->sha256, &c->encoded_sha256))
                                        return log_oom();
                        }
                }

                if (!usable) {
                        uapi16_contents_done(c);
                        continue;
                }

                /* Keep the array compact */
                if (n != k) {
                        o->contents[n] = *c;
                        *c = UAPI16_CONTENTS_NULL;
                }
                n++;
        }

        if (o->n_contents > 0 && n == 0) {
                log_warning("File '%s' has no usable source, skipping.", o->name);
                o->n_contents = 0;
                return 0;
        }

        o->n_contents = n;
        return 1;
}

typedef struct Uapi16ProcessContext {
        Resource *resource;
        const XAttrMatchFilter *filter;
} Uapi16ProcessContext;

static int uapi16_process_object(Uapi16Object *object, size_t index, void *userdata) {
        Uapi16ProcessContext *pc = ASSERT_PTR(userdata);
        Resource *rr = ASSERT_PTR(pc->resource);
        int r;

        assert(object);

        /* Honour validity properties, but otherwise ignore intro object */
        if (index == 0) {
                r = uapi16_object_check_validity(object);
                if (r < 0) {
                        if (verify_freshness())
                                return log_error_errno(r, "Manifest file marked invalid: %m");

                        log_warning_errno(r, "Manifest file marked invalid, but freshness checks disabled, proceeding.");
                }

                return 0;
        }

        /* Ignore non-regular files */
        if (!S_ISREG(object->type)) {
                log_debug("Skipping file '%s' as it is not a regular file.", object->name);
                return 0;
        }

        /* Ignore non-matching partition types */
        if (object->gpt_type_uuid_set && rr->partition_type_set && !sd_id128_equal(object->gpt_type_uuid, rr->partition_type.uuid))
                return 0;

        r = uapi16_object_check_validity(object);
        if (r < 0) {
                if (verify_freshness()) {
                        log_warning_errno(r, "File '%s' marked invalid, skipping: %m", object->name);
                        return 0;
                }

                log_warning_errno(r, "File '%s' marked invalid, but freshness checks disabled, proceeding.", object->name);
        }

        if (object->size == UINT64_MAX) {
                log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "File '%s' lacks a size, skipping.", object->name);
                return 0;
        }

        if (!iovec_is_set(&object->sha256)) {
                log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "File '%s' lacks a SHA256 digest, skipping.", object->name);
                return 0;
        }

        /* Refuse "%" for the same reason as in sha256sums_line() */
        if (strchr(object->name, '%')) {
                log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "File '%s' contains a '%%' character, skipping.", object->name);
                return 0;
        }

        r = uapi16_object_resolve_sources(rr, object);
        if (r <= 0)
                return r;

        _cleanup_(instance_metadata_destroy) InstanceMetadata extracted_fields = INSTANCE_METADATA_NULL;
        r = pattern_match_many(rr->patterns, object->name, &extracted_fields);
        if (r < 0)
                return log_error_errno(r, "Failed to match pattern: %m");
        if (!IN_SET(r, PATTERN_MATCH_YES, PATTERN_MATCH_YES_AND_RETRY))
                return 0;

        /* Skip instances restricted to other systems via extended attributes */
        r = xattr_match_filter_test_uapi16_object(pc->filter, object);
        if (r <= 0)
                return r;

        _cleanup_free_ char *path = NULL;
        r = import_url_append_component(rr->path, object->name, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to build instance URL: %m");

        Instance *instance;
        r = resource_add_instance(rr, path, &extracted_fields, &instance);
        if (r < 0)
                return r;

        /* Now copy the fields from the manifest into our instances logic */
        r = instance_copy_uapi16(instance, object);
        if (r < 0)
                return r;

        /* And take possession of the list of sources, we'll need it when acquiring the file */
        instance->sources = TAKE_PTR(object->contents);
        instance->n_sources = object->n_contents;
        object->n_contents = 0;

        /* Similar, for the extended attributes to apply when installing */
        instance->user_xattrs = TAKE_PTR(object->user_xattrs);
        instance->n_user_xattrs = object->n_user_xattrs;
        object->n_user_xattrs = 0;

        return 0;
}

static int uapi16_process(
                Resource *rr,
                const struct iovec *manifest,
                X509 *const *certificates,
                size_t n_certificates,
                const XAttrMatchFilter *filter) {

        assert(rr);
        assert(manifest);

        if (!iovec_is_set(manifest))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Manifest is empty, refusing.");

        _cleanup_fclose_ FILE *f = fmemopen_unlocked(manifest->iov_base, manifest->iov_len, "r");
        if (!f)
                return log_error_errno(errno, "Failed to open manifest buffer as stream: %m");

        return uapi16_manifest_read(
                        f,
                        certificates,
                        n_certificates,
                        uapi16_process_object,
                        &(Uapi16ProcessContext) {
                                .resource = rr,
                                .filter = filter,
                        });
}

static int resource_load_from_web(
                Resource *rr,
                bool verify,
                X509 *const *certificates,
                size_t n_certificates,
                Hashmap **web_cache,
                const XAttrMatchFilter *filter) {

        _cleanup_(iovec_done) struct iovec buf = {};
        struct iovec manifest = {};
        int r;

        assert(rr);
        POINTER_MAY_BE_NULL(web_cache);

        /* Key the cache by the URL of the manifest itself, not the one of the resource, as the former
         * depends on ManifestFormat= and ManifestPath= too. */
        _cleanup_free_ char *manifest_url = NULL;
        r = resource_manifest_url(rr, &manifest_url);
        if (r < 0)
                return r;

        WebCacheItem *ci = web_cache ? web_cache_get_item(*web_cache, manifest_url, verify) : NULL;
        if (ci) {
                log_debug("Manifest web cache hit for %s.", manifest_url);

                manifest = IOVEC_MAKE(ci->data, ci->size);
        } else {
                log_debug("Manifest web cache miss for %s.", manifest_url);

                r = download_manifest(rr->manifest_format, manifest_url, verify, &buf);
                if (r < 0)
                        return r;

                manifest = buf;
        }

        switch (rr->manifest_format) {

        case MANIFEST_FORMAT_SHA256SUMS:
                r = sha256sums_process(rr, &manifest);
                break;

        case MANIFEST_FORMAT_UAPI16:
                /* UAPI.16 manifests carry their signatures inline, hence systemd-pull didn't verify
                 * anything, and we do it here. */
                r = uapi16_process(
                                rr,
                                &manifest,
                                verify ? certificates : NULL,
                                verify ? n_certificates : 0,
                                filter);
                break;

        default:
                assert_not_reached();
        }
        if (r < 0)
                return r;

        if (!ci && web_cache) {
                r = web_cache_add_item(web_cache, manifest_url, verify, manifest.iov_base, manifest.iov_len);
                if (r < 0)
                        log_debug_errno(r, "Failed to add manifest '%s' to cache, ignoring: %m", manifest_url);
                else
                        log_debug("Added manifest '%s' to cache.", manifest_url);
        }

        return 0;
}

static int instance_cmp(Instance *const*a, Instance *const*b) {
        int r;

        assert(a);
        assert(b);
        assert(*a);
        assert(*b);
        assert((*a)->metadata.version);
        assert((*b)->metadata.version);

        /* Newest version at the beginning */
        r = strverscmp_improved((*a)->metadata.version, (*b)->metadata.version);
        if (r != 0)
                return -r;

        /* Instances don't have to be uniquely named (uniqueness on partition tables is not enforced at all,
         * and since we allow multiple matching patterns not even in directories they are unique). Hence
         * let's order by path as secondary ordering key. */
        return path_compare((*a)->path, (*b)->path);
}

int resource_load_instances(
                Resource *rr,
                bool verify,
                X509 *const *certificates,
                size_t n_certificates,
                Hashmap **web_cache,
                const XAttrMatchFilter *filter) {
        int r;

        assert(rr);

        switch (rr->type) {

        case RESOURCE_TAR:
        case RESOURCE_REGULAR_FILE:
                r = resource_load_from_directory(rr, S_IFREG, filter);
                break;

        case RESOURCE_DIRECTORY:
        case RESOURCE_SUBVOLUME:
                r = resource_load_from_directory(rr, S_IFDIR, filter);
                break;

        case RESOURCE_PARTITION:
                r = resource_load_from_blockdev(rr);
                break;

        case RESOURCE_URL_FILE:
        case RESOURCE_URL_TAR:
                r = resource_load_from_web(rr, verify, certificates, n_certificates, web_cache, filter);
                break;

        default:
                assert_not_reached();
        }
        if (r < 0)
                return r;

        typesafe_qsort(rr->instances, rr->n_instances, instance_cmp);

        /* There are various cases where the same version can be provided by different files either due to
         * multiple match patterns defined in a naming scheme transition or due to a subdirectory containing
         * the same file again when the glob directory prefix is used, or due to a wildcard like @s or @t
         * being used and the files offer different values there while reporting the same version. Since
         * this could lead to unexpected behavior we report this here to the user. */
        for (size_t i = 1; i < rr->n_instances; i++) {
                Instance *a = rr->instances[i - 1], *b = rr->instances[i];

                if (strverscmp_improved(a->metadata.version, b->metadata.version) != 0 || streq(a->path, b->path))
                        continue;

                _cleanup_free_ char *suffix = NULL;

                if (!streq(a->metadata.version, b->metadata.version)) {
                        suffix = strjoin("/'", b->metadata.version, "'");
                        if (!suffix)
                                return log_oom();
                }

                log_info("Multiple instances of version '%s'%s found at '%s' and '%s'.",
                         a->metadata.version,
                         strempty(suffix),
                         a->path, b->path);
        }

        return 0;
}

static int instance_version_match(Instance *const*a, Instance *const*b) {
        assert(a);
        assert(b);
        assert(*a);
        assert(*b);
        assert((*a)->metadata.version);
        assert((*b)->metadata.version);

        /* List is sorted newest-to-oldest */
        return -strverscmp_improved((*a)->metadata.version, (*b)->metadata.version);
}

Instance* resource_find_instance(Resource *rr, const char *version) {
        Instance key = {
                .metadata.version = (char*) version,
        }, *k = &key;

        Instance **found;
        found = typesafe_bsearch(&k, rr->instances, rr->n_instances, instance_version_match);
        if (!found)
                return NULL;

        return *found;
}

int resource_resolve_path(
                Resource *rr,
                const char *root,
                const char *relative_to_directory,
                const char *node) {

        _cleanup_free_ char *p = NULL;
        dev_t d;
        int r;

        assert(rr);

        if (IN_SET(rr->path_relative_to, PATH_RELATIVE_TO_ESP, PATH_RELATIVE_TO_XBOOTLDR, PATH_RELATIVE_TO_BOOT) &&
            !IN_SET(rr->type, RESOURCE_REGULAR_FILE, RESOURCE_DIRECTORY))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Paths relative to %s are only allowed for regular-file or directory resources.",
                                       path_relative_to_to_string(rr->path_relative_to));

        if (rr->path_auto) {
                /* NB: If the root mount has been replaced by some form of volatile file system (overlayfs),
                 * the original root block device node is symlinked in /run/systemd/volatile-root. Let's
                 * follow that link here. If that doesn't exist, we check the backing device of "/usr". We
                 * don't actually check the backing device of the root fs "/", in order to support
                 * environments where the root fs is a tmpfs, and the OS itself placed exclusively in
                 * /usr/. */

                if (rr->type != RESOURCE_PARTITION)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Automatic root path discovery only supported for partition resources.");

                if (node) { /* If --image= is specified, directly use the loopback device */
                        r = free_and_strdup_warn(&rr->path, node);
                        if (r < 0)
                                return r;

                        return 0;
                }

                if (root)
                        return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                               "Block device is not allowed when using --root= mode.");

                struct stat orig_root_stats;
                r = RET_NERRNO(stat("/run/systemd/volatile-root", &orig_root_stats));
                if (r < 0) {
                        if (r != -ENOENT)
                                return log_error_errno(r, "Failed to stat /run/systemd/volatile-root: %m");

                        /* volatile-root not found */
                        r = get_block_device_harder("/usr/", &d);
                        if (r == 0) /* Not backed by a block device? Let's see if this is a sysext overlayfs instance */
                                r = extension_overlay_block("/usr/", IMAGE_SYSEXT, &d);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine block device of file system: %m");
                } else if (!S_ISBLK(orig_root_stats.st_mode)) /* symlink was present but not block device */
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK), "/run/systemd/volatile-root is not linked to a block device.");
                else /* symlink was present and a block device */
                        d = orig_root_stats.st_rdev;

        } else if (rr->type == RESOURCE_PARTITION) {
                _cleanup_close_ int fd = -EBADF, real_fd = -EBADF;
                _cleanup_free_ char *resolved = NULL;
                struct stat st;

                r = chase(rr->path, root, CHASE_PREFIX_ROOT|CHASE_TRIGGER_AUTOFS, &resolved, &fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve '%s': %m", rr->path);

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", resolved);

                if (S_ISBLK(st.st_mode) && root)
                        return log_error_errno(SYNTHETIC_ERRNO(EPERM), "When using --root= or --image= access to device nodes is prohibited.");

                if (S_ISREG(st.st_mode) || S_ISBLK(st.st_mode))
                        /* Not a directory, hence no need to find backing block device for the path */
                        return free_and_replace(rr->path, resolved);

                if (!S_ISDIR(st.st_mode))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTDIR), "Target path '%s' does not refer to regular file, directory or block device, refusing.",  rr->path);

                if (node) { /* If --image= is specified all file systems are backed by the same loopback device, hence shortcut things. */
                        r = free_and_strdup_warn(&rr->path, node);
                        if (r < 0)
                                return r;

                        return 0;
                }

                real_fd = fd_reopen(fd, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
                if (real_fd < 0)
                        return log_error_errno(real_fd, "Failed to convert O_PATH file descriptor for %s to regular file descriptor: %m", rr->path);

                r = get_block_device_harder_fd(real_fd, &d);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine block device of file system: %m");

        } else if (RESOURCE_IS_FILESYSTEM(rr->type)) {
                _cleanup_free_ char *resolved = NULL, *relative_to = NULL;
                ChaseFlags chase_flags = CHASE_NONEXISTENT | CHASE_PREFIX_ROOT | CHASE_TRIGGER_AUTOFS;

                if (rr->path_relative_to == PATH_RELATIVE_TO_EXPLICIT) {
                        assert(relative_to_directory);

                        relative_to = strdup(relative_to_directory);
                        if (!relative_to)
                                return log_oom();
                } else if (rr->path_relative_to == PATH_RELATIVE_TO_ROOT) {
                        relative_to = strdup(empty_to_root(root));
                        if (!relative_to)
                                return log_oom();
                } else { /* boot, esp, or xbootldr */
                        r = 0;
                        if (IN_SET(rr->path_relative_to, PATH_RELATIVE_TO_BOOT, PATH_RELATIVE_TO_XBOOTLDR))
                                r = find_xbootldr_and_warn(root, /* path= */ NULL, /* unprivileged_mode= */ -1, &relative_to, /* ret_fd= */ NULL);
                        if (r == -ENOKEY || rr->path_relative_to == PATH_RELATIVE_TO_ESP)
                                r = find_esp_and_warn(root, /* path= */ NULL, /* unprivileged_mode= */ -1, &relative_to, /* ret_fd= */ NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to resolve $BOOT: %m");
                        log_debug("Resolved $BOOT to '%s'", relative_to);

                        /* Since this partition is read from EFI, there should be no symlinks */
                        chase_flags |= CHASE_PROHIBIT_SYMLINKS;
                }

                r = chase(rr->path, relative_to, chase_flags, &resolved, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve '%s' (relative to '%s'): %m", rr->path, relative_to);

                return free_and_replace(rr->path, resolved);
        } else
                return 0; /* Otherwise assume there's nothing to resolve */

        r = block_get_whole_disk(d, &d);
        if (r < 0)
                return log_error_errno(r, "Failed to find whole disk device for partition backing file system: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "File system is not placed on a partition block device, cannot determine whole block device backing root file system.");

        r = devname_from_devnum(S_IFBLK, d, &p);
        if (r < 0)
                return r;

        if (rr->path)
                log_info("Automatically discovered block device '%s' from '%s'.", p, rr->path);
        else
                log_info("Automatically discovered root block device '%s'.", p);

        free_and_replace(rr->path, p);
        return 1;
}

static const char *resource_type_table[_RESOURCE_TYPE_MAX] = {
        [RESOURCE_URL_FILE]     = "url-file",
        [RESOURCE_URL_TAR]      = "url-tar",
        [RESOURCE_TAR]          = "tar",
        [RESOURCE_PARTITION]    = "partition",
        [RESOURCE_REGULAR_FILE] = "regular-file",
        [RESOURCE_DIRECTORY]    = "directory",
        [RESOURCE_SUBVOLUME]    = "subvolume",
};

DEFINE_STRING_TABLE_LOOKUP(resource_type, ResourceType);

static const char *path_relative_to_table[_PATH_RELATIVE_TO_MAX] = {
        [PATH_RELATIVE_TO_ROOT]     = "root",
        [PATH_RELATIVE_TO_ESP]      = "esp",
        [PATH_RELATIVE_TO_XBOOTLDR] = "xbootldr",
        [PATH_RELATIVE_TO_BOOT]     = "boot",
        [PATH_RELATIVE_TO_EXPLICIT] = "explicit",
};

DEFINE_STRING_TABLE_LOOKUP(path_relative_to, PathRelativeTo);
