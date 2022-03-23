/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "chase-symlinks.h"
#include "dirent-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "glyph-util.h"
#include "gpt.h"
#include "hexdecoct.h"
#include "import-util.h"
#include "macro.h"
#include "process-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "sysupdate-cache.h"
#include "sysupdate-instance.h"
#include "sysupdate-pattern.h"
#include "sysupdate-resource.h"
#include "sysupdate.h"
#include "utf8.h"

void resource_destroy(Resource *rr) {
        assert(rr);

        free(rr->path);
        strv_free(rr->patterns);

        for (size_t i = 0; i < rr->n_instances; i++)
                instance_free(rr->instances[i]);
        free(rr->instances);
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

static int resource_load_from_directory(
                Resource *rr,
                mode_t m) {

        _cleanup_(closedirp) DIR *d = NULL;
        int r;

        assert(rr);
        assert(IN_SET(rr->type, RESOURCE_TAR, RESOURCE_REGULAR_FILE, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME));
        assert(IN_SET(m, S_IFREG, S_IFDIR));

        d = opendir(rr->path);
        if (!d) {
                if (errno == ENOENT) {
                        log_debug("Directory %s does not exist, not loading any resources.", rr->path);
                        return 0;
                }

                return log_error_errno(errno, "Failed to open directory '%s': %m", rr->path);
        }

        for (;;) {
                _cleanup_(instance_metadata_destroy) InstanceMetadata extracted_fields = INSTANCE_METADATA_NULL;
                _cleanup_free_ char *joined = NULL;
                Instance *instance;
                struct dirent *de;
                struct stat st;

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
                        if (m != S_IFDIR)
                                continue;

                        break;

                case DT_REG:
                        if (m != S_IFREG)
                                continue;
                        break;

                default:
                        continue;
                }

                if (fstatat(dirfd(d), de->d_name, &st, AT_NO_AUTOMOUNT) < 0) {
                        if (errno == ENOENT) /* Gone by now? */
                                continue;

                        return log_error_errno(errno, "Failed to stat %s/%s: %m", rr->path, de->d_name);
                }

                if ((st.st_mode & S_IFMT) != m)
                        continue;

                r = pattern_match_many(rr->patterns, de->d_name, &extracted_fields);
                if (r < 0)
                        return log_error_errno(r, "Failed to match pattern: %m");
                if (r == 0)
                        continue;

                joined = path_join(rr->path, de->d_name);
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
        }

        return 0;
}

static int resource_load_from_blockdev(Resource *rr) {
        _cleanup_(fdisk_unref_contextp) struct fdisk_context *c = NULL;
        _cleanup_(fdisk_unref_tablep) struct fdisk_table *t = NULL;
        size_t n_partitions;
        int r;

        assert(rr);

        c = fdisk_new_context();
        if (!c)
                return log_oom();

        r = fdisk_assign_device(c, rr->path, /* readonly= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to open device '%s': %m", rr->path);

        if (!fdisk_is_labeltype(c, FDISK_DISKLABEL_GPT))
                return log_error_errno(SYNTHETIC_ERRNO(EHWPOISON), "Disk %s has no GPT disk label, not suitable.", rr->path);

        r = fdisk_get_partitions(c, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire partition table: %m");

        n_partitions = fdisk_table_get_nents(t);
        for (size_t i = 0; i < n_partitions; i++)  {
                _cleanup_(instance_metadata_destroy) InstanceMetadata extracted_fields = INSTANCE_METADATA_NULL;
                _cleanup_(partition_info_destroy) PartitionInfo pinfo = PARTITION_INFO_NULL;
                Instance *instance;

                r = read_partition_info(c, t, i, &pinfo);
                if (r < 0)
                        return r;
                if (r == 0) /* not assigned */
                        continue;

                /* Check if partition type matches */
                if (rr->partition_type_set && !sd_id128_equal(pinfo.type, rr->partition_type))
                        continue;

                /* A label of "_empty" means "not used so far" for us */
                if (streq_ptr(pinfo.label, "_empty")) {
                        rr->n_empty++;
                        continue;
                }

                r = pattern_match_many(rr->patterns, pinfo.label, &extracted_fields);
                if (r < 0)
                        return log_error_errno(r, "Failed to match pattern: %m");
                if (r == 0)
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
        }

        return 0;
}

static int download_manifest(
                const char *url,
                bool verify_signature,
                char **ret_buffer,
                size_t *ret_size) {

        _cleanup_free_ char *buffer = NULL, *suffixed_url = NULL;
        _cleanup_(close_pairp) int pfd[2] = { -1, -1 };
        _cleanup_fclose_ FILE *manifest = NULL;
        size_t size = 0;
        pid_t pid;
        int r;

        assert(url);
        assert(ret_buffer);
        assert(ret_size);

        /* Download a SHA256SUMS file as manifest */

        r = import_url_append_component(url, "SHA256SUMS", &suffixed_url);
        if (r < 0)
                return log_error_errno(r, "Failed to append SHA256SUMS to URL: %m");

        if (pipe2(pfd, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to allocate pipe: %m");

        log_info("%s Acquiring manifest file %s…", special_glyph(SPECIAL_GLYPH_DOWNLOAD), suffixed_url);

        r = safe_fork("(sd-pull)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */

                const char *cmdline[] = {
                        "systemd-pull",
                        "raw",
                        "--direct",                        /* just download the specified URL, don't download anything else */
                        "--verify", verify_signature ? "signature" : "no", /* verify the manifest file */
                        suffixed_url,
                        "-",                               /* write to stdout */
                        NULL
                };

                pfd[0] = safe_close(pfd[0]);

                r = rearrange_stdio(-1, pfd[1], STDERR_FILENO);
                if (r < 0) {
                        log_error_errno(r, "Failed to rearrange stdin/stdout: %m");
                        _exit(EXIT_FAILURE);
                }

                (void) unsetenv("NOTIFY_SOCKET");
                execv(pull_binary_path(), (char *const*) cmdline);
                log_error_errno(errno, "Failed to execute %s tool: %m", pull_binary_path());
                _exit(EXIT_FAILURE);
        };

        pfd[1] = safe_close(pfd[1]);

        /* We'll first load the entire manifest into memory before parsing it. That's because the
         * systemd-pull tool can validate the download only after its completion, but still pass the data to
         * us as it runs. We thus need to check the return value of the process *before* parsing, to be
         * reasonably safe. */

        manifest = fdopen(pfd[0], "r");
        if (!manifest)
                return log_error_errno(errno, "Failed allocate FILE object for manifest file: %m");

        TAKE_FD(pfd[0]);

        r = read_full_stream(manifest, &buffer, &size);
        if (r < 0)
                return log_error_errno(r, "Failed to read manifest file from child: %m");

        manifest = safe_fclose(manifest);

        r = wait_for_terminate_and_check("(sd-pull)", pid, WAIT_LOG);
        if (r < 0)
                return r;
        if (r != 0)
                return -EPROTO;

        *ret_buffer = TAKE_PTR(buffer);
        *ret_size = size;

        return 0;
}

static int resource_load_from_web(
                Resource *rr,
                bool verify,
                Hashmap **web_cache) {

        size_t manifest_size = 0, left = 0;
        _cleanup_free_ char *buf = NULL;
        const char *manifest, *p;
        size_t line_nr = 1;
        WebCacheItem *ci;
        int r;

        assert(rr);

        ci = web_cache ? web_cache_get_item(*web_cache, rr->path, verify) : NULL;
        if (ci) {
                log_debug("Manifest web cache hit for %s.", rr->path);

                manifest = (char*) ci->data;
                manifest_size = ci->size;
        } else {
                log_debug("Manifest web cache miss for %s.", rr->path);

                r = download_manifest(rr->path, verify, &buf, &manifest_size);
                if (r < 0)
                        return r;

                manifest = buf;
        }

        if (memchr(manifest, 0, manifest_size))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Manifest file has embedded NUL byte, refusing.");
        if (!utf8_is_valid_n(manifest, manifest_size))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Manifest file is not valid UTF-8, refusing.");

        p = manifest;
        left = manifest_size;

        while (left > 0) {
                _cleanup_(instance_metadata_destroy) InstanceMetadata extracted_fields = INSTANCE_METADATA_NULL;
                _cleanup_free_ char *fn = NULL;
                _cleanup_free_ void *h = NULL;
                Instance *instance;
                const char *e;
                size_t hlen;

                /* 64 character hash + separator + filename + newline */
                if (left < 67)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Corrupt manifest at line %zu, refusing.", line_nr);

                if (p[0] == '\\')
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "File names with escapes not supported in manifest at line %zu, refusing.", line_nr);

                r = unhexmem(p, 64, &h, &hlen);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse digest at manifest line %zu, refusing.", line_nr);

                p += 64, left -= 64;

                if (*p != ' ')
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing space separator at manifest line %zu, refusing.", line_nr);
                p++, left--;

                if (!IN_SET(*p, '*', ' '))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing binary/text input marker at manifest line %zu, refusing.", line_nr);
                p++, left--;

                e = memchr(p, '\n', left);
                if (!e)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Truncated manifest file at line %zu, refusing.", line_nr);
                if (e == p)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Empty filename specified at manifest line %zu, refusing.", line_nr);

                fn = strndup(p, e - p);
                if (!fn)
                        return log_oom();

                if (!filename_is_valid(fn))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid filename specified at manifest line %zu, refusing.", line_nr);
                if (string_has_cc(fn, NULL))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Filename contains control characters at manifest line %zu, refusing.", line_nr);

                r = pattern_match_many(rr->patterns, fn, &extracted_fields);
                if (r < 0)
                        return log_error_errno(r, "Failed to match pattern: %m");
                if (r > 0) {
                        _cleanup_free_ char *path = NULL;

                        r = import_url_append_component(rr->path, fn, &path);
                        if (r < 0)
                                return log_error_errno(r, "Failed to build instance URL: %m");

                        r = resource_add_instance(rr, path, &extracted_fields, &instance);
                        if (r < 0)
                                return r;

                        assert(hlen == sizeof(instance->metadata.sha256sum));

                        if (instance->metadata.sha256sum_set) {
                                if (memcmp(instance->metadata.sha256sum, h, hlen) != 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "SHA256 sum parsed from filename and manifest don't match at line %zu, refusing.", line_nr);
                        } else {
                                memcpy(instance->metadata.sha256sum, h, hlen);
                                instance->metadata.sha256sum_set = true;
                        }
                }

                left -= (e - p) + 1;
                p = e + 1;

                line_nr++;
        }

        if (!ci && web_cache) {
                r = web_cache_add_item(web_cache, rr->path, verify, manifest, manifest_size);
                if (r < 0)
                        log_debug_errno(r, "Failed to add manifest '%s' to cache, ignoring: %m", rr->path);
                else
                        log_debug("Added manifest '%s' to cache.", rr->path);
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

int resource_load_instances(Resource *rr, bool verify, Hashmap **web_cache) {
        int r;

        assert(rr);

        switch (rr->type) {

        case RESOURCE_TAR:
        case RESOURCE_REGULAR_FILE:
                r = resource_load_from_directory(rr, S_IFREG);
                break;

        case RESOURCE_DIRECTORY:
        case RESOURCE_SUBVOLUME:
                r = resource_load_from_directory(rr, S_IFDIR);
                break;

        case RESOURCE_PARTITION:
                r = resource_load_from_blockdev(rr);
                break;

        case RESOURCE_URL_FILE:
        case RESOURCE_URL_TAR:
                r = resource_load_from_web(rr, verify, web_cache);
                break;

        default:
                assert_not_reached();
        }
        if (r < 0)
                return r;

        typesafe_qsort(rr->instances, rr->n_instances, instance_cmp);
        return 0;
}

Instance* resource_find_instance(Resource *rr, const char *version) {
        Instance key = {
                .metadata.version = (char*) version,
        }, *k = &key;

        return typesafe_bsearch(&k, rr->instances, rr->n_instances, instance_cmp);
}

int resource_resolve_path(
                Resource *rr,
                const char *root,
                const char *node) {

        _cleanup_free_ char *p = NULL;
        dev_t d;
        int r;

        assert(rr);

        if (rr->path_auto) {

                /* NB: we don't actually check the backing device of the root fs "/", but of "/usr", in order
                 * to support environments where the root fs is a tmpfs, and the OS itself placed exclusively
                 * in /usr/. */

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

                r = get_block_device_harder("/usr/", &d);

        } else if (rr->type == RESOURCE_PARTITION) {
                _cleanup_close_ int fd = -1, real_fd = -1;
                _cleanup_free_ char *resolved = NULL;
                struct stat st;

                r = chase_symlinks(rr->path, root, CHASE_PREFIX_ROOT, &resolved, &fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve '%s': %m", rr->path);

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", resolved);

                if (S_ISBLK(st.st_mode) && root)
                        return log_error_errno(SYNTHETIC_ERRNO(EPERM), "When using --root= or --image= access to device nodes is prohibited.");

                if (S_ISREG(st.st_mode) || S_ISBLK(st.st_mode)) {
                        /* Not a directory, hence no need to find backing block device for the path */
                        free_and_replace(rr->path, resolved);
                        return 0;
                }

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

                r = get_block_device_harder_fd(fd, &d);

        } else if (RESOURCE_IS_FILESYSTEM(rr->type) && root) {
                _cleanup_free_ char *resolved = NULL;

                r = chase_symlinks(rr->path, root, CHASE_PREFIX_ROOT, &resolved, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve '%s': %m", rr->path);

                free_and_replace(rr->path, resolved);
                return 0;
        } else
                return 0; /* Otherwise assume there's nothing to resolve */

        if (r < 0)
                return log_error_errno(r, "Failed to determine block device of file system: %m");

        r = block_get_whole_disk(d, &d);
        if (r < 0)
                return log_error_errno(r, "Failed to find whole disk device for partition backing file system: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "File system is not placed on a partition block device, cannot determine whole block device backing root file system.");

        r = device_path_make_canonical(S_IFBLK, d, &p);
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
