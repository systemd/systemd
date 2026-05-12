/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>
#include <stdio.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "discover-image.h"
#include "env-util.h"
#include "format-table.h"
#include "hexdecoct.h"
#include "import-common.h"
#include "import-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "log.h"
#include "main-func.h"
#include "oci-util.h"
#include "options.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pull-oci.h"
#include "pull-raw.h"
#include "pull-tar.h"
#include "runtime-scope.h"
#include "signal-util.h"
#include "string-util.h"
#include "verbs.h"
#include "web-util.h"

static char *arg_image_root = NULL;
static ImportVerify arg_verify = IMPORT_VERIFY_SIGNATURE;
static ImportFlags arg_import_flags = IMPORT_PULL_SETTINGS | IMPORT_PULL_ROOTHASH | IMPORT_PULL_ROOTHASH_SIGNATURE | IMPORT_PULL_VERITY | IMPORT_BTRFS_SUBVOL | IMPORT_BTRFS_QUOTA | IMPORT_CONVERT_QCOW2 | IMPORT_SYNC;
static uint64_t arg_offset = UINT64_MAX, arg_size_max = UINT64_MAX;
static struct iovec arg_checksum = {};
static ImageClass arg_class = IMAGE_MACHINE;
static RuntimeScope arg_runtime_scope = _RUNTIME_SCOPE_INVALID;

STATIC_DESTRUCTOR_REGISTER(arg_checksum, iovec_done);
STATIC_DESTRUCTOR_REGISTER(arg_image_root, freep);

static int normalize_local(const char *local, const char *url, char **ret) {
        _cleanup_free_ char *ll = NULL;
        int r;

        assert(ret);

        if (arg_import_flags & IMPORT_DIRECT) {

                if (!local)
                        log_debug("Writing downloaded data to STDOUT.");
                else {
                        if (!path_is_absolute(local)) {
                                ll = path_join(arg_image_root, local);
                                if (!ll)
                                        return log_oom();

                                local = ll;
                        }

                        if (!path_is_valid(local))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Local path name '%s' is not valid.", local);
                }

        } else if (local) {

                if (!image_name_is_valid(local))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Local image name '%s' is not valid.",
                                               local);

                if (!FLAGS_SET(arg_import_flags, IMPORT_FORCE)) {
                        r = image_find(arg_runtime_scope, arg_class, local, NULL, NULL);
                        if (r < 0) {
                                if (r != -ENOENT)
                                        return log_error_errno(r, "Failed to check whether image '%s' exists: %m", local);
                        } else
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "Image '%s' already exists.",
                                                       local);
                }
        }

        if (!ll && local) {
                ll = strdup(local);
                if (!ll)
                        return log_oom();
        }

        if (ll) {
                if (arg_offset != UINT64_MAX)
                        log_info("Pulling '%s', saving at offset %" PRIu64 " in '%s'.", url, arg_offset, ll);
                else
                        log_info("Pulling '%s', saving as '%s'.", url, ll);
        } else
                log_info("Pulling '%s'.", url);

        if (!FLAGS_SET(arg_import_flags, IMPORT_DIRECT))
                log_info("Operating on image directory '%s'.", arg_image_root);

        if (!FLAGS_SET(arg_import_flags, IMPORT_SYNC))
                log_info("File system synchronization on completion is off.");

        *ret = TAKE_PTR(ll);
        return 0;
}

static void on_tar_finished(TarPull *pull, int error, void *userdata) {
        sd_event *event = userdata;
        assert(pull);

        if (error == 0)
                log_info("Operation completed successfully.");

        sd_event_exit(event, ABS(error));
}

VERB(verb_tar, "tar", "URL [NAME]", 2, 3, 0, "Download a TAR image");
static int verb_tar(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_free_ char *ll = NULL, *normalized = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(tar_pull_unrefp) TarPull *pull = NULL;
        const char *url, *local;
        int r;

        url = argv[1];
        if (!http_url_is_valid(url) && !file_url_is_valid(url))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "URL '%s' is not valid.", url);

        if (argc >= 3)
                local = empty_or_dash_to_null(argv[2]);
        else {
                _cleanup_free_ char *l = NULL;

                r = import_url_last_component(url, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to get final component of URL: %m");

                r = tar_strip_suffixes(l, &ll);
                if (r < 0)
                        return log_oom();

                local = ll;
        }

        if (!local && FLAGS_SET(arg_import_flags, IMPORT_DIRECT))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Pulling tar images to STDOUT is not supported.");

        r = normalize_local(local, url, &normalized);
        if (r < 0)
                return r;

        r = import_allocate_event_with_signals(&event);
        if (r < 0)
                return r;

        r = tar_pull_new(&pull, event, arg_image_root, on_tar_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate puller: %m");

        r = tar_pull_start(
                        pull,
                        url,
                        normalized,
                        arg_import_flags & IMPORT_PULL_FLAGS_MASK_TAR,
                        arg_verify,
                        &arg_checksum);
        if (r < 0)
                return log_error_errno(r, "Failed to pull image: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        log_info("Exiting.");
        return -r;
}

static void on_raw_finished(RawPull *pull, int error, void *userdata) {
        sd_event *event = userdata;
        assert(pull);

        if (error == 0)
                log_info("Operation completed successfully.");

        sd_event_exit(event, ABS(error));
}

VERB(verb_raw, "raw", "URL [NAME]", 2, 3, 0, "Download a RAW image");
static int verb_raw(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_free_ char *ll = NULL, *normalized = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(raw_pull_unrefp) RawPull *pull = NULL;
        const char *url, *local;
        int r;

        url = argv[1];
        if (!http_url_is_valid(url) && !file_url_is_valid(url))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "URL '%s' is not valid.", url);

        if (argc >= 3)
                local = empty_or_dash_to_null(argv[2]);
        else {
                _cleanup_free_ char *l = NULL;

                r = import_url_last_component(url, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to get final component of URL: %m");

                r = raw_strip_suffixes(l, &ll);
                if (r < 0)
                        return log_oom();

                local = ll;
        }

        r = normalize_local(local, url, &normalized);
        if (r < 0)
                return r;

        r = import_allocate_event_with_signals(&event);
        if (r < 0)
                return r;

        r = raw_pull_new(&pull, event, arg_image_root, on_raw_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate puller: %m");

        r = raw_pull_start(
                        pull,
                        url,
                        normalized,
                        arg_offset,
                        arg_size_max,
                        arg_import_flags & IMPORT_PULL_FLAGS_MASK_RAW,
                        arg_verify,
                        &arg_checksum);
        if (r < 0)
                return log_error_errno(r, "Failed to pull image: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        log_info("Exiting.");
        return -r;
}

static void on_oci_finished(OciPull *pull, int error, void *userdata) {
        sd_event *event = userdata;
        assert(pull);

        if (error == 0)
                log_info("Operation completed successfully.");

        sd_event_exit(event, ABS(error));
}

VERB(verb_oci, "oci", "REF [NAME]", 2, 3, 0, "Download an OCI image");
static int verb_oci(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        const char *ref = argv[1];

        _cleanup_free_ char *image = NULL;
        r = oci_ref_parse(ref, /* ret_registry= */ NULL, &image, /* ret_tag= */ NULL);
        if (r == -EINVAL)
                return log_error_errno(r, "OCI ref '%s' is invalid.", ref);
        if (r < 0)
                return log_error_errno(r, "Failed to check of OCI ref '%s' is valid: %m", ref);

        _cleanup_free_ char *l = NULL;
        const char *local;
        if (argc >= 3)
                local = empty_or_dash_to_null(argv[2]);
        else {
                r = path_extract_filename(image, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to get extract final component of '%s': %m", image);

                local = l;
        }

        _cleanup_free_ char *normalized = NULL;
        r = normalize_local(local, ref, &normalized);
        if (r < 0)
                return r;

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        r = import_allocate_event_with_signals(&event);
        if (r < 0)
                return r;

        _cleanup_(oci_pull_unrefp) OciPull *pull = NULL;
        r = oci_pull_new(&pull, event, arg_image_root, on_oci_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate puller: %m");

        r = oci_pull_start(
                        pull,
                        ref,
                        normalized,
                        arg_import_flags & IMPORT_PULL_FLAGS_MASK_OCI);
        if (r < 0)
                return log_error_errno(r, "Failed to pull image: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        log_info("Exiting.");
        return -r;
}

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL, *verbs = NULL;
        int r;

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, options);

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "%sDownload disk images.%s\n"
               "\n%sCommands:%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        printf("\n%sOptions:%s\n",
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        return 0;
}

VERB_COMMON_HELP_HIDDEN(help);

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        int r;
        bool auto_settings = true, auto_keep_download = true;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("force", NULL, "Force creation of image"):
                        arg_import_flags |= IMPORT_FORCE;
                        break;

                OPTION_LONG("image-root", "PATH", "Image root directory"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_image_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("verify", "MODE",
                            "Verify downloaded image, one of: 'no', 'checksum', 'signature' or literal SHA256 hash"): {
                        ImportVerify v;

                        v = import_verify_from_string(opts.arg);
                        if (v < 0) {
                                _cleanup_free_ void *h = NULL;
                                size_t n;

                                /* If this is not a valid verification mode, maybe it's a literally specified
                                 * SHA256 hash? We can handle that too... */

                                r = unhexmem(opts.arg, &h, &n);
                                if (r < 0 || n == 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Invalid verification setting: %s", opts.arg);
                                if (n != 32)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "64 hex character SHA256 hash required when specifying explicit checksum, %zu specified", n * 2);

                                iovec_done(&arg_checksum);
                                arg_checksum = IOVEC_MAKE(TAKE_PTR(h), n);

                                arg_import_flags &= ~(IMPORT_PULL_SETTINGS|IMPORT_PULL_ROOTHASH|IMPORT_PULL_ROOTHASH_SIGNATURE|IMPORT_PULL_VERITY);
                                arg_verify = _IMPORT_VERIFY_INVALID;
                        } else
                                arg_verify = v;

                        break;
                }

                OPTION_LONG("settings", "BOOL", "Download settings file with image"):
                        r = parse_boolean_argument("--settings=", opts.arg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_import_flags, IMPORT_PULL_SETTINGS, r);
                        auto_settings = false;
                        break;

                OPTION_LONG("roothash", "BOOL", "Download root hash file with image"):
                        r = parse_boolean_argument("--roothash=", opts.arg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_import_flags, IMPORT_PULL_ROOTHASH, r);

                        /* If we were asked to turn off the root hash, implicitly also turn off the root hash signature */
                        if (!r)
                                SET_FLAG(arg_import_flags, IMPORT_PULL_ROOTHASH_SIGNATURE, false);
                        break;

                OPTION_LONG("roothash-signature", "BOOL",
                            "Download root hash signature file with image"):
                        r = parse_boolean_argument("--roothash-signature=", opts.arg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_import_flags, IMPORT_PULL_ROOTHASH_SIGNATURE, r);
                        break;

                OPTION_LONG("verity", "BOOL", "Download verity file with image"):
                        r = parse_boolean_argument("--verity=", opts.arg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_import_flags, IMPORT_PULL_VERITY, r);
                        break;

                OPTION_LONG("read-only", NULL, "Create a read-only image"):
                        arg_import_flags |= IMPORT_READ_ONLY;
                        break;

                OPTION_LONG("direct", NULL, "Download directly to specified file"):
                        arg_import_flags |= IMPORT_DIRECT;
                        arg_import_flags &= ~(IMPORT_PULL_SETTINGS|IMPORT_PULL_ROOTHASH|IMPORT_PULL_ROOTHASH_SIGNATURE|IMPORT_PULL_VERITY);
                        break;

                OPTION_LONG("btrfs-subvol", "BOOL",
                            "Controls whether to create a btrfs subvolume instead of a directory"):
                        r = parse_boolean_argument("--btrfs-subvol=", opts.arg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_import_flags, IMPORT_BTRFS_SUBVOL, r);
                        break;

                OPTION_LONG("btrfs-quota", "BOOL",
                            "Controls whether to set up quota for btrfs subvolume"):
                        r = parse_boolean_argument("--btrfs-quota=", opts.arg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_import_flags, IMPORT_BTRFS_QUOTA, r);
                        break;

                OPTION_LONG("convert-qcow2", "BOOL",
                            "Controls whether to convert QCOW2 images to regular disk images"):
                        r = parse_boolean_argument("--convert-qcow2=", opts.arg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_import_flags, IMPORT_CONVERT_QCOW2, r);
                        break;

                OPTION_LONG("sync", "BOOL", "Controls whether to sync() before completing"):
                        r = parse_boolean_argument("--sync=", opts.arg, NULL);
                        if (r < 0)
                                return r;
                        SET_FLAG(arg_import_flags, IMPORT_SYNC, r);
                        break;

                OPTION_LONG("offset", "BYTES", "Offset to seek to in destination"): {
                        uint64_t u;

                        r = safe_atou64(opts.arg, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --offset= argument: %s", opts.arg);
                        if (!FILE_SIZE_VALID(u))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Argument to --offset= switch too large: %s", opts.arg);

                        arg_offset = u;
                        break;
                }

                OPTION_LONG("size-max", "BYTES", "Maximum number of bytes to write to destination"): {
                        uint64_t u;

                        r = parse_size(opts.arg, 1024, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --size-max= argument: %s", opts.arg);
                        if (!FILE_SIZE_VALID(u))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Argument to --size-max= switch too large: %s", opts.arg);

                        arg_size_max = u;
                        break;
                }

                OPTION_LONG("class", "CLASS",
                            "Select image class (machine, sysext, confext, portable)"):
                        arg_class = image_class_from_string(opts.arg);
                        if (arg_class < 0)
                                return log_error_errno(arg_class, "Failed to parse --class= argument: %s", opts.arg);
                        break;

                OPTION_LONG("keep-download", "BOOL",
                            "Keep a pristine copy of the downloaded file around"):
                        r = parse_boolean(opts.arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --keep-download= argument: %s", opts.arg);

                        SET_FLAG(arg_import_flags, IMPORT_PULL_KEEP_DOWNLOAD, r);
                        auto_keep_download = false;
                        break;

                OPTION_COMMON_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                OPTION_COMMON_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;
                }

        /* Make sure offset+size is still in the valid range if both set */
        if (arg_offset != UINT64_MAX && arg_size_max != UINT64_MAX &&
            ((arg_size_max > (UINT64_MAX - arg_offset)) ||
             !FILE_SIZE_VALID(arg_offset + arg_size_max)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File offset und maximum size out of range.");

        if (arg_offset != UINT64_MAX && !FLAGS_SET(arg_import_flags, IMPORT_DIRECT))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File offset only supported in --direct mode.");

        if (iovec_is_set(&arg_checksum) && (arg_import_flags & (IMPORT_PULL_SETTINGS|IMPORT_PULL_ROOTHASH|IMPORT_PULL_ROOTHASH_SIGNATURE|IMPORT_PULL_VERITY)) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Literal checksum verification only supported if no associated files are downloaded.");

        if (!arg_image_root) {
                r = image_root_pick(arg_runtime_scope < 0 ? RUNTIME_SCOPE_SYSTEM : arg_runtime_scope, arg_class, /* runtime= */ false, &arg_image_root);
                if (r < 0)
                        return log_error_errno(r, "Failed to pick image root: %m");
        }

        /* .nspawn settings files only really make sense for machine images, not for sysext/confext/portable */
        if (auto_settings && arg_class != IMAGE_MACHINE)
                arg_import_flags &= ~IMPORT_PULL_SETTINGS;

        /* Keep the original pristine downloaded file as a copy only when dealing with machine images,
         * because unlike sysext/confext/portable they are typically modified during runtime. */
        if (auto_keep_download)
                SET_FLAG(arg_import_flags, IMPORT_PULL_KEEP_DOWNLOAD, arg_class == IMAGE_MACHINE);

        if (arg_runtime_scope == RUNTIME_SCOPE_USER)
                arg_import_flags |= IMPORT_FOREIGN_UID;

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static void parse_env(void) {
        int r;

        /* Let's make these relatively low-level settings also controllable via env vars. User can then set
         * them for systemd-importd.service if they like to tweak behaviour */

        r = getenv_bool("SYSTEMD_IMPORT_BTRFS_SUBVOL");
        if (r >= 0)
                SET_FLAG(arg_import_flags, IMPORT_BTRFS_SUBVOL, r);
        else if (r != -ENXIO)
                log_warning_errno(r, "Failed to parse $SYSTEMD_IMPORT_BTRFS_SUBVOL: %m");

        r = getenv_bool("SYSTEMD_IMPORT_BTRFS_QUOTA");
        if (r >= 0)
                SET_FLAG(arg_import_flags, IMPORT_BTRFS_QUOTA, r);
        else if (r != -ENXIO)
                log_warning_errno(r, "Failed to parse $SYSTEMD_IMPORT_BTRFS_QUOTA: %m");

        r = getenv_bool("SYSTEMD_IMPORT_SYNC");
        if (r >= 0)
                SET_FLAG(arg_import_flags, IMPORT_SYNC, r);
        else if (r != -ENXIO)
                log_warning_errno(r, "Failed to parse $SYSTEMD_IMPORT_SYNC: %m");
}

static int run(int argc, char *argv[]) {
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        parse_env();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        (void) ignore_signals(SIGPIPE);

        return dispatch_verb_with_args(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
