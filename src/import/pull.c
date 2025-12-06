/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>
#include <stdio.h>

#include "sd-event.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "discover-image.h"
#include "env-util.h"
#include "fd-util.h"
#include "json-util.h"
#include "hexdecoct.h"
#include "import-common.h"
#include "import-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pull-raw.h"
#include "pull-tar.h"
#include "runtime-scope.h"
#include "string-table.h"
#include "signal-util.h"
#include "string-util.h"
#include "varlink-io.systemd.PullWorker.h"
#include "varlink-util.h"
#include "verbs.h"
#include "web-util.h"

static char *arg_image_root = NULL;
static ImportVerify arg_verify = IMPORT_VERIFY_SIGNATURE;
static ImportFlags arg_import_flags = IMPORT_PULL_SETTINGS | IMPORT_PULL_ROOTHASH | IMPORT_PULL_ROOTHASH_SIGNATURE | IMPORT_PULL_VERITY | IMPORT_BTRFS_SUBVOL | IMPORT_BTRFS_QUOTA | IMPORT_CONVERT_QCOW2 | IMPORT_SYNC;
static uint64_t arg_offset = UINT64_MAX, arg_size_max = UINT64_MAX;
static struct iovec arg_checksum = {};
static ImageClass arg_class = IMAGE_MACHINE;
static RuntimeScope arg_runtime_scope = _RUNTIME_SCOPE_INVALID;
static bool arg_varlink = false;

STATIC_DESTRUCTOR_REGISTER(arg_checksum, iovec_done);
STATIC_DESTRUCTOR_REGISTER(arg_image_root, freep);

static int normalize_local(const char *local, const char *url, char **ret) {
        _cleanup_free_ char *ll = NULL;
        int r;

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

static int pull_tar(int argc, char *argv[], void *userdata) {
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
                        -EBADF,
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

static int pull_raw(int argc, char *argv[], void *userdata) {
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
                        -EBADF,
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

static int pull_direct(const char *url, int local_fd, ImportType type) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(tar_pull_unrefp) TarPull *tar_pull = NULL;
        _cleanup_(raw_pull_unrefp) RawPull *raw_pull = NULL;
        int r;

        assert(FLAGS_SET(arg_import_flags, IMPORT_DIRECT));

        if (!http_url_is_valid(url) && !file_url_is_valid(url))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "URL '%s' is not valid.", url);

        //if (!path_is_absolute(local) || !path_is_valid(local))
        //        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Local path name '%s' is not valid.", local);

        if (!FLAGS_SET(arg_import_flags, IMPORT_SYNC))
                log_info("File system synchronization on completion is off.");

        r = import_allocate_event_with_signals(&event);
        if (r < 0)
                return r;

        if (type == IMPORT_TAR) {
                r = tar_pull_new(&tar_pull, event, arg_image_root, on_tar_finished, event);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate puller: %m");

                r = tar_pull_start(
                                tar_pull,
                                url,
                                NULL,
                                local_fd,
                                arg_import_flags & IMPORT_PULL_FLAGS_MASK_TAR,
                                arg_verify,
                                &arg_checksum);
        } else if (type == IMPORT_RAW) {
                r = raw_pull_new(&raw_pull, event, arg_image_root, on_raw_finished, event);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate puller: %m");

                r = raw_pull_start(
                                raw_pull,
                                url,
                                NULL,
                                local_fd,
                                arg_offset,
                                arg_size_max,
                                arg_import_flags & IMPORT_PULL_FLAGS_MASK_RAW,
                                arg_verify,
                                &arg_checksum);
        } else {
                assert_not_reached ();
        }
        if (r < 0)
                return log_error_errno(r, "Failed to pull image: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        log_info("Exiting.");
        return -r;
}

static int help(int argc, char *argv[], void *userdata) {

        printf("%1$s [OPTIONS...] {COMMAND} ...\n"
               "\n%4$sDownload disk images.%5$s\n"
               "\n%2$sCommands:%3$s\n"
               "  tar URL [NAME]              Download a TAR image\n"
               "  raw URL [NAME]              Download a RAW image\n"
               "\n%2$sOptions:%3$s\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "     --force                  Force creation of image\n"
               "     --verify=MODE            Verify downloaded image, one of: 'no',\n"
               "                              'checksum', 'signature' or literal SHA256 hash\n"
               "     --settings=BOOL          Download settings file with image\n"
               "     --roothash=BOOL          Download root hash file with image\n"
               "     --roothash-signature=BOOL\n"
               "                              Download root hash signature file with image\n"
               "     --verity=BOOL            Download verity file with image\n"
               "     --image-root=PATH        Image root directory\n"
               "     --read-only              Create a read-only image\n"
               "     --direct                 Download directly to specified file\n"
               "     --btrfs-subvol=BOOL      Controls whether to create a btrfs subvolume\n"
               "                              instead of a directory\n"
               "     --btrfs-quota=BOOL       Controls whether to set up quota for btrfs\n"
               "                              subvolume\n"
               "     --convert-qcow2=BOOL     Controls whether to convert QCOW2 images to\n"
               "                              regular disk images\n"
               "     --sync=BOOL              Controls whether to sync() before completing\n"
               "     --offset=BYTES           Offset to seek to in destination\n"
               "     --size-max=BYTES         Maximum number of bytes to write to destination\n"
               "     --class=CLASS            Select image class (machine, sysext, confext,\n"
               "                              portable)\n"
               "     --keep-download=BOOL     Keep a pristine copy of the downloaded file\n"
               "                              around\n"
               "     --system                 Operate in per-system mode\n"
               "     --user                   Operate in per-user mode\n",
               program_invocation_short_name,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int set_checksum(const char *checksum) {
        int r;
        _cleanup_free_ void *h = NULL;
        size_t n;

        r = unhexmem(checksum, &h, &n);
        if (r < 0 || n == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid verification setting: %s", checksum);
        if (n != 32)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "64 hex character SHA256 hash required when specifying explicit checksum, %zu specified", n * 2);

        iovec_done(&arg_checksum);
        arg_checksum.iov_base = TAKE_PTR(h);
        arg_checksum.iov_len = n;

        arg_import_flags &= ~(IMPORT_PULL_SETTINGS|IMPORT_PULL_ROOTHASH|IMPORT_PULL_ROOTHASH_SIGNATURE|IMPORT_PULL_VERITY);
        arg_verify = _IMPORT_VERIFY_INVALID;

        return 1;
}

static int check_argv(bool auto_settings, bool auto_keep_download) {
        int r;
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

        return 1;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_FORCE,
                ARG_IMAGE_ROOT,
                ARG_VERIFY,
                ARG_SETTINGS,
                ARG_ROOTHASH,
                ARG_ROOTHASH_SIGNATURE,
                ARG_VERITY,
                ARG_READ_ONLY,
                ARG_DIRECT,
                ARG_BTRFS_SUBVOL,
                ARG_BTRFS_QUOTA,
                ARG_CONVERT_QCOW2,
                ARG_SYNC,
                ARG_OFFSET,
                ARG_SIZE_MAX,
                ARG_CLASS,
                ARG_KEEP_DOWNLOAD,
                ARG_SYSTEM,
                ARG_USER,
        };

        static const struct option options[] = {
                { "help",               no_argument,       NULL, 'h'                    },
                { "version",            no_argument,       NULL, ARG_VERSION            },
                { "force",              no_argument,       NULL, ARG_FORCE              },
                { "image-root",         required_argument, NULL, ARG_IMAGE_ROOT         },
                { "verify",             required_argument, NULL, ARG_VERIFY             },
                { "settings",           required_argument, NULL, ARG_SETTINGS           },
                { "roothash",           required_argument, NULL, ARG_ROOTHASH           },
                { "roothash-signature", required_argument, NULL, ARG_ROOTHASH_SIGNATURE },
                { "verity",             required_argument, NULL, ARG_VERITY             },
                { "read-only",          no_argument,       NULL, ARG_READ_ONLY          },
                { "direct",             no_argument,       NULL, ARG_DIRECT             },
                { "btrfs-subvol",       required_argument, NULL, ARG_BTRFS_SUBVOL       },
                { "btrfs-quota",        required_argument, NULL, ARG_BTRFS_QUOTA        },
                { "convert-qcow2",      required_argument, NULL, ARG_CONVERT_QCOW2      },
                { "sync",               required_argument, NULL, ARG_SYNC               },
                { "offset",             required_argument, NULL, ARG_OFFSET             },
                { "size-max",           required_argument, NULL, ARG_SIZE_MAX           },
                { "class",              required_argument, NULL, ARG_CLASS              },
                { "keep-download",      required_argument, NULL, ARG_KEEP_DOWNLOAD      },
                { "system",             no_argument,       NULL, ARG_SYSTEM             },
                { "user",               no_argument,       NULL, ARG_USER               },
                {}
        };

        int c, r;
        bool auto_settings = true, auto_keep_download = true;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_FORCE:
                        SET_FLAG(arg_import_flags, IMPORT_FORCE, true);
                        break;

                case ARG_IMAGE_ROOT:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_image_root);
                        if (r < 0)
                                return r;

                        break;

                case ARG_VERIFY: {
                        ImportVerify v;

                        v = import_verify_from_string(optarg);
                        if (v < 0) {

                                /* If this is not a valid verification mode, maybe it's a literally specified
                                 * SHA256 hash? We can handle that too... */

                                r = set_checksum (optarg);
                                if (r < 0)
                                        return r;
                        } else
                                arg_verify = v;

                        break;
                }

                case ARG_SETTINGS:
                        r = parse_boolean_argument("--settings=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_import_flags, IMPORT_PULL_SETTINGS, r);
                        auto_settings = false;
                        break;

                case ARG_ROOTHASH:
                        r = parse_boolean_argument("--roothash=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_import_flags, IMPORT_PULL_ROOTHASH, r);

                        /* If we were asked to turn off the root hash, implicitly also turn off the root hash signature */
                        if (!r)
                                SET_FLAG(arg_import_flags, IMPORT_PULL_ROOTHASH_SIGNATURE, false);
                        break;

                case ARG_ROOTHASH_SIGNATURE:
                        r = parse_boolean_argument("--roothash-signature=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_import_flags, IMPORT_PULL_ROOTHASH_SIGNATURE, r);
                        break;

                case ARG_VERITY:
                        r = parse_boolean_argument("--verity=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_import_flags, IMPORT_PULL_VERITY, r);
                        break;

                case ARG_READ_ONLY:
                        SET_FLAG(arg_import_flags, IMPORT_READ_ONLY, true);
                        break;

                case ARG_DIRECT:
                        SET_FLAG(arg_import_flags, IMPORT_DIRECT, true);
                        SET_FLAG(arg_import_flags, IMPORT_PULL_SETTINGS|IMPORT_PULL_ROOTHASH|IMPORT_PULL_ROOTHASH_SIGNATURE|IMPORT_PULL_VERITY, false);
                        break;

                case ARG_BTRFS_SUBVOL:
                        r = parse_boolean_argument("--btrfs-subvol=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_import_flags, IMPORT_BTRFS_SUBVOL, r);
                        break;

                case ARG_BTRFS_QUOTA:
                        r = parse_boolean_argument("--btrfs-quota=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_import_flags, IMPORT_BTRFS_QUOTA, r);
                        break;

                case ARG_CONVERT_QCOW2:
                        r = parse_boolean_argument("--convert-qcow2=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_import_flags, IMPORT_CONVERT_QCOW2, r);
                        break;

                case ARG_SYNC:
                        r = parse_boolean_argument("--sync=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_import_flags, IMPORT_SYNC, r);
                        break;

                case ARG_OFFSET: {
                        uint64_t u;

                        r = safe_atou64(optarg, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --offset= argument: %s", optarg);
                        if (!FILE_SIZE_VALID(u))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Argument to --offset= switch too large: %s", optarg);

                        arg_offset = u;
                        break;
                }

                case ARG_SIZE_MAX: {
                        uint64_t u;

                        r = parse_size(optarg, 1024, &u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --size-max= argument: %s", optarg);
                        if (!FILE_SIZE_VALID(u))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Argument to --size-max= switch too large: %s", optarg);

                        arg_size_max = u;
                        break;
                }

                case ARG_CLASS:
                        arg_class = image_class_from_string(optarg);
                        if (arg_class < 0)
                                return log_error_errno(arg_class, "Failed to parse --class= argument: %s", optarg);

                        break;

                case ARG_KEEP_DOWNLOAD:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --keep-download= argument: %s", optarg);

                        SET_FLAG(arg_import_flags, IMPORT_PULL_KEEP_DOWNLOAD, r);
                        auto_keep_download = false;
                        break;

                case ARG_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                case ARG_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        return check_argv (auto_settings, auto_keep_download);
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

static int pull_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help", VERB_ANY, VERB_ANY, 0, help     },
                { "tar",  2,        3,        0, pull_tar },
                { "raw",  2,        3,        0, pull_raw },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_import_type, ImportType, import_type_from_string);
static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_import_verify, ImportVerify, import_verify_from_string);

typedef struct MethodPullParameters {
        ImportType mode;
        bool fsync;
        ImportVerify verify;
        const char *checksum;
        const char *source;
        unsigned destination_fd_index;
        uint64_t offset;
        uint64_t size_max;
        bool subvolume;
} MethodPullParameters;

static int vl_method_pull(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        // parse only the parameters used by systemd-pull

        static const sd_json_dispatch_field dispatch_table[] = {
                { "version",        SD_JSON_VARIANT_STRING,  NULL,                          0,                                           0 },
                { "mode",           SD_JSON_VARIANT_STRING,  json_dispatch_import_type,     offsetof(MethodPullParameters, mode),        SD_JSON_MANDATORY },
                { "fsync",          SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      offsetof(MethodPullParameters, fsync),       0 },
                { "verify",         SD_JSON_VARIANT_STRING,  json_dispatch_import_verify,   offsetof(MethodPullParameters, verify),      SD_JSON_MANDATORY },
                { "checksum",       SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, offsetof(MethodPullParameters, checksum),    0 },
                { "source",         SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, offsetof(MethodPullParameters, source),      SD_JSON_MANDATORY },
                { "destinationFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint, offsetof(MethodPullParameters, destination_fd_index), SD_JSON_MANDATORY },
                { "instances",      SD_JSON_VARIANT_ARRAY,   NULL,                          0,                                           0 },
                { "offset",         SD_JSON_VARIANT_NUMBER,  sd_json_dispatch_uint64,       offsetof(MethodPullParameters, offset),      0 },
                { "maxSize",        SD_JSON_VARIANT_NUMBER,  sd_json_dispatch_uint64,       offsetof(MethodPullParameters, size_max),    0 },
                { "subvolume",      SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      offsetof(MethodPullParameters, subvolume),   0 },
                {}
        };

        MethodPullParameters p = {
                .mode = _IMPORT_TYPE_INVALID,
                .fsync = true,
                .verify = _IMPORT_VERIFY_INVALID,
                .destination_fd_index = UINT_MAX,
                .offset = UINT64_MAX,
                .size_max = UINT64_MAX,
                .subvolume = false,
        };
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        int destination_fd = sd_varlink_take_fd(link, p.destination_fd_index);
        if (destination_fd < 0)
                return sd_varlink_error(link, "io.systemd.PullWorker.InvalidParameters", NULL);

        SET_FLAG(arg_import_flags, IMPORT_SYNC, p.fsync);

        if (p.offset != UINT64_MAX && !FILE_SIZE_VALID(p.offset))
                return sd_varlink_error(link, "io.systemd.PullWorker.InvalidParameters", NULL);
        arg_offset = p.offset;

        if (p.size_max != UINT64_MAX && (!FILE_SIZE_VALID(p.size_max) || (p.size_max % 1024) != 0))
                return sd_varlink_error(link, "io.systemd.PullWorker.InvalidParameters", NULL);
        arg_size_max = p.size_max;

        SET_FLAG(arg_import_flags, IMPORT_DIRECT, true);
        SET_FLAG(arg_import_flags, IMPORT_PULL_SETTINGS|IMPORT_PULL_ROOTHASH|IMPORT_PULL_ROOTHASH_SIGNATURE|IMPORT_PULL_VERITY, false);

        SET_FLAG(arg_import_flags, IMPORT_BTRFS_SUBVOL, p.subvolume);

        arg_verify = p.verify;
        if (p.verify == IMPORT_VERIFY_CHECKSUM) {
                r = set_checksum(p.checksum);
                if (r < 0)
                        return sd_varlink_error(link, "io.systemd.PullWorker.InvalidParameters", NULL);
        }

        r = check_argv (true, true);
        if (r < 0)
                return sd_varlink_error(link, "io.systemd.PullWorker.InvalidParameters", NULL);

        r = pull_direct(p.source, TAKE_FD(destination_fd), p.mode);
        if (r < 0)
                return sd_varlink_error(link, "io.systemd.PullWorker.PullError", NULL);

        return sd_varlink_reply(link, NULL);
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        int r;

        r = varlink_server_new(&varlink_server, SD_VARLINK_SERVER_ROOT_ONLY|SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_PullWorker);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method(varlink_server, "io.systemd.PullWorker.Pull", vl_method_pull);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        parse_env();

        (void) ignore_signals(SIGPIPE);

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0)
                arg_varlink = true;

        if (arg_varlink)
                return vl_server(); /* Invocation as Varlink service */

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return pull_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
