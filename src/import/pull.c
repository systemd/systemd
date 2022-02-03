/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>

#include "sd-event.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "discover-image.h"
#include "env-util.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "import-common.h"
#include "import-util.h"
#include "io-util.h"
#include "main-func.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pull-raw.h"
#include "pull-tar.h"
#include "signal-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "verbs.h"
#include "web-util.h"

static const char *arg_image_root = "/var/lib/machines";
static ImportVerify arg_verify = IMPORT_VERIFY_SIGNATURE;
static PullFlags arg_pull_flags = PULL_SETTINGS | PULL_ROOTHASH | PULL_ROOTHASH_SIGNATURE | PULL_VERITY | PULL_BTRFS_SUBVOL | PULL_BTRFS_QUOTA | PULL_CONVERT_QCOW2 | PULL_SYNC;
static uint64_t arg_offset = UINT64_MAX, arg_size_max = UINT64_MAX;
static char *arg_checksum = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_checksum, freep);

static int normalize_local(const char *local, const char *url, char **ret) {
        _cleanup_free_ char *ll = NULL;
        int r;

        if (arg_pull_flags & PULL_DIRECT) {

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

                if (!hostname_is_valid(local, 0))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Local image name '%s' is not valid.",
                                               local);

                if (!FLAGS_SET(arg_pull_flags, PULL_FORCE)) {
                        r = image_find(IMAGE_MACHINE, local, NULL, NULL);
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

        *ret = TAKE_PTR(ll);
        return 0;
}

static void on_tar_finished(TarPull *pull, int error, void *userdata) {
        sd_event *event = userdata;
        assert(pull);

        if (error == 0)
                log_info("Operation completed successfully.");

        sd_event_exit(event, abs(error));
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

        if (!local && FLAGS_SET(arg_pull_flags, PULL_DIRECT))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Pulling tar images to STDOUT is not supported.");

        r = normalize_local(local, url, &normalized);
        if (r < 0)
                return r;

        r = import_allocate_event_with_signals(&event);
        if (r < 0)
                return r;

        if (!FLAGS_SET(arg_pull_flags, PULL_SYNC))
                log_info("File system synchronization on completion is off.");

        r = tar_pull_new(&pull, event, arg_image_root, on_tar_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate puller: %m");

        r = tar_pull_start(
                        pull,
                        url,
                        normalized,
                        arg_pull_flags & PULL_FLAGS_MASK_TAR,
                        arg_verify,
                        arg_checksum);
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

        sd_event_exit(event, abs(error));
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

        if (!FLAGS_SET(arg_pull_flags, PULL_SYNC))
                log_info("File system synchronization on completion is off.");
         r = raw_pull_new(&pull, event, arg_image_root, on_raw_finished, event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate puller: %m");

        r = raw_pull_start(
                        pull,
                        url,
                        normalized,
                        arg_offset,
                        arg_size_max,
                        arg_pull_flags & PULL_FLAGS_MASK_RAW,
                        arg_verify,
                        arg_checksum);
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
               "\n%4$sDownload container or virtual machine images.%5$s\n"
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
               "     --image-root=PATH        Image root directory\n\n"
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
               "     --size-max=BYTES         Maximum number of bytes to write to destination\n",
               program_invocation_short_name,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
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
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_FORCE:
                        arg_pull_flags |= PULL_FORCE;
                        break;

                case ARG_IMAGE_ROOT:
                        arg_image_root = optarg;
                        break;

                case ARG_VERIFY: {
                        ImportVerify v;

                        v = import_verify_from_string(optarg);
                        if (v < 0) {
                                _cleanup_free_ void *h = NULL;
                                char *hh;
                                size_t n;

                                /* If this is not a valid verification mode, maybe it's a literally specified
                                 * SHA256 hash? We can handle that too... */

                                r = unhexmem(optarg, (size_t) -1, &h, &n);
                                if (r < 0 || n == 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Invalid verification setting: %s", optarg);
                                if (n != 32)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "64 hex character SHA256 hash required when specifying explicit checksum, %zu specified", n * 2);

                                hh = hexmem(h, n); /* bring into canonical (lowercase) form */
                                if (!hh)
                                        return log_oom();

                                free_and_replace(arg_checksum, hh);
                                arg_pull_flags &= ~(PULL_SETTINGS|PULL_ROOTHASH|PULL_ROOTHASH_SIGNATURE|PULL_VERITY);
                                arg_verify = _IMPORT_VERIFY_INVALID;
                        } else
                                arg_verify = v;

                        break;
                }

                case ARG_SETTINGS:
                        r = parse_boolean_argument("--settings=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_pull_flags, PULL_SETTINGS, r);
                        break;

                case ARG_ROOTHASH:
                        r = parse_boolean_argument("--roothash=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_pull_flags, PULL_ROOTHASH, r);

                        /* If we were asked to turn off the root hash, implicitly also turn off the root hash signature */
                        if (!r)
                                SET_FLAG(arg_pull_flags, PULL_ROOTHASH_SIGNATURE, false);
                        break;

                case ARG_ROOTHASH_SIGNATURE:
                        r = parse_boolean_argument("--roothash-signature=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_pull_flags, PULL_ROOTHASH_SIGNATURE, r);
                        break;

                case ARG_VERITY:
                        r = parse_boolean_argument("--verity=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_pull_flags, PULL_VERITY, r);
                        break;

                case ARG_READ_ONLY:
                        arg_pull_flags |= PULL_READ_ONLY;
                        break;

                case ARG_DIRECT:
                        arg_pull_flags |= PULL_DIRECT;
                        arg_pull_flags &= ~(PULL_SETTINGS|PULL_ROOTHASH|PULL_ROOTHASH_SIGNATURE|PULL_VERITY);
                        break;

                case ARG_BTRFS_SUBVOL:
                        r = parse_boolean_argument("--btrfs-subvol=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_pull_flags, PULL_BTRFS_SUBVOL, r);
                        break;

                case ARG_BTRFS_QUOTA:
                        r = parse_boolean_argument("--btrfs-quota=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_pull_flags, PULL_BTRFS_QUOTA, r);
                        break;

                case ARG_CONVERT_QCOW2:
                        r = parse_boolean_argument("--convert-qcow2=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_pull_flags, PULL_CONVERT_QCOW2, r);
                        break;

                case ARG_SYNC:
                        r = parse_boolean_argument("--sync=", optarg, NULL);
                        if (r < 0)
                                return r;

                        SET_FLAG(arg_pull_flags, PULL_SYNC, r);
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

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        /* Make sure offset+size is still in the valid range if both set */
        if (arg_offset != UINT64_MAX && arg_size_max != UINT64_MAX &&
            ((arg_size_max > (UINT64_MAX - arg_offset)) ||
             !FILE_SIZE_VALID(arg_offset + arg_size_max)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File offset und maximum size out of range.");

        if (arg_offset != UINT64_MAX && !FLAGS_SET(arg_pull_flags, PULL_DIRECT))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File offset only supported in --direct mode.");

        if (arg_checksum && (arg_pull_flags & (PULL_SETTINGS|PULL_ROOTHASH|PULL_ROOTHASH_SIGNATURE|PULL_VERITY)) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Literal checksum verification only supported if no associated files are downloaded.");

        return 1;
}

static void parse_env(void) {
        int r;

        /* Let's make these relatively low-level settings also controllable via env vars. User can then set
         * them for systemd-importd.service if they like to tweak behaviour */

        r = getenv_bool("SYSTEMD_IMPORT_BTRFS_SUBVOL");
        if (r >= 0)
                SET_FLAG(arg_pull_flags, PULL_BTRFS_SUBVOL, r);
        else if (r != -ENXIO)
                log_warning_errno(r, "Failed to parse $SYSTEMD_IMPORT_BTRFS_SUBVOL: %m");

        r = getenv_bool("SYSTEMD_IMPORT_BTRFS_QUOTA");
        if (r >= 0)
                SET_FLAG(arg_pull_flags, PULL_BTRFS_QUOTA, r);
        else if (r != -ENXIO)
                log_warning_errno(r, "Failed to parse $SYSTEMD_IMPORT_BTRFS_QUOTA: %m");

        r = getenv_bool("SYSTEMD_IMPORT_SYNC");
        if (r >= 0)
                SET_FLAG(arg_pull_flags, PULL_SYNC, r);
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

static int run(int argc, char *argv[]) {
        int r;

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        parse_env();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        (void) ignore_signals(SIGPIPE);

        return pull_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
