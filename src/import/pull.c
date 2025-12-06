/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>
#include <stdio.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "discover-image.h"
#include "env-util.h"
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

/* Those are used when parsing arguments. */
static bool arg_auto_settings = true;
static bool arg_auto_keep_download = true;

STATIC_DESTRUCTOR_REGISTER(arg_checksum, iovec_done);
STATIC_DESTRUCTOR_REGISTER(arg_image_root, freep);

#include "pull.args.inc"

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

static int help(void) {
        printf("%1$s [OPTIONS...] {COMMAND} ...\n"
               "\n%4$sDownload disk images.%5$s\n"
               "\n%2$sCommands:%3$s\n"
               "  tar URL [NAME]              Download a TAR image\n"
               "  raw URL [NAME]              Download a RAW image\n"
               "\n%2$sOptions:%3$s\n"
               OPTION_HELP_GENERATED,
               program_invocation_short_name,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        r = parse_argv_generated(argc, argv);
        if (r <= 0)
                return r;

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
        if (arg_auto_settings && arg_class != IMAGE_MACHINE)
                arg_import_flags &= ~IMPORT_PULL_SETTINGS;

        /* Keep the original pristine downloaded file as a copy only when dealing with machine images,
         * because unlike sysext/confext/portable they are typically modified during runtime. */
        if (arg_auto_keep_download)
                SET_FLAG(arg_import_flags, IMPORT_PULL_KEEP_DOWNLOAD, arg_class == IMAGE_MACHINE);

        if (arg_runtime_scope == RUNTIME_SCOPE_USER)
                arg_import_flags |= IMPORT_FOREIGN_UID;

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

static int pull_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help", VERB_ANY, VERB_ANY, 0, verb_help },
                { "tar",  2,        3,        0, pull_tar  },
                { "raw",  2,        3,        0, pull_raw  },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        parse_env();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        (void) ignore_signals(SIGPIPE);

        return pull_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
