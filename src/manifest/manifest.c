/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-json.h"

#include "ansi-color.h"
#include "build.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "main-func.h"
#include "manifest-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "path-util.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "uapi16-manifest.h"
#include "verbs.h"

static ManifestFormat arg_format = _MANIFEST_FORMAT_INVALID;
static ManifestField arg_fields = _MANIFEST_FIELD_DEFAULT;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_graceful = false;

COMMAND(
        "systemd-manifest\0",
        "Generate and verify file manifests of directory trees.",
        .man_pages = "systemd-manifest(1)\0",
        .pager_flags = &arg_pager_flags,
);

VERB_COMMON_HELP_AUTO_HIDDEN();

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };
        int r;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("format", "FORMAT", "Manifest format (list, sha256sums, mtree, uapi16)"):
                        arg_format = manifest_format_from_string(opts.arg);
                        if (arg_format < 0)
                                return log_error_errno(arg_format, "Unknown manifest format: %s", opts.arg);
                        break;

                OPTION_LONG("field", "FIELDS", "Fields to include (mode, uid, gid, size, hash, symlink, device, hardlink, mtime, all, default, none, or +/- prefixed to adjust)"):
                        r = manifest_fields_from_string(opts.arg, &arg_fields);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse field list: %s", opts.arg);
                        break;

                OPTION_LONG("graceful", NULL, "Don't fail if inodes had to be skipped or metadata omitted"):
                        arg_graceful = true;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static int open_directory(const char *path) {
        int fd;

        /* Opens the specified directory, or the current directory if none is specified */

        fd = open(path ?: ".", O_DIRECTORY|O_CLOEXEC|O_RDONLY);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open directory '%s': %m", path ?: ".");

        return fd;
}

static void context_from_args(ManifestContext *c) {
        assert(c);

        *c = MANIFEST_CONTEXT_NULL;
        c->format = arg_format;
        c->fields = arg_fields;
        c->json_format_flags = arg_json_format_flags;
        c->color = colors_enabled();
}

VERB(verb_make, "make", "[DIRECTORY [MANIFEST]]\0", 1, 3, 0, "Generate a manifest of a directory tree");
static int verb_make(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        _cleanup_close_ int dfd = open_directory(argc > 1 ? argv[1] : NULL);
        if (dfd < 0)
                return dfd;

        const char *manifest = argc > 2 && !streq(argv[2], "-") ? argv[2] : NULL;

        if (arg_format < 0)
                arg_format = MANIFEST_FORMAT_UAPI16;

        /* UAPI.16 is always JSON, hence default to a good JSON mode. We turn on color, but not pretty
         * alignment, so that each file is in one row */
        if (arg_format == MANIFEST_FORMAT_UAPI16 &&
            FLAGS_SET(arg_json_format_flags, SD_JSON_FORMAT_OFF))
                arg_json_format_flags = SD_JSON_FORMAT_COLOR_AUTO;

        _cleanup_(manifest_context_done) ManifestContext c;
        context_from_args(&c);

        _cleanup_(unlink_and_freep) char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        if (manifest) {
                r = fopen_tmpfile_linkable(manifest, O_WRONLY|O_CLOEXEC, &t, &f);
                if (r < 0)
                        return log_error_errno(r, "Failed to create '%s': %m", manifest);

                c.output = f;
                c.color = false;
        } else
                pager_open(arg_pager_flags);

        r = manifest_make(&c, dfd);
        if (r < 0)
                return r;

        /* Even in graceful mode, insist that the top-level inode is covered, after all a manifest that
         * doesn't even cover that is useless. */
        if (!c.top_level_covered)
                return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN), "Top-level inode not covered by manifest, refusing.");

        int level = arg_graceful ? LOG_WARNING : LOG_ERR;
        if (c.n_skipped > 0)
                log_full(level, "%" PRIu64 " entries skipped, as they could not be read or were not representable in the manifest.", c.n_skipped);
        if (c.n_metadata_omitted > 0)
                log_full(level, "%" PRIu64 " metadata fields omitted, as they could not be read or were not representable in the manifest.", c.n_metadata_omitted);
        if (!arg_graceful && (c.n_skipped > 0 || c.n_metadata_omitted > 0))
                return -EUCLEAN;

        if (manifest) {
                r = flink_tmpfile(f, t, manifest, LINK_TMPFILE_REPLACE);
                if (r < 0)
                        return log_error_errno(r, "Failed to move '%s' into place: %m", manifest);

                t = mfree(t); /* disarm auto delete */
        }

        return 0;
}

static int guess_format(const char *path) {
        int r;

        if (!path)
                return _MANIFEST_FORMAT_INVALID;

        _cleanup_free_ char *fn = NULL;
        r = path_extract_filename(path, &fn);
        if (r < 0)
                return r;

        if (streq(fn, "SHA256SUMS") || startswith(fn, "SHA256SUMS."))
                return MANIFEST_FORMAT_SHA256SUMS;

        if (uapi16_manifest_filename_is_reserved(fn) || uapi16_manifest_filename_is_suffixed(fn))
                return MANIFEST_FORMAT_UAPI16;

        if (endswith(fn, ".mtree"))
                return MANIFEST_FORMAT_MTREE;

        return _MANIFEST_FORMAT_INVALID;
}

VERB(verb_verify, "verify", "[DIRECTORY [MANIFEST]]\0", 1, 3, 0, "Verify a directory tree against a manifest");
static int verb_verify(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        _cleanup_close_ int dfd = open_directory(argc > 1 ? argv[1] : NULL);
        if (dfd < 0)
                return dfd;

        const char *manifest = argc > 2 && !streq(argv[2], "-") ? argv[2] : NULL;

        /* If the format is not specified explicitly, guess it from the file name, and otherwise default to
         * UAPI.16, like on "make". */
        if (arg_format < 0) {
                arg_format = guess_format(manifest);
                if (arg_format < 0)
                        arg_format = MANIFEST_FORMAT_UAPI16;
        }

        _cleanup_(manifest_context_done) ManifestContext c;
        context_from_args(&c);

        _cleanup_fclose_ FILE *f = NULL;
        if (manifest) {
                f = fopen(manifest, "re");
                if (!f)
                        return log_error_errno(errno, "Failed to open manifest file '%s': %m", manifest);
        } else {
                r = fdopen_independent(STDIN_FILENO, "re", &f);
                if (r < 0)
                        return log_error_errno(r, "Failed to open standard input: %m");
        }

        return manifest_verify(&c, dfd, f);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
