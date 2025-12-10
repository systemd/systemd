/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <sys/stat.h>
#include <unistd.h>             /* access */

#include "alloc-util.h"
#include "build.h"
#include "clonesetup-ioctl.h"
#include "extract-word.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "parse-util.h"
#include "path-util.h"          /* path_join */
#include "string-util.h"
#include "strv.h"               /* strv_skip */
#include "verbs.h"

/* region_size: size of each dm-clone region in 512-byte sectors.
 * Must be a power of 2 between 8 (4 KiB) and 2097152 (1 GiB) per dm-clone kernel docs. */
#define CLONE_REGION_SIZE_DEFAULT       (UINT64_C(1) << 3)      /* 8 sectors = 4 KiB */
#define CLONE_REGION_SIZE_MIN           (UINT64_C(1) << 3)      /* 8 sectors = 4 KiB */
#define CLONE_REGION_SIZE_MAX           (UINT64_C(1) << 21)     /* 2097152 sectors = 1 GiB */

static int parse_clone_options(const char *options, uint64_t *ret_region_size) {
        uint64_t region_size = CLONE_REGION_SIZE_DEFAULT;

        assert(ret_region_size);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                const char *val;
                int r;

                /* extract_first_word: *
                 * Returns > 0 — successfully extracted a word *
                 * Returns 0 — no more words (end of string) *
                 * Returns < 0 — actual error (e.g. memory allocation failure) */
                r = extract_first_word(&options, &word, ",", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse clone options: %m");
                if (r == 0)
                        break;

                /* region_size = N; size of each clone region in 512-byte sectors ( default 8 = 4KB )
                 * Must be a power of 2 between 8 and 2097152 per dm-clone kernel docs. */
                /* treat - as empty — common placeholders for "no options" */
                if (streq(word, "-"))
                        continue;

                if ((val = startswith(word, "region_size="))) {
                        uint64_t r_size;
                        r = safe_atou64(val, &r_size);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse region_size= value '%s', using default.", val);
                        else if (!ISPOWEROF2(r_size) || r_size < CLONE_REGION_SIZE_MIN || r_size > CLONE_REGION_SIZE_MAX)
                                log_warning("region_size=%s must be a power of two between 8 and 2097152, using default.", val);
                        else
                                region_size = r_size;
                } else {
                        /* currently only region_size is supported */
                        log_warning("Unknown clone option '%s', ignoring.", word);
                }
        }
        *ret_region_size = region_size;
        return 0;
}

/* dm-clone device creation workflow:
 * 1. Create the dm-clone device
 * 2. Enable background hydration */
static int clone_device(
                const char *clone_name,
                const char *source_dev,
                const char *dest_dev,
                const char *metadata_dev,
                const char *options) {

        _cleanup_free_ char *clone_dev_path = NULL;
        int r;

        assert(clone_name);
        assert(source_dev);
        assert(dest_dev);
        assert(metadata_dev);

        /* create clone device path to check if clone device already exists */
        clone_dev_path = path_join("/dev/mapper", clone_name);
        if (!clone_dev_path)
                return log_oom();

        /* Check before calling the DM ioctl to give a cleaner error message;
         * DM_DEV_CREATE would return EEXIST too, but with a less obvious message. */
        if (access(clone_dev_path, F_OK) >= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Device '%s' already exists.", clone_dev_path);

        uint64_t region_size;
        r = parse_clone_options(options, &region_size);
        if (r < 0)
                return r;

        r = dm_clone_create_device(clone_name, source_dev, dest_dev, metadata_dev, region_size);
        if (r < 0)
                return r;

        r = dm_clone_send_message(clone_name, "enable_hydration");
        if (r < 0) {
                (void) dm_clone_remove_device_deferred(clone_name);
                return r;
        }
        return 0;
}

/* Argument validation — what each check covers:
 *   /, .., leading ., empty name     → filename_is_valid() on name
 *   control chars, \, ', whitespace  → string_is_safe() on device paths
 *   .. in device paths               → path_is_normalized()
 *   non-/dev/ device paths           → path_is_absolute() + path_startswith(path, "/dev/") */
static int validate_dev_path(const char *what, const char *path) {
        if (!string_is_safe(path, 0) || !path_is_valid(path) || !path_is_normalized(path) ||
            !path_is_absolute(path) || !path_startswith(path, "/dev/"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid %s device path '%s'.", what, path);
        return 0;
}

static int validate_fields(const char *name, const char *src, const char *dst,
                const char *meta, const char *options) {
        if (!filename_is_valid(name))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid clone name '%s'.", name);

        int r;
        r = validate_dev_path("source", src);
        if (r < 0)
                return r;
        r = validate_dev_path("destination", dst);
        if (r < 0)
                return r;
        r = validate_dev_path("metadata", meta);
        if (r < 0)
                return r;
        if (!string_is_safe(options, 0))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid options '%s'.", options);
        return 0;
}

VERB(verb_add, "add", "NAME SOURCE DEST METADATA [OPTIONS]", 5, 6, 0, "Create a dm-clone device");

/* Arguments: systemd-clonesetup add NAME SOURCE DEST METADATA [OPTIONS] */
static int verb_add(int argc, char *argv[], uintptr_t data, void *userdata) {
        assert(argc >= 5 && argc <= 6);

        const char *name = ASSERT_PTR(argv[1]);
        const char *src = ASSERT_PTR(argv[2]);
        const char *dst = ASSERT_PTR(argv[3]);
        const char *meta = ASSERT_PTR(argv[4]);

        const char *options = argc == 6 ? argv[5] : "";

        int r;
        r = validate_fields(name, src, dst, meta, options);
        if (r < 0)
                return r;

        log_debug("%s %s %s %s %s opts=%s", __func__,
                name, src, dst, meta, options);
        return clone_device(name, src, dst, meta, options);
}

VERB(verb_remove, "remove", "NAME", 2, 2, 0, "Remove a dm-clone device");

static int verb_remove(int argc, char *argv[], uintptr_t data, void *userdata) {
        const char *name = ASSERT_PTR(argv[1]);
        int r;

        r = dm_clone_remove_device(name);
        if (r == -ENXIO) {
                log_info("Device %s already inactive.", name);
                return 0;
        }

        if (r == -EBUSY) {
                r = dm_clone_remove_device_deferred(name);
                return r == -ENXIO ? 0 : r;
        }

        if (r < 0)
                return r;

        return 0;
}

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        help_cmdline("add NAME SOURCE DEST METADATA [OPTIONS]");
        help_cmdline("remove NAME");
        help_abstract("Add or remove a dm-clone device.");
        help_section("Options");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("systemd-clonesetup", "8");
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };
        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();
                }

        return 1;
}

/* systemd-clonesetup uses device-mapper ioctls to create and remove the
 * dm-clone devices. */
static int run(int argc, char *argv[]) {
        int r;

        log_setup();
        umask(0022);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return dispatch_verb(strv_skip(argv, 1), /* userdata= */ NULL);
}

DEFINE_MAIN_FUNCTION(run);
