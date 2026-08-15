/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <sys/stat.h>

#include "alloc-util.h"
#include "build.h"
#include "clonesetup-ioctl.h"
#include "clonesetup-util.h"
#include "extract-word.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"               /* strv_skip */
#include "verbs.h"

/* region-size: size of each dm-clone region in bytes. Handled internally in bytes, but must correspond to a
 * power of 2 between 4K and 1G per dm-clone kernel docs. */
#define CLONE_REGION_SIZE_DEFAULT_BYTES       (UINT64_C(1) << 12)      /* 4 KiB */
#define CLONE_REGION_SIZE_MIN_BYTES           (UINT64_C(1) << 12)      /* 4 KiB */
#define CLONE_REGION_SIZE_MAX_BYTES           (UINT64_C(1) << 30)      /* 1 GiB */

static int parse_clone_options(const char *options, uint64_t *ret_region_size_bytes) {
        uint64_t region_size_bytes = CLONE_REGION_SIZE_DEFAULT_BYTES;

        assert(ret_region_size_bytes);

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

                /* treat - as empty — common placeholders for "no options" */
                if (streq(word, "-"))
                        continue;

                if ((val = startswith(word, "region-size="))) {
                        uint64_t r_size_bytes;
                        /* parse_size handles suffixes like K, M, G automatically */
                        r = parse_size(val, 1024, &r_size_bytes);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse region-size= value '%s', using default.", val);
                        else if (!ISPOWEROF2(r_size_bytes) || r_size_bytes < CLONE_REGION_SIZE_MIN_BYTES || r_size_bytes > CLONE_REGION_SIZE_MAX_BYTES)
                                log_warning("region-size=%s must be a power of two between 4K and 1G, using default.", val);
                        else
                                region_size_bytes = r_size_bytes;
                } else
                        /* currently only region-size is supported */
                        log_warning("Unknown clone option '%s', ignoring.", word);
        }
        *ret_region_size_bytes = region_size_bytes;
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

        int r;

        assert(clone_name);
        assert(source_dev);
        assert(dest_dev);
        assert(metadata_dev);

        uint64_t region_size_bytes;
        r = parse_clone_options(options, &region_size_bytes);
        if (r < 0)
                return r;

        r = dm_clone_create_device(clone_name, source_dev, dest_dev, metadata_dev, region_size_bytes);
        if (r < 0)
                return r;

        r = dm_clone_send_message(clone_name, "enable_hydration");
        if (r < 0) {
                (void) dm_clone_remove_device_deferred(clone_name);
                return r;
        }
        return 0;
}

VERB(verb_add, "add", "NAME SOURCE DEST METADATA [OPTIONS]", 5, 6, 0, "Create a dm-clone device");

/* Arguments: systemd-clonesetup add NAME SOURCE DEST METADATA [OPTIONS] */
static int verb_add(int argc, char *argv[], uintptr_t data, void *userdata) {
        int r;
        assert(argc >= 5 && argc <= 6);

        const char *name = ASSERT_PTR(argv[1]);
        const char *src = ASSERT_PTR(argv[2]);
        const char *dst = ASSERT_PTR(argv[3]);
        const char *meta = ASSERT_PTR(argv[4]);

        const char *options = argc == 6 ? argv[5] : "";

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
        if (r == -EBUSY)
                return dm_clone_remove_device_deferred(name);
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
