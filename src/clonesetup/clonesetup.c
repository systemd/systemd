/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <getopt.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>     /* access */

#include "alloc-util.h"
#include "argv-util.h"
#include "build.h"
#include "clonesetup-ioctl.h"
#include "log.h"
#include "main-func.h"
#include "pretty-print.h"
#include "verbs.h"
#include "path-util.h"      /* path_join */
#include "time-util.h"      /* USEC_PER_SEC */
#include "udev-util.h"      /* device_wait_for_devlink */
#include "extract-word.h"
#include "string-util.h"
#include "parse-util.h"

/* region_size: Must be a power of 2 between 8 and 2097152 per dm-clone kernel docs. */
#define DEFAULT_REGION_SIZE 8
#define CLONE_MIN_REGION_SIZE (UINT64_C(1) << 3)        /* 8 */
#define CLONE_MAX_REGION_SIZE (UINT64_C(1) << 21)       /* 2097152 */

static int parse_clone_options(const char *options, uint64_t *ret_region_size) {
        *ret_region_size=DEFAULT_REGION_SIZE;

        for (;;) {
                _cleanup_free_ char *word=NULL;
                const char *val;
                int r;

                /* extract_first_word: *
                 * Returns > 0 — successfully extracted a word *
                 * Returns 0 — no more words (end of string) *
                 * Returns < 0 — actual error (e.g. memory allocation failure) */
                r = extract_first_word(&options, &word, ",", EXTRACT_DONT_COALESCE_SEPARATORS);
                if ( r < 0 )
                        return log_error_errno(r, "Failed to parse clone options: %m");
                if ( r == 0 )
                        break;

                /* region_size=N; size of each clone region in 512-byte sectors ( default 8 = 4KB )
                 * Must be a power of 2 between 8 and 2097152 per dm-clone kernel docs. */
                /* treat "" and "-" as empty — common placeholders for "no options" */
                if (streq(word, "\"\"") || streq(word, "-"))
                        continue;

                if (( val = startswith(word, "region_size="))) {
                        uint64_t region_size;
                        r = safe_atou64(val, &region_size);
                        if (r < 0) {
                                log_warning("Invalid region size=value '%s', using default", val);
                        } else if (!ISPOWEROF2(region_size) || region_size < CLONE_MIN_REGION_SIZE || region_size > CLONE_MAX_REGION_SIZE) {
                                log_warning("region_size=%s must be a power of two between 8 and 2097152, using default.", val);
                        } else {
                                *ret_region_size=region_size;
                        }
                } else {
                        /* currently only region_size is supported */
                        log_warning("Unknown clone option '%s', ignoring.", word);
                }
        }
        return 0;
}

/* dm-clone device creation workflow:
 * 1. Create the dm-clone device
 * 2. Enable background hydration
 * 3. (Optional) Replace with linear mapping to finalize */
static int clone_device(const char *clone_name, const char *source_dev, const char *dest_dev,
                const char *metadata_dev, const char *options) {

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
                return log_error_errno(r, "Failed to parse clone options: %m");

        r = dm_clone_create_device(clone_name, source_dev, dest_dev, metadata_dev, region_size);
        if (r < 0)
                return log_error_errno(r, "Failed to create dm-clone device: %m");

        /* Wait for udev to create /dev/mapper/<name> */
        r = device_wait_for_devlink(clone_dev_path, "block", 10 * USEC_PER_SEC, /* ret_inode = */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for device %s: %m", clone_dev_path);

        r = dm_clone_send_message(clone_name, "enable_hydration");
        if (r < 0)
                return log_error_errno(r, "Failed to send dm message: %m");

        return 0;
}

/* Arguments: systemd-clonesetup add NAME SOURCE-DEVICE DST_DEVICE META-DEVICE [OPTIONS] */
static int verb_add(int argc, char *argv[], uintptr_t data, void *userdata) {
        int r;

        assert(argc >= 5 && argc <= 6);

        const char *name = ASSERT_PTR(argv[1]),
              *src_dev = ASSERT_PTR(argv[2]),
              *dst_dev = ASSERT_PTR(argv[3]),
              *meta_dev = ASSERT_PTR(argv[4]);

        const char *options = (argc == 6 ? argv[5] : "");

        log_debug("%s %s %s %s %s opts=%s ", __func__,
                  name, src_dev, dst_dev, meta_dev, options);

        r = clone_device(name, src_dev, dst_dev, meta_dev, options);
        if (r < 0)
                return r;

        return 0;
}

static int verb_remove(int argc, char *argv[], uintptr_t data, void *userdata) {
        const char *name = ASSERT_PTR(argv[1]);
        int r;

        r = dm_clone_remove_device(name);
        if (r < 0)
                return r;

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-clonesetup", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s add NAME SOURCE-DEVICE DST-DEVICE META-DEVICE [OPTIONS] \n"
               "%1$s remove VOLUME\n\n"
               "%2$sAdd or remove a dm clone device.%3$s\n\n"
               "  -h --help            Show this help\n"
               "     --version         Show package version\n"
               "\nSee the %4$s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",                         no_argument,       NULL, 'h'                       },
                { "version",                      no_argument,       NULL, ARG_VERSION               },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        if (argv_looks_like_help(argc, argv))
                return help();

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                        case 'h':
                                return help();

                        case ARG_VERSION:
                                return version();

                        case '?':
                                return -EINVAL;

                        default:
                                assert_not_reached();
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

        static const Verb verbs[] = {
                { "add",    5, 6, 0, verb_add,    0 },
                { "remove", 2, 2, 0, verb_remove, 0 },
                {}
        };
        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
