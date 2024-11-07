/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "bootspec.h"
#include "build.h"
#include "devnum-util.h"
#include "efi-api.h"
#include "efi-loader.h"
#include "efivars.h"
#include "fd-util.h"
#include "find-esp.h"
#include "fs-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "sync-util.h"
#include "terminal-util.h"
#include "verbs.h"
#include "virt.h"

static char **arg_path = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_path, strv_freep);

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-bless-boot.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND\n"
               "\n%sMark the boot process as good or bad.%s\n"
               "\nCommands:\n"
               "     status          Show status of current boot loader entry\n"
               "     good            Mark this boot as good\n"
               "     bad             Mark this boot as bad\n"
               "     indeterminate   Undo any marking as good or bad\n"
               "\nOptions:\n"
               "  -h --help          Show this help\n"
               "     --version       Print version\n"
               "     --path=PATH     Path to the $BOOT partition (may be used multiple times)\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_PATH = 0x100,
                ARG_VERSION,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "path",         required_argument, NULL, ARG_PATH         },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help(0, NULL, NULL);
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_PATH:
                        r = strv_extend(&arg_path, optarg);
                        if (r < 0)
                                return log_oom();
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int acquire_path(void) {
        _cleanup_free_ char *esp_path = NULL, *xbootldr_path = NULL;
        dev_t esp_devid = 0, xbootldr_devid = 0;
        char **a;
        int r;

        if (!strv_isempty(arg_path))
                return 0;

        r = find_esp_and_warn(NULL, NULL, /* unprivileged_mode= */ false, &esp_path, NULL, NULL, NULL, NULL, &esp_devid);
        if (r < 0 && r != -ENOKEY) /* ENOKEY means not found, and is the only error the function won't log about on its own */
                return r;

        r = find_xbootldr_and_warn(NULL, NULL, /* unprivileged_mode= */ false, &xbootldr_path, NULL, &xbootldr_devid);
        if (r < 0 && r != -ENOKEY)
                return r;

        if (!esp_path && !xbootldr_path)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Couldn't find $BOOT partition. It is recommended to mount it to /boot.\n"
                                       "Alternatively, use --path= to specify path to mount point.");

        if (esp_path && xbootldr_path && !devnum_set_and_equal(esp_devid, xbootldr_devid)) /* in case the two paths refer to the same inode, suppress one */
                a = strv_new(esp_path, xbootldr_path);
        else if (esp_path)
                a = strv_new(esp_path);
        else
                a = strv_new(xbootldr_path);
        if (!a)
                return log_oom();

        strv_free_and_replace(arg_path, a);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *j = NULL;

                j = strv_join(arg_path, ":");
                log_debug("Using %s as boot loader drop-in search path.", strna(j));
        }

        return 0;
}

static int parse_counter(
                const char *path,
                const char **p,
                uint64_t *ret_left,
                uint64_t *ret_done) {

        uint64_t left, done;
        const char *z, *e;
        size_t k;
        int r;

        assert(path);
        assert(p);

        e = *p;
        assert(e);
        assert(*e == '+');

        e++;

        k = strspn(e, DIGITS);
        if (k == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Can't parse empty 'tries left' counter from LoaderBootCountPath: %s",
                                       path);

        z = strndupa_safe(e, k);
        r = safe_atou64(z, &left);
        if (r < 0)
                return log_error_errno(r, "Failed to parse 'tries left' counter from LoaderBootCountPath: %s", path);

        e += k;

        if (*e == '-') {
                e++;

                k = strspn(e, DIGITS);
                if (k == 0) /* If there's a "-" there also needs to be at least one digit */
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Can't parse empty 'tries done' counter from LoaderBootCountPath: %s",
                                               path);

                z = strndupa_safe(e, k);
                r = safe_atou64(z, &done);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse 'tries done' counter from LoaderBootCountPath: %s", path);

                e += k;
        } else
                done = 0;

        if (done == 0)
                log_warning("The 'tries done' counter is currently at zero. This can't really be, after all we are running, and this boot must hence count as one. Proceeding anyway.");

        *p = e;

        if (ret_left)
                *ret_left = left;

        if (ret_done)
                *ret_done = done;

        return 0;
}

static int acquire_boot_count_path(
                char **ret_path,
                char **ret_prefix,
                uint64_t *ret_left,
                uint64_t *ret_done,
                char **ret_suffix) {

        _cleanup_free_ char *path = NULL, *prefix = NULL, *suffix = NULL;
        const char *last, *e;
        uint64_t left, done;
        int r;

        r = efi_get_variable_path(EFI_LOADER_VARIABLE_STR("LoaderBootCountPath"), &path);
        if (r == -ENOENT)
                return -EUNATCH; /* in this case, let the caller print a message */
        if (r < 0)
                return log_error_errno(r, "Failed to read LoaderBootCountPath EFI variable: %m");

        if (!path_is_normalized(path))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Path read from LoaderBootCountPath is not normalized, refusing: %s",
                                       path);

        if (!path_is_absolute(path))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Path read from LoaderBootCountPath is not absolute, refusing: %s",
                                       path);

        last = last_path_component(path);
        e = strrchr(last, '+');
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Path read from LoaderBootCountPath does not contain a counter, refusing: %s",
                                       path);

        if (ret_prefix) {
                prefix = strndup(path, e - path);
                if (!prefix)
                        return log_oom();
        }

        r = parse_counter(path, &e, &left, &done);
        if (r < 0)
                return r;

        if (ret_suffix) {
                suffix = strdup(e);
                if (!suffix)
                        return log_oom();

                *ret_suffix = TAKE_PTR(suffix);
        }

        if (ret_path)
                *ret_path = TAKE_PTR(path);
        if (ret_prefix)
                *ret_prefix = TAKE_PTR(prefix);
        if (ret_left)
                *ret_left = left;
        if (ret_done)
                *ret_done = done;

        return 0;
}

static int make_good(const char *prefix, const char *suffix, char **ret) {
        _cleanup_free_ char *good = NULL;

        assert(prefix);
        assert(suffix);
        assert(ret);

        /* Generate the path we'd use on good boots. This one is easy. If we are successful, we simple drop the counter
         * pair entirely from the name. After all, we know all is good, and the logs will contain information about the
         * tries we needed to come here, hence it's safe to drop the counters from the name. */

        good = strjoin(prefix, suffix);
        if (!good)
                return -ENOMEM;

        *ret = TAKE_PTR(good);
        return 0;
}

static int make_bad(const char *prefix, uint64_t done, const char *suffix, char **ret) {
        _cleanup_free_ char *bad = NULL;

        assert(prefix);
        assert(suffix);
        assert(ret);

        /* Generate the path we'd use on bad boots. Let's simply set the 'left' counter to zero, and keep the 'done'
         * counter. The information might be interesting to boot loaders, after all. */

        if (done == 0) {
                bad = strjoin(prefix, "+0", suffix);
                if (!bad)
                        return -ENOMEM;
        } else {
                if (asprintf(&bad, "%s+0-%" PRIu64 "%s", prefix, done, suffix) < 0)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(bad);
        return 0;
}

static int verb_status(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *path = NULL, *prefix = NULL, *suffix = NULL, *good = NULL, *bad = NULL;
        uint64_t left, done;
        int r;

        r = acquire_boot_count_path(&path, &prefix, &left, &done, &suffix);
        if (r == -EUNATCH) { /* No boot count in place, then let's consider this a "clean" boot, as "good", "bad" or "indeterminate" don't apply. */
                puts("clean");
                return 0;
        }
        if (r < 0)
                return r;

        r = acquire_path();
        if (r < 0)
                return r;

        r = make_good(prefix, suffix, &good);
        if (r < 0)
                return log_oom();

        r = make_bad(prefix, done, suffix, &bad);
        if (r < 0)
                return log_oom();

        log_debug("Booted file: %s\n"
                  "The same modified for 'good': %s\n"
                  "The same modified for 'bad':  %s\n",
                  path,
                  good,
                  bad);

        log_debug("Tries left: %" PRIu64"\n"
                  "Tries done: %" PRIu64"\n",
                  left, done);

        STRV_FOREACH(p, arg_path) {
                _cleanup_close_ int fd = -EBADF;

                fd = open(*p, O_DIRECTORY|O_CLOEXEC|O_RDONLY);
                if (fd < 0) {
                        if (errno == ENOENT)
                                continue;

                        return log_error_errno(errno, "Failed to open $BOOT partition '%s': %m", *p);
                }

                if (faccessat(fd, skip_leading_slash(path), F_OK, 0) >= 0) {
                        puts("indeterminate");
                        return 0;
                }
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to check if '%s' exists: %m", path);

                if (faccessat(fd, skip_leading_slash(good), F_OK, 0) >= 0) {
                        puts("good");
                        return 0;
                }

                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to check if '%s' exists: %m", good);

                if (faccessat(fd, skip_leading_slash(bad), F_OK, 0) >= 0) {
                        puts("bad");
                        return 0;
                }
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to check if '%s' exists: %m", bad);

                /* We didn't find any of the three? If so, let's try the next directory, before we give up. */
        }

        return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Couldn't determine boot state.");
}

static int verb_set(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *path = NULL, *prefix = NULL, *suffix = NULL, *good = NULL, *bad = NULL;
        const char *target, *source1, *source2;
        uint64_t done;
        int r;

        r = acquire_boot_count_path(&path, &prefix, NULL, &done, &suffix);
        if (r == -EUNATCH) /* acquire_boot_count_path() won't log on its own for this specific error */
                return log_error_errno(r, "Not booted with boot counting in effect.");
        if (r < 0)
                return r;

        r = acquire_path();
        if (r < 0)
                return r;

        r = make_good(prefix, suffix, &good);
        if (r < 0)
                return log_oom();

        r = make_bad(prefix, done, suffix, &bad);
        if (r < 0)
                return log_oom();

        /* Figure out what rename to what */
        if (streq(argv[0], "good")) {
                target = good;
                source1 = path;
                source2 = bad;      /* Maybe this boot was previously marked as 'bad'? */
        } else if (streq(argv[0], "bad")) {
                target = bad;
                source1 = path;
                source2 = good;     /* Maybe this boot was previously marked as 'good'? */
        } else {
                assert(streq(argv[0], "indeterminate"));
                target = path;
                source1 = good;
                source2 = bad;
        }

        STRV_FOREACH(p, arg_path) {
                _cleanup_close_ int fd = -EBADF;

                fd = open(*p, O_DIRECTORY|O_CLOEXEC|O_RDONLY);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open $BOOT partition '%s': %m", *p);

                r = rename_noreplace(fd, skip_leading_slash(source1), fd, skip_leading_slash(target));
                if (r == -EEXIST)
                        goto exists;
                if (r == -ENOENT) {

                        r = rename_noreplace(fd, skip_leading_slash(source2), fd, skip_leading_slash(target));
                        if (r == -EEXIST)
                                goto exists;
                        if (r == -ENOENT) {

                                if (faccessat(fd, skip_leading_slash(target), F_OK, 0) >= 0) /* Hmm, if we can't find either source file, maybe the destination already exists? */
                                        goto exists;

                                if (errno != ENOENT)
                                        return log_error_errno(errno, "Failed to determine if %s already exists: %m", target);

                                /* We found none of the snippets here, try the next directory */
                                continue;
                        }
                        if (r < 0)
                                return log_error_errno(r, "Failed to rename '%s' to '%s': %m", source2, target);

                        log_debug("Successfully renamed '%s' to '%s'.", source2, target);
                } else if (r < 0)
                        return log_error_errno(r, "Failed to rename '%s' to '%s': %m", source1, target);
                else
                        log_debug("Successfully renamed '%s' to '%s'.", source1, target);

                /* First, fsync() the directory these files are located in */
                r = fsync_parent_at(fd, skip_leading_slash(target));
                if (r < 0)
                        log_debug_errno(r, "Failed to synchronize image directory, ignoring: %m");

                /* Secondly, syncfs() the whole file system these files are located in */
                if (syncfs(fd) < 0)
                        log_debug_errno(errno, "Failed to synchronize $BOOT partition, ignoring: %m");

                log_info("Marked boot as '%s'. (Boot attempt counter is at %" PRIu64".)", argv[0], done);
                return 0;
        }

        return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Can't find boot counter source file for '%s'.", target);

exists:
        log_debug("Operation already executed before, not doing anything.");
        return 0;
}

static int run(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",          VERB_ANY, VERB_ANY, 0,            help        },
                { "status",        VERB_ANY, 1,        VERB_DEFAULT, verb_status },
                { "good",          VERB_ANY, 1,        0,            verb_set    },
                { "bad",           VERB_ANY, 1,        0,            verb_set    },
                { "indeterminate", VERB_ANY, 1,        0,            verb_set    },
                {}
        };

        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (detect_container() > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Marking a boot is not supported in containers.");

        if (!is_efi_boot())
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Marking a boot is only supported on EFI systems.");

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
