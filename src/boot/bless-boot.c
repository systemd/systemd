/* SPDX-License-Identifier: LGPL-2.1+ */

#include <getopt.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "bootspec.h"
#include "efivars.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "path-util.h"
#include "util.h"
#include "verbs.h"
#include "virt.h"

static char **arg_path = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_path, strv_freep);

static int help(int argc, char *argv[], void *userdata) {

        printf("%s [COMMAND] [OPTIONS...]\n"
               "\n"
               "Mark the boot process as good or bad.\n\n"
               "  -h --help          Show this help\n"
               "     --version       Print version\n"
               "     --path=PATH     Path to the $BOOT partition (may be used multiple times)\n"
               "\n"
               "Commands:\n"
               "     good            Mark this boot as good\n"
               "     bad             Mark this boot as bad\n"
               "     indeterminate   Undo any marking as good or bad\n",
               program_invocation_short_name);

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
                        assert_not_reached("Unknown option");
                }

        return 1;
}

static int acquire_path(void) {
        _cleanup_free_ char *esp_path = NULL, *xbootldr_path = NULL;
        char **a;
        int r;

        if (!strv_isempty(arg_path))
                return 0;

        r = find_esp_and_warn(NULL, false, &esp_path, NULL, NULL, NULL, NULL);
        if (r < 0 && r != -ENOKEY) /* ENOKEY means not found, and is the only error the function won't log about on its own */
                return r;

        r = find_xbootldr_and_warn(NULL, false, &xbootldr_path, NULL);
        if (r < 0 && r != -ENOKEY)
                return r;

        if (!esp_path && !xbootldr_path)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Couldn't find $BOOT partition. It is recommended to mount it to /boot.\n"
                                       "Alternatively, use --path= to specify path to mount point.");

        if (esp_path)
                a = strv_new(esp_path, xbootldr_path);
        else
                a = strv_new(xbootldr_path);
        if (!a)
                return log_oom();

        strv_free_and_replace(arg_path, a);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *j;

                j = strv_join(arg_path, ":");
                log_debug("Using %s as boot loader drop-in search path.", j);
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

        z = strndupa(e, k);
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

                z = strndupa(e, k);
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

        r = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderBootCountPath", &path);
        if (r == -ENOENT)
                return -EUNATCH; /* in this case, let the caller print a message */
        if (r < 0)
                return log_error_errno(r, "Failed to read LoaderBootCountPath EFI variable: %m");

        efi_tilt_backslashes(path);

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

static const char *skip_slash(const char *path) {
        assert(path);
        assert(path[0] == '/');

        return path + 1;
}

static int verb_status(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *path = NULL, *prefix = NULL, *suffix = NULL, *good = NULL, *bad = NULL;
        uint64_t left, done;
        char **p;
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
                _cleanup_close_ int fd = -1;

                fd = open(*p, O_DIRECTORY|O_CLOEXEC|O_RDONLY);
                if (fd < 0) {
                        if (errno == ENOENT)
                                continue;

                        return log_error_errno(errno, "Failed to open $BOOT partition '%s': %m", *p);
                }

                if (faccessat(fd, skip_slash(path), F_OK, 0) >= 0) {
                        puts("indeterminate");
                        return 0;
                }
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to check if '%s' exists: %m", path);

                if (faccessat(fd, skip_slash(good), F_OK, 0) >= 0) {
                        puts("good");
                        return 0;
                }

                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to check if '%s' exists: %m", good);

                if (faccessat(fd, skip_slash(bad), F_OK, 0) >= 0) {
                        puts("bad");
                        return 0;
                }
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to check if '%s' exists: %m", bad);

                /* We didn't find any of the three? If so, let's try the next directory, before we give up. */
        }

        return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Couldn't determine boot state: %m");
}

static int verb_set(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *path = NULL, *prefix = NULL, *suffix = NULL, *good = NULL, *bad = NULL, *parent = NULL;
        const char *target, *source1, *source2;
        uint64_t done;
        char **p;
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
                _cleanup_close_ int fd = -1;

                fd = open(*p, O_DIRECTORY|O_CLOEXEC|O_RDONLY);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open $BOOT partition '%s': %m", *p);

                r = rename_noreplace(fd, skip_slash(source1), fd, skip_slash(target));
                if (r == -EEXIST)
                        goto exists;
                else if (r == -ENOENT) {

                        r = rename_noreplace(fd, skip_slash(source2), fd, skip_slash(target));
                        if (r == -EEXIST)
                                goto exists;
                        else if (r == -ENOENT) {

                                if (faccessat(fd, skip_slash(target), F_OK, 0) >= 0) /* Hmm, if we can't find either source file, maybe the destination already exists? */
                                        goto exists;

                                if (errno != ENOENT)
                                        return log_error_errno(errno, "Failed to determine if %s already exists: %m", target);

                                /* We found none of the snippets here, try the next directory */
                                continue;
                        } else if (r < 0)
                                return log_error_errno(r, "Failed to rename '%s' to '%s': %m", source2, target);
                        else
                                log_debug("Successfully renamed '%s' to '%s'.", source2, target);

                } else if (r < 0)
                        return log_error_errno(r, "Failed to rename '%s' to '%s': %m", source1, target);
                else
                        log_debug("Successfully renamed '%s' to '%s'.", source1, target);

                /* First, fsync() the directory these files are located in */
                parent = dirname_malloc(target);
                if (!parent)
                        return log_oom();

                r = fsync_path_at(fd, skip_slash(parent));
                if (r < 0)
                        log_debug_errno(errno, "Failed to synchronize image directory, ignoring: %m");

                /* Secondly, syncfs() the whole file system these files are located in */
                if (syncfs(fd) < 0)
                        log_debug_errno(errno, "Failed to synchronize $BOOT partition, ignoring: %m");

                log_info("Marked boot as '%s'. (Boot attempt counter is at %" PRIu64".)", argv[0], done);
        }

        log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Can't find boot counter source file for '%s': %m", target);
        return 1;

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

        log_parse_environment();
        log_open();

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
