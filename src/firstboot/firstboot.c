/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
#include <linux/loop.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "chase.h"
#include "copy.h"
#include "creds-util.h"
#include "dissect-image.h"
#include "env-file.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "hostname-util.h"
#include "kbd-util.h"
#include "libcrypt-util.h"
#include "locale-util.h"
#include "lock-util.h"
#include "main-func.h"
#include "memory-util.h"
#include "mkdir.h"
#include "mount-util.h"
#include "os-util.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "password-quality-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "random-util.h"
#include "smack-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "tmpfile-util-label.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "user-util.h"

static char *arg_root = NULL;
static char *arg_image = NULL;
static char *arg_locale = NULL;  /* $LANG */
static char *arg_locale_messages = NULL; /* $LC_MESSAGES */
static char *arg_keymap = NULL;
static char *arg_timezone = NULL;
static char *arg_hostname = NULL;
static sd_id128_t arg_machine_id = {};
static char *arg_root_password = NULL;
static char *arg_root_shell = NULL;
static char *arg_kernel_cmdline = NULL;
static bool arg_prompt_locale = false;
static bool arg_prompt_keymap = false;
static bool arg_prompt_timezone = false;
static bool arg_prompt_hostname = false;
static bool arg_prompt_root_password = false;
static bool arg_prompt_root_shell = false;
static bool arg_copy_locale = false;
static bool arg_copy_keymap = false;
static bool arg_copy_timezone = false;
static bool arg_copy_root_password = false;
static bool arg_copy_root_shell = false;
static bool arg_force = false;
static bool arg_delete_root_password = false;
static bool arg_root_password_is_hashed = false;
static bool arg_welcome = true;
static bool arg_reset = false;
static ImagePolicy *arg_image_policy = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_locale, freep);
STATIC_DESTRUCTOR_REGISTER(arg_locale_messages, freep);
STATIC_DESTRUCTOR_REGISTER(arg_keymap, freep);
STATIC_DESTRUCTOR_REGISTER(arg_timezone, freep);
STATIC_DESTRUCTOR_REGISTER(arg_hostname, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_password, erase_and_freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);

static bool press_any_key(void) {
        char k = 0;
        bool need_nl = true;

        printf("-- Press any key to proceed --");
        fflush(stdout);

        (void) read_one_char(stdin, &k, USEC_INFINITY, &need_nl);

        if (need_nl)
                putchar('\n');

        return k != 'q';
}

static void print_welcome(int rfd) {
        _cleanup_free_ char *pretty_name = NULL, *os_name = NULL, *ansi_color = NULL;
        static bool done = false;
        const char *pn, *ac;
        int r;

        assert(rfd >= 0);

        if (!arg_welcome)
                return;

        if (done)
                return;

        r = parse_os_release_at(rfd,
                                "PRETTY_NAME", &pretty_name,
                                "NAME", &os_name,
                                "ANSI_COLOR", &ansi_color);
        if (r < 0)
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to read os-release file, ignoring: %m");

        pn = os_release_pretty_name(pretty_name, os_name);
        ac = isempty(ansi_color) ? "0" : ansi_color;

        (void) reset_terminal_fd(STDIN_FILENO, /* switch_to_text= */ false);

        if (colors_enabled())
                printf("\nWelcome to your new installation of \x1B[%sm%s\x1B[0m!\n", ac, pn);
        else
                printf("\nWelcome to your new installation of %s!\n", pn);

        printf("\nPlease configure your system!\n\n");

        press_any_key();

        done = true;
}

static int show_menu(char **x, unsigned n_columns, unsigned width, unsigned percentage) {
        unsigned break_lines, break_modulo;
        size_t n, per_column, i, j;

        assert(n_columns > 0);

        n = strv_length(x);
        per_column = DIV_ROUND_UP(n, n_columns);

        break_lines = lines();
        if (break_lines > 2)
                break_lines--;

        /* The first page gets two extra lines, since we want to show
         * a title */
        break_modulo = break_lines;
        if (break_modulo > 3)
                break_modulo -= 3;

        for (i = 0; i < per_column; i++) {

                for (j = 0; j < n_columns; j++) {
                        _cleanup_free_ char *e = NULL;

                        if (j * per_column + i >= n)
                                break;

                        e = ellipsize(x[j * per_column + i], width, percentage);
                        if (!e)
                                return log_oom();

                        printf("%4zu) %-*s", j * per_column + i + 1, (int) width, e);
                }

                putchar('\n');

                /* on the first screen we reserve 2 extra lines for the title */
                if (i % break_lines == break_modulo) {
                        if (!press_any_key())
                                return 0;
                }
        }

        return 0;
}

static int prompt_loop(const char *text, char **l, unsigned percentage, bool (*is_valid)(const char *name), char **ret) {
        int r;

        assert(text);
        assert(is_valid);
        assert(ret);

        for (;;) {
                _cleanup_free_ char *p = NULL;
                unsigned u;

                r = ask_string(&p, "%s %s (empty to skip, \"list\" to list options): ",
                               special_glyph(SPECIAL_GLYPH_TRIANGULAR_BULLET), text);
                if (r < 0)
                        return log_error_errno(r, "Failed to query user: %m");

                if (isempty(p)) {
                        log_warning("No data entered, skipping.");
                        return 0;
                }

                if (streq(p, "list")) {
                        r = show_menu(l, 3, 22, percentage);
                        if (r < 0)
                                return r;

                        putchar('\n');
                        continue;
                };

                r = safe_atou(p, &u);
                if (r >= 0) {
                        if (u <= 0 || u > strv_length(l)) {
                                log_error("Specified entry number out of range.");
                                continue;
                        }

                        log_info("Selected '%s'.", l[u-1]);
                        return free_and_strdup_warn(ret, l[u-1]);
                }

                if (!is_valid(p)) {
                        log_error("Entered data invalid.");
                        continue;
                }

                return free_and_replace(*ret, p);
        }
}

static int should_configure(int dir_fd, const char *filename) {
        _cleanup_fclose_ FILE *passwd = NULL, *shadow = NULL;
        int r;

        assert(dir_fd >= 0);
        assert(filename);

        if (streq(filename, "passwd") && !arg_force)
                /* We may need to do additional checks, so open the file. */
                r = xfopenat(dir_fd, filename, "re", O_NOFOLLOW, &passwd);
        else
                r = RET_NERRNO(faccessat(dir_fd, filename, F_OK, AT_SYMLINK_NOFOLLOW));

        if (r == -ENOENT)
                return true; /* missing */
        if (r < 0)
                return log_error_errno(r, "Failed to access %s: %m", filename);
        if (arg_force)
                return true; /* exists, but if --force was given we should still configure the file. */

        if (!passwd)
                return false;

        /* In case of /etc/passwd, do an additional check for the root password field.
         * We first check that passwd redirects to shadow, and then we check shadow.
         */
        struct passwd *i;
        while ((r = fgetpwent_sane(passwd, &i)) > 0) {
                if (!streq(i->pw_name, "root"))
                        continue;

                if (streq_ptr(i->pw_passwd, PASSWORD_SEE_SHADOW))
                        break;
                log_debug("passwd: root account with non-shadow password found, treating root as configured");
                return false;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read %s: %m", filename);
        if (r == 0) {
                log_debug("No root account found in %s, assuming root is not configured.", filename);
                return true;
        }

        r = xfopenat(dir_fd, "shadow", "re", O_NOFOLLOW, &shadow);
        if (r == -ENOENT) {
                log_debug("No shadow file found, assuming root is not configured.");
                return true; /* missing */
        }
        if (r < 0)
                return log_error_errno(r, "Failed to access shadow: %m");

        struct spwd *j;
        while ((r = fgetspent_sane(shadow, &j)) > 0) {
                if (!streq(j->sp_namp, "root"))
                        continue;

                bool unprovisioned = streq_ptr(j->sp_pwdp, PASSWORD_UNPROVISIONED);
                log_debug("Root account found, %s.",
                          unprovisioned ? "with unprovisioned password, treating root as not configured" :
                                          "treating root as configured");
                return unprovisioned;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read shadow: %m");
        assert(r == 0);
        log_debug("No root account found in shadow, assuming root is not configured.");
        return true;
}

static bool locale_is_installed_bool(const char *name) {
        return locale_is_installed(name) > 0;
}

static bool locale_is_ok(int rfd, const char *name) {
        assert(rfd >= 0);

        return dir_fd_is_root(rfd) ? locale_is_installed_bool(name) : locale_is_valid(name);
}

static int prompt_locale(int rfd) {
        _cleanup_strv_free_ char **locales = NULL;
        bool acquired_from_creds = false;
        int r;

        assert(rfd >= 0);

        if (arg_locale || arg_locale_messages)
                return 0;

        r = read_credential("firstboot.locale", (void**) &arg_locale, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential firstboot.locale, ignoring: %m");
        else
                acquired_from_creds = true;

        r = read_credential("firstboot.locale-messages", (void**) &arg_locale_messages, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential firstboot.locale-messages, ignoring: %m");
        else
                acquired_from_creds = true;

        if (acquired_from_creds) {
                log_debug("Acquired locale from credentials.");
                return 0;
        }

        if (!arg_prompt_locale) {
                log_debug("Prompting for locale was not requested.");
                return 0;
        }

        r = get_locales(&locales);
        if (r < 0)
                return log_error_errno(r, "Cannot query locales list: %m");

        if (strv_isempty(locales))
                log_debug("No locales found, skipping locale selection.");
        else if (strv_length(locales) == 1) {

                if (streq(locales[0], SYSTEMD_DEFAULT_LOCALE))
                        log_debug("Only installed locale is default locale anyway, not setting locale explicitly.");
                else {
                        log_debug("Only a single locale available (%s), selecting it as default.", locales[0]);

                        arg_locale = strdup(locales[0]);
                        if (!arg_locale)
                                return log_oom();

                        /* Not setting arg_locale_message here, since it defaults to LANG anyway */
                }
        } else {
                bool (*is_valid)(const char *name) = dir_fd_is_root(rfd) ? locale_is_installed_bool
                                                                         : locale_is_valid;

                print_welcome(rfd);

                r = prompt_loop("Please enter system locale name or number",
                                locales, 60, is_valid, &arg_locale);
                if (r < 0)
                        return r;

                if (isempty(arg_locale))
                        return 0;

                r = prompt_loop("Please enter system message locale name or number",
                                locales, 60, is_valid, &arg_locale_messages);
                if (r < 0)
                        return r;

                /* Suppress the messages setting if it's the same as the main locale anyway */
                if (streq_ptr(arg_locale, arg_locale_messages))
                        arg_locale_messages = mfree(arg_locale_messages);
        }

        return 0;
}

static int process_locale(int rfd) {
        _cleanup_close_ int pfd = -EBADF;
        _cleanup_free_ char *f = NULL;
        char* locales[3];
        unsigned i = 0;
        int r;

        assert(rfd >= 0);

        pfd = chase_and_open_parent_at(rfd, "/etc/locale.conf",
                                       CHASE_AT_RESOLVE_IN_ROOT|CHASE_MKDIR_0755|CHASE_WARN|CHASE_NOFOLLOW,
                                       &f);
        if (pfd < 0)
                return log_error_errno(pfd, "Failed to chase /etc/locale.conf: %m");

        r = should_configure(pfd, f);
        if (r == 0)
                log_debug("Found /etc/locale.conf, assuming locale information has been configured.");
        if (r <= 0)
                return r;

        r = dir_fd_is_root(rfd);
        if (r < 0)
                return log_error_errno(r, "Failed to check if directory file descriptor is root: %m");

        if (arg_copy_locale && r == 0) {
                r = copy_file_atomic_at(AT_FDCWD, "/etc/locale.conf", pfd, f, 0644, COPY_REFLINK);
                if (r != -ENOENT) {
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy host's /etc/locale.conf: %m");

                        log_info("Copied host's /etc/locale.conf.");
                        return 0;
                }
        }

        r = prompt_locale(rfd);
        if (r < 0)
                return r;

        if (!isempty(arg_locale))
                locales[i++] = strjoina("LANG=", arg_locale);
        if (!isempty(arg_locale_messages) && !streq_ptr(arg_locale_messages, arg_locale))
                locales[i++] = strjoina("LC_MESSAGES=", arg_locale_messages);

        if (i == 0)
                return 0;

        locales[i] = NULL;

        r = write_env_file(pfd, f, NULL, locales);
        if (r < 0)
                return log_error_errno(r, "Failed to write /etc/locale.conf: %m");

        log_info("/etc/locale.conf written.");
        return 1;
}

static int prompt_keymap(int rfd) {
        _cleanup_strv_free_ char **kmaps = NULL;
        int r;

        assert(rfd >= 0);

        if (arg_keymap)
                return 0;

        r = read_credential("firstboot.keymap", (void**) &arg_keymap, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential firstboot.keymap, ignoring: %m");
        else {
                log_debug("Acquired keymap from credential.");
                return 0;
        }

        if (!arg_prompt_keymap) {
                log_debug("Prompting for keymap was not requested.");
                return 0;
        }

        r = get_keymaps(&kmaps);
        if (r == -ENOENT) /* no keymaps installed */
                return log_debug_errno(r, "No keymaps are installed.");
        if (r < 0)
                return log_error_errno(r, "Failed to read keymaps: %m");

        print_welcome(rfd);

        return prompt_loop("Please enter system keymap name or number",
                           kmaps, 60, keymap_is_valid, &arg_keymap);
}

static int process_keymap(int rfd) {
        _cleanup_close_ int pfd = -EBADF;
        _cleanup_free_ char *f = NULL;
        char **keymap;
        int r;

        assert(rfd >= 0);

        pfd = chase_and_open_parent_at(rfd, "/etc/vconsole.conf",
                                       CHASE_AT_RESOLVE_IN_ROOT|CHASE_MKDIR_0755|CHASE_WARN|CHASE_NOFOLLOW,
                                       &f);
        if (pfd < 0)
                return log_error_errno(pfd, "Failed to chase /etc/vconsole.conf: %m");

        r = should_configure(pfd, f);
        if (r == 0)
                log_debug("Found /etc/vconsole.conf, assuming console has been configured.");
        if (r <= 0)
                return r;

        r = dir_fd_is_root(rfd);
        if (r < 0)
                return log_error_errno(r, "Failed to check if directory file descriptor is root: %m");

        if (arg_copy_keymap && r == 0) {
                r = copy_file_atomic_at(AT_FDCWD, "/etc/vconsole.conf", pfd, f, 0644, COPY_REFLINK);
                if (r != -ENOENT) {
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy host's /etc/vconsole.conf: %m");

                        log_info("Copied host's /etc/vconsole.conf.");
                        return 0;
                }
        }

        r = prompt_keymap(rfd);
        if (r == -ENOENT)
                return 0; /* don't fail if no keymaps are installed */
        if (r < 0)
                return r;

        if (isempty(arg_keymap))
                return 0;

        keymap = STRV_MAKE(strjoina("KEYMAP=", arg_keymap));

        r = write_vconsole_conf(pfd, f, keymap);
        if (r < 0)
                return log_error_errno(r, "Failed to write /etc/vconsole.conf: %m");

        log_info("/etc/vconsole.conf written.");
        return 1;
}

static bool timezone_is_valid_log_error(const char *name) {
        return timezone_is_valid(name, LOG_ERR);
}

static int prompt_timezone(int rfd) {
        _cleanup_strv_free_ char **zones = NULL;
        int r;

        assert(rfd >= 0);

        if (arg_timezone)
                return 0;

        r = read_credential("firstboot.timezone", (void**) &arg_timezone, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential firstboot.timezone, ignoring: %m");
        else {
                log_debug("Acquired timezone from credential.");
                return 0;
        }

        if (!arg_prompt_timezone) {
                log_debug("Prompting for timezone was not requested.");
                return 0;
        }

        r = get_timezones(&zones);
        if (r < 0)
                return log_error_errno(r, "Cannot query timezone list: %m");

        print_welcome(rfd);

        r = prompt_loop("Please enter timezone name or number",
                        zones, 30, timezone_is_valid_log_error, &arg_timezone);
        if (r < 0)
                return r;

        return 0;
}

static int process_timezone(int rfd) {
        _cleanup_close_ int pfd = -EBADF;
        _cleanup_free_ char *f = NULL;
        const char *e;
        int r;

        assert(rfd >= 0);

        pfd = chase_and_open_parent_at(rfd, "/etc/localtime",
                                       CHASE_AT_RESOLVE_IN_ROOT|CHASE_MKDIR_0755|CHASE_WARN|CHASE_NOFOLLOW,
                                       &f);
        if (pfd < 0)
                return log_error_errno(pfd, "Failed to chase /etc/localtime: %m");

        r = should_configure(pfd, f);
        if (r == 0)
                log_debug("Found /etc/localtime, assuming timezone has been configured.");
        if (r <= 0)
                return r;

        r = dir_fd_is_root(rfd);
        if (r < 0)
                return log_error_errno(r, "Failed to check if directory file descriptor is root: %m");

        if (arg_copy_timezone && r == 0) {
                _cleanup_free_ char *s = NULL;

                r = readlink_malloc("/etc/localtime", &s);
                if (r != -ENOENT) {
                        if (r < 0)
                                return log_error_errno(r, "Failed to read host's /etc/localtime: %m");

                        r = symlinkat_atomic_full(s, pfd, f, /* make_relative= */ false);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create /etc/localtime symlink: %m");

                        log_info("Copied host's /etc/localtime.");
                        return 0;
                }
        }

        r = prompt_timezone(rfd);
        if (r < 0)
                return r;

        if (isempty(arg_timezone))
                return 0;

        e = strjoina("../usr/share/zoneinfo/", arg_timezone);

        r = symlinkat_atomic_full(e, pfd, f, /* make_relative= */ false);
        if (r < 0)
                return log_error_errno(r, "Failed to create /etc/localtime symlink: %m");

        log_info("/etc/localtime written");
        return 0;
}

static int prompt_hostname(int rfd) {
        int r;

        assert(rfd >= 0);

        if (arg_hostname)
                return 0;

        if (!arg_prompt_hostname) {
                log_debug("Prompting for hostname was not requested.");
                return 0;
        }

        print_welcome(rfd);
        putchar('\n');

        for (;;) {
                _cleanup_free_ char *h = NULL;

                r = ask_string(&h, "%s Please enter hostname for new system (empty to skip): ", special_glyph(SPECIAL_GLYPH_TRIANGULAR_BULLET));
                if (r < 0)
                        return log_error_errno(r, "Failed to query hostname: %m");

                if (isempty(h)) {
                        log_warning("No hostname entered, skipping.");
                        break;
                }

                if (!hostname_is_valid(h, VALID_HOSTNAME_TRAILING_DOT)) {
                        log_error("Specified hostname invalid.");
                        continue;
                }

                /* Get rid of the trailing dot that we allow, but don't want to see */
                arg_hostname = hostname_cleanup(h);
                h = NULL;
                break;
        }

        return 0;
}

static int process_hostname(int rfd) {
        _cleanup_close_ int pfd = -EBADF;
        _cleanup_free_ char *f = NULL;
        int r;

        assert(rfd >= 0);

        pfd = chase_and_open_parent_at(rfd, "/etc/hostname",
                                       CHASE_AT_RESOLVE_IN_ROOT|CHASE_MKDIR_0755|CHASE_WARN,
                                       &f);
        if (pfd < 0)
                return log_error_errno(pfd, "Failed to chase /etc/hostname: %m");

        r = should_configure(pfd, f);
        if (r == 0)
                log_debug("Found /etc/hostname, assuming hostname has been configured.");
        if (r <= 0)
                return r;

        r = prompt_hostname(rfd);
        if (r < 0)
                return r;

        if (isempty(arg_hostname))
                return 0;

        r = write_string_file_at(pfd, f, arg_hostname,
                                 WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_SYNC|WRITE_STRING_FILE_ATOMIC);
        if (r < 0)
                return log_error_errno(r, "Failed to write /etc/hostname: %m");

        log_info("/etc/hostname written.");
        return 0;
}

static int process_machine_id(int rfd) {
        _cleanup_close_ int pfd = -EBADF;
        _cleanup_free_ char *f = NULL;
        int r;

        assert(rfd >= 0);

        pfd = chase_and_open_parent_at(rfd, "/etc/machine-id",
                                       CHASE_AT_RESOLVE_IN_ROOT|CHASE_MKDIR_0755|CHASE_WARN|CHASE_NOFOLLOW,
                                       &f);
        if (pfd < 0)
                return log_error_errno(pfd, "Failed to chase /etc/machine-id: %m");

        r = should_configure(pfd, f);
        if (r == 0)
                log_debug("Found /etc/machine-id, assuming machine-id has been configured.");
        if (r <= 0)
                return r;

        if (sd_id128_is_null(arg_machine_id)) {
                log_debug("Initialization of machine-id was not requested, skipping.");
                return 0;
        }

        r = write_string_file_at(pfd, "machine-id", SD_ID128_TO_STRING(arg_machine_id),
                                 WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_SYNC|WRITE_STRING_FILE_ATOMIC);
        if (r < 0)
                return log_error_errno(r, "Failed to write /etc/machine-id: %m");

        log_info("/etc/machine-id written.");
        return 0;
}

static int prompt_root_password(int rfd) {
        const char *msg1, *msg2;
        int r;

        assert(rfd >= 0);

        if (arg_root_password)
                return 0;

        if (get_credential_user_password("root", &arg_root_password, &arg_root_password_is_hashed) >= 0)
                return 0;

        if (!arg_prompt_root_password) {
                log_debug("Prompting for root password was not requested.");
                return 0;
        }

        print_welcome(rfd);
        putchar('\n');

        msg1 = strjoina(special_glyph(SPECIAL_GLYPH_TRIANGULAR_BULLET), " Please enter a new root password (empty to skip):");
        msg2 = strjoina(special_glyph(SPECIAL_GLYPH_TRIANGULAR_BULLET), " Please enter new root password again:");

        suggest_passwords();

        for (;;) {
                _cleanup_strv_free_erase_ char **a = NULL, **b = NULL;
                _cleanup_free_ char *error = NULL;

                r = ask_password_tty(-1, msg1, NULL, 0, 0, NULL, &a);
                if (r < 0)
                        return log_error_errno(r, "Failed to query root password: %m");
                if (strv_length(a) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Received multiple passwords, where we expected one.");

                if (isempty(*a)) {
                        log_warning("No password entered, skipping.");
                        break;
                }

                r = check_password_quality(*a, /* old */ NULL, "root", &error);
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_warning("Password quality check is not supported, proceeding anyway.");
                else if (r < 0)
                        return log_error_errno(r, "Failed to check password quality: %m");
                else if (r == 0)
                        log_warning("Password is weak, accepting anyway: %s", error);

                r = ask_password_tty(-1, msg2, NULL, 0, 0, NULL, &b);
                if (r < 0)
                        return log_error_errno(r, "Failed to query root password: %m");
                if (strv_length(b) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Received multiple passwords, where we expected one.");

                if (!streq(*a, *b)) {
                        log_error("Entered passwords did not match, please try again.");
                        continue;
                }

                arg_root_password = TAKE_PTR(*a);
                break;
        }

        return 0;
}

static int find_shell(int rfd, const char *path) {
        int r;

        assert(path);

        if (!valid_shell(path))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s is not a valid shell", path);

        r = chaseat(rfd, path, CHASE_AT_RESOLVE_IN_ROOT, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve shell %s: %m", path);

        return 0;
}

static int prompt_root_shell(int rfd) {
        int r;

        assert(rfd >= 0);

        if (arg_root_shell)
                return 0;

        r = read_credential("passwd.shell.root", (void**) &arg_root_shell, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential passwd.shell.root, ignoring: %m");
        else {
                log_debug("Acquired root shell from credential.");
                return 0;
        }

        if (!arg_prompt_root_shell) {
                log_debug("Prompting for root shell was not requested.");
                return 0;
        }

        print_welcome(rfd);
        putchar('\n');

        for (;;) {
                _cleanup_free_ char *s = NULL;

                r = ask_string(&s, "%s Please enter root shell for new system (empty to skip): ", special_glyph(SPECIAL_GLYPH_TRIANGULAR_BULLET));
                if (r < 0)
                        return log_error_errno(r, "Failed to query root shell: %m");

                if (isempty(s)) {
                        log_warning("No shell entered, skipping.");
                        break;
                }

                r = find_shell(rfd, s);
                if (r < 0)
                        continue;

                arg_root_shell = TAKE_PTR(s);
                break;
        }

        return 0;
}

static int write_root_passwd(int rfd, int etc_fd, const char *password, const char *shell) {
        _cleanup_fclose_ FILE *original = NULL, *passwd = NULL;
        _cleanup_(unlink_and_freep) char *passwd_tmp = NULL;
        int r;

        assert(password);

        r = fopen_temporary_at_label(etc_fd, "passwd", "passwd", &passwd, &passwd_tmp);
        if (r < 0)
                return r;

        r = xfopenat(etc_fd, "passwd", "re", O_NOFOLLOW, &original);
        if (r < 0 && r != -ENOENT)
                return r;

        if (original) {
                struct passwd *i;

                r = copy_rights(fileno(original), fileno(passwd));
                if (r < 0)
                        return r;

                while ((r = fgetpwent_sane(original, &i)) > 0) {

                        if (streq(i->pw_name, "root")) {
                                i->pw_passwd = (char *) password;
                                if (shell)
                                        i->pw_shell = (char *) shell;
                        }

                        r = putpwent_sane(i, passwd);
                        if (r < 0)
                                return r;
                }
                if (r < 0)
                        return r;

        } else {
                struct passwd root = {
                        .pw_name = (char *) "root",
                        .pw_passwd = (char *) password,
                        .pw_uid = 0,
                        .pw_gid = 0,
                        .pw_gecos = (char *) "Super User",
                        .pw_dir = (char *) "/root",
                        .pw_shell = (char *) (shell ?: default_root_shell_at(rfd)),
                };

                if (errno != ENOENT)
                        return -errno;

                r = fchmod(fileno(passwd), 0644);
                if (r < 0)
                        return -errno;

                r = putpwent_sane(&root, passwd);
                if (r < 0)
                        return r;
        }

        r = fflush_sync_and_check(passwd);
        if (r < 0)
                return r;

        r = renameat_and_apply_smack_floor_label(etc_fd, passwd_tmp, etc_fd, "passwd");
        if (r < 0)
                return r;

        return 0;
}

static int write_root_shadow(int etc_fd, const char *hashed_password) {
        _cleanup_fclose_ FILE *original = NULL, *shadow = NULL;
        _cleanup_(unlink_and_freep) char *shadow_tmp = NULL;
        int r;

        assert(hashed_password);

        r = fopen_temporary_at_label(etc_fd, "shadow", "shadow", &shadow, &shadow_tmp);
        if (r < 0)
                return r;

        r = xfopenat(etc_fd, "shadow", "re", O_NOFOLLOW, &original);
        if (r < 0 && r != -ENOENT)
                return r;

        if (original) {
                struct spwd *i;

                r = copy_rights(fileno(original), fileno(shadow));
                if (r < 0)
                        return r;

                while ((r = fgetspent_sane(original, &i)) > 0) {

                        if (streq(i->sp_namp, "root")) {
                                i->sp_pwdp = (char *) hashed_password;
                                i->sp_lstchg = (long) (now(CLOCK_REALTIME) / USEC_PER_DAY);
                        }

                        r = putspent_sane(i, shadow);
                        if (r < 0)
                                return r;
                }
                if (r < 0)
                        return r;

        } else {
                struct spwd root = {
                        .sp_namp = (char*) "root",
                        .sp_pwdp = (char *) hashed_password,
                        .sp_lstchg = (long) (now(CLOCK_REALTIME) / USEC_PER_DAY),
                        .sp_min = -1,
                        .sp_max = -1,
                        .sp_warn = -1,
                        .sp_inact = -1,
                        .sp_expire = -1,
                        .sp_flag = ULONG_MAX, /* this appears to be what everybody does ... */
                };

                if (errno != ENOENT)
                        return -errno;

                r = fchmod(fileno(shadow), 0000);
                if (r < 0)
                        return -errno;

                r = putspent_sane(&root, shadow);
                if (r < 0)
                        return r;
        }

        r = fflush_sync_and_check(shadow);
        if (r < 0)
                return r;

        r = renameat_and_apply_smack_floor_label(etc_fd, shadow_tmp, etc_fd, "shadow");
        if (r < 0)
                return r;

        return 0;
}

static int process_root_account(int rfd) {
        _cleanup_close_ int pfd = -EBADF;
        _cleanup_(release_lock_file) LockFile lock = LOCK_FILE_INIT;
        _cleanup_(erase_and_freep) char *_hashed_password = NULL;
        const char *password, *hashed_password;
        int k = 0, r;

        assert(rfd >= 0);

        pfd = chase_and_open_parent_at(rfd, "/etc/passwd",
                                       CHASE_AT_RESOLVE_IN_ROOT|CHASE_MKDIR_0755|CHASE_WARN|CHASE_NOFOLLOW,
                                       NULL);
        if (pfd < 0)
                return log_error_errno(pfd, "Failed to chase /etc/passwd: %m");

        /* Ensure that passwd and shadow are in the same directory and are not symlinks. */

        FOREACH_STRING(s, "passwd", "shadow") {
                r = verify_regular_at(pfd, s, /* follow = */ false);
                if (IN_SET(r, -EISDIR, -ELOOP, -EBADFD))
                        return log_error_errno(r, "/etc/%s is not a regular file", s);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to check whether /etc/%s is a regular file: %m", s);

                r = should_configure(pfd, s);
                if (r < 0)
                        return r;

                k += r;
        }

        if (k == 0) {
                log_debug("Found /etc/passwd and /etc/shadow, assuming root account has been initialized.");
                return 0;
        }

        /* Don't create/modify passwd and shadow if not asked */
        if (!(arg_root_password || arg_prompt_root_password || arg_copy_root_password || arg_delete_root_password ||
              arg_root_shell || arg_prompt_root_shell || arg_copy_root_shell)) {
                log_debug("Initialization of root account was not requested, skipping.");
                return 0;
        }

        r = make_lock_file_at(pfd, ETC_PASSWD_LOCK_FILENAME, LOCK_EX, &lock);
        if (r < 0)
                return log_error_errno(r, "Failed to take a lock on /etc/passwd: %m");

        k = dir_fd_is_root(rfd);
        if (k < 0)
                return log_error_errno(k, "Failed to check if directory file descriptor is root: %m");

        if (arg_copy_root_shell && k == 0) {
                struct passwd *p;

                errno = 0;
                p = getpwnam("root");
                if (!p)
                        return log_error_errno(errno_or_else(EIO), "Failed to find passwd entry for root: %m");

                r = free_and_strdup(&arg_root_shell, p->pw_shell);
                if (r < 0)
                        return log_oom();
        }

        r = prompt_root_shell(rfd);
        if (r < 0)
                return r;

        if (arg_copy_root_password && k == 0) {
                struct spwd *p;

                errno = 0;
                p = getspnam("root");
                if (!p)
                        return log_error_errno(errno_or_else(EIO), "Failed to find shadow entry for root: %m");

                r = free_and_strdup(&arg_root_password, p->sp_pwdp);
                if (r < 0)
                        return log_oom();

                arg_root_password_is_hashed = true;
        }

        r = prompt_root_password(rfd);
        if (r < 0)
                return r;

        if (arg_root_password && arg_root_password_is_hashed) {
                password = PASSWORD_SEE_SHADOW;
                hashed_password = arg_root_password;
        } else if (arg_root_password) {
                r = hash_password(arg_root_password, &_hashed_password);
                if (r < 0)
                        return log_error_errno(r, "Failed to hash password: %m");

                password = PASSWORD_SEE_SHADOW;
                hashed_password = _hashed_password;

        } else if (arg_delete_root_password)
                password = hashed_password = PASSWORD_NONE;
        else
                password = hashed_password = PASSWORD_LOCKED_AND_INVALID;

        r = write_root_passwd(rfd, pfd, password, arg_root_shell);
        if (r < 0)
                return log_error_errno(r, "Failed to write /etc/passwd: %m");

        log_info("/etc/passwd written.");

        r = write_root_shadow(pfd, hashed_password);
        if (r < 0)
                return log_error_errno(r, "Failed to write /etc/shadow: %m");

        log_info("/etc/shadow written.");
        return 0;
}

static int process_kernel_cmdline(int rfd) {
        _cleanup_close_ int pfd = -EBADF;
        _cleanup_free_ char *f = NULL;
        int r;

        assert(rfd >= 0);

        pfd = chase_and_open_parent_at(rfd, "/etc/kernel/cmdline",
                                       CHASE_AT_RESOLVE_IN_ROOT|CHASE_MKDIR_0755|CHASE_WARN|CHASE_NOFOLLOW,
                                       &f);
        if (pfd < 0)
                return log_error_errno(pfd, "Failed to chase /etc/kernel/cmdline: %m");

        r = should_configure(pfd, f);
        if (r == 0)
                log_debug("Found /etc/kernel/cmdline, assuming kernel command line has been configured.");
        if (r <= 0)
                return r;

        if (!arg_kernel_cmdline) {
                log_debug("Creation of /etc/kernel/cmdline was not requested, skipping.");
                return 0;
        }

        r = write_string_file_at(pfd, "cmdline", arg_kernel_cmdline,
                                 WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_SYNC|WRITE_STRING_FILE_ATOMIC);
        if (r < 0)
                return log_error_errno(r, "Failed to write /etc/kernel/cmdline: %m");

        log_info("/etc/kernel/cmdline written.");
        return 0;
}

static int reset_one(int rfd, const char *path) {
        _cleanup_close_ int pfd = -EBADF;
        _cleanup_free_ char *f = NULL;

        assert(rfd >= 0);
        assert(path);

        pfd = chase_and_open_parent_at(rfd, path, CHASE_AT_RESOLVE_IN_ROOT|CHASE_WARN|CHASE_NOFOLLOW, &f);
        if (pfd == -ENOENT)
                return 0;
        if (pfd < 0)
                return log_error_errno(pfd, "Failed to resolve %s: %m", path);

        if (unlinkat(pfd, f, 0) < 0)
                return errno == ENOENT ? 0 : log_error_errno(errno, "Failed to remove %s: %m", path);

        log_info("Removed %s", path);
        return 0;
}

static int process_reset(int rfd) {
        int r;

        assert(rfd >= 0);

        if (!arg_reset)
                return 0;

        FOREACH_STRING(p,
                       "/etc/locale.conf",
                       "/etc/vconsole.conf",
                       "/etc/hostname",
                       "/etc/machine-id",
                       "/etc/kernel/cmdline",
                       "/etc/localtime") {
                r = reset_one(rfd, p);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-firstboot", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "Configures basic settings of the system.\n\n"
               "  -h --help                       Show this help\n"
               "     --version                    Show package version\n"
               "     --root=PATH                  Operate on an alternate filesystem root\n"
               "     --image=PATH                 Operate on disk image as filesystem root\n"
               "     --image-policy=POLICY        Specify disk image dissection policy\n"
               "     --locale=LOCALE              Set primary locale (LANG=)\n"
               "     --locale-messages=LOCALE     Set message locale (LC_MESSAGES=)\n"
               "     --keymap=KEYMAP              Set keymap\n"
               "     --timezone=TIMEZONE          Set timezone\n"
               "     --hostname=NAME              Set hostname\n"
               "     --setup-machine-id           Set a random machine ID\n"
               "     --machine-ID=ID              Set specified machine ID\n"
               "     --root-password=PASSWORD     Set root password from plaintext password\n"
               "     --root-password-file=FILE    Set root password from file\n"
               "     --root-password-hashed=HASH  Set root password from hashed password\n"
               "     --root-shell=SHELL           Set root shell\n"
               "     --prompt-locale              Prompt the user for locale settings\n"
               "     --prompt-keymap              Prompt the user for keymap settings\n"
               "     --prompt-timezone            Prompt the user for timezone\n"
               "     --prompt-hostname            Prompt the user for hostname\n"
               "     --prompt-root-password       Prompt the user for root password\n"
               "     --prompt-root-shell          Prompt the user for root shell\n"
               "     --prompt                     Prompt for all of the above\n"
               "     --copy-locale                Copy locale from host\n"
               "     --copy-keymap                Copy keymap from host\n"
               "     --copy-timezone              Copy timezone from host\n"
               "     --copy-root-password         Copy root password from host\n"
               "     --copy-root-shell            Copy root shell from host\n"
               "     --copy                       Copy locale, keymap, timezone, root password\n"
               "     --force                      Overwrite existing files\n"
               "     --delete-root-password       Delete root password\n"
               "     --welcome=no                 Disable the welcome text\n"
               "     --reset                      Remove existing files\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_IMAGE_POLICY,
                ARG_LOCALE,
                ARG_LOCALE_MESSAGES,
                ARG_KEYMAP,
                ARG_TIMEZONE,
                ARG_HOSTNAME,
                ARG_SETUP_MACHINE_ID,
                ARG_MACHINE_ID,
                ARG_ROOT_PASSWORD,
                ARG_ROOT_PASSWORD_FILE,
                ARG_ROOT_PASSWORD_HASHED,
                ARG_ROOT_SHELL,
                ARG_KERNEL_COMMAND_LINE,
                ARG_PROMPT,
                ARG_PROMPT_LOCALE,
                ARG_PROMPT_KEYMAP,
                ARG_PROMPT_TIMEZONE,
                ARG_PROMPT_HOSTNAME,
                ARG_PROMPT_ROOT_PASSWORD,
                ARG_PROMPT_ROOT_SHELL,
                ARG_COPY,
                ARG_COPY_LOCALE,
                ARG_COPY_KEYMAP,
                ARG_COPY_TIMEZONE,
                ARG_COPY_ROOT_PASSWORD,
                ARG_COPY_ROOT_SHELL,
                ARG_FORCE,
                ARG_DELETE_ROOT_PASSWORD,
                ARG_WELCOME,
                ARG_RESET,
        };

        static const struct option options[] = {
                { "help",                    no_argument,       NULL, 'h'                         },
                { "version",                 no_argument,       NULL, ARG_VERSION                 },
                { "root",                    required_argument, NULL, ARG_ROOT                    },
                { "image",                   required_argument, NULL, ARG_IMAGE                   },
                { "image-policy",            required_argument, NULL, ARG_IMAGE_POLICY            },
                { "locale",                  required_argument, NULL, ARG_LOCALE                  },
                { "locale-messages",         required_argument, NULL, ARG_LOCALE_MESSAGES         },
                { "keymap",                  required_argument, NULL, ARG_KEYMAP                  },
                { "timezone",                required_argument, NULL, ARG_TIMEZONE                },
                { "hostname",                required_argument, NULL, ARG_HOSTNAME                },
                { "setup-machine-id",        no_argument,       NULL, ARG_SETUP_MACHINE_ID        },
                { "machine-id",              required_argument, NULL, ARG_MACHINE_ID              },
                { "root-password",           required_argument, NULL, ARG_ROOT_PASSWORD           },
                { "root-password-file",      required_argument, NULL, ARG_ROOT_PASSWORD_FILE      },
                { "root-password-hashed",    required_argument, NULL, ARG_ROOT_PASSWORD_HASHED    },
                { "root-shell",              required_argument, NULL, ARG_ROOT_SHELL              },
                { "kernel-command-line",     required_argument, NULL, ARG_KERNEL_COMMAND_LINE     },
                { "prompt",                  no_argument,       NULL, ARG_PROMPT                  },
                { "prompt-locale",           no_argument,       NULL, ARG_PROMPT_LOCALE           },
                { "prompt-keymap",           no_argument,       NULL, ARG_PROMPT_KEYMAP           },
                { "prompt-timezone",         no_argument,       NULL, ARG_PROMPT_TIMEZONE         },
                { "prompt-hostname",         no_argument,       NULL, ARG_PROMPT_HOSTNAME         },
                { "prompt-root-password",    no_argument,       NULL, ARG_PROMPT_ROOT_PASSWORD    },
                { "prompt-root-shell",       no_argument,       NULL, ARG_PROMPT_ROOT_SHELL       },
                { "copy",                    no_argument,       NULL, ARG_COPY                    },
                { "copy-locale",             no_argument,       NULL, ARG_COPY_LOCALE             },
                { "copy-keymap",             no_argument,       NULL, ARG_COPY_KEYMAP             },
                { "copy-timezone",           no_argument,       NULL, ARG_COPY_TIMEZONE           },
                { "copy-root-password",      no_argument,       NULL, ARG_COPY_ROOT_PASSWORD      },
                { "copy-root-shell",         no_argument,       NULL, ARG_COPY_ROOT_SHELL         },
                { "force",                   no_argument,       NULL, ARG_FORCE                   },
                { "delete-root-password",    no_argument,       NULL, ARG_DELETE_ROOT_PASSWORD    },
                { "welcome",                 required_argument, NULL, ARG_WELCOME                 },
                { "reset",                   no_argument,       NULL, ARG_RESET                   },
                {}
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_ROOT:
                        r = parse_path_argument(optarg, true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE:
                        r = parse_path_argument(optarg, false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE_POLICY:
                        r = parse_image_policy_argument(optarg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                case ARG_LOCALE:
                        r = free_and_strdup(&arg_locale, optarg);
                        if (r < 0)
                                return log_oom();

                        break;

                case ARG_LOCALE_MESSAGES:
                        r = free_and_strdup(&arg_locale_messages, optarg);
                        if (r < 0)
                                return log_oom();

                        break;

                case ARG_KEYMAP:
                        if (!keymap_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Keymap %s is not valid.", optarg);

                        r = free_and_strdup(&arg_keymap, optarg);
                        if (r < 0)
                                return log_oom();

                        break;

                case ARG_TIMEZONE:
                        if (!timezone_is_valid(optarg, LOG_ERR))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Timezone %s is not valid.", optarg);

                        r = free_and_strdup(&arg_timezone, optarg);
                        if (r < 0)
                                return log_oom();

                        break;

                case ARG_ROOT_PASSWORD:
                        r = free_and_strdup(&arg_root_password, optarg);
                        if (r < 0)
                                return log_oom();

                        arg_root_password_is_hashed = false;
                        break;

                case ARG_ROOT_PASSWORD_FILE:
                        arg_root_password = mfree(arg_root_password);

                        r = read_one_line_file(optarg, &arg_root_password);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read %s: %m", optarg);

                        arg_root_password_is_hashed = false;
                        break;

                case ARG_ROOT_PASSWORD_HASHED:
                        r = free_and_strdup(&arg_root_password, optarg);
                        if (r < 0)
                                return log_oom();

                        arg_root_password_is_hashed = true;
                        break;

                case ARG_ROOT_SHELL:
                        r = free_and_strdup(&arg_root_shell, optarg);
                        if (r < 0)
                                return log_oom();

                        break;

                case ARG_HOSTNAME:
                        if (!hostname_is_valid(optarg, VALID_HOSTNAME_TRAILING_DOT))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Host name %s is not valid.", optarg);

                        r = free_and_strdup(&arg_hostname, optarg);
                        if (r < 0)
                                return log_oom();

                        hostname_cleanup(arg_hostname);
                        break;

                case ARG_SETUP_MACHINE_ID:
                        r = sd_id128_randomize(&arg_machine_id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to generate randomized machine ID: %m");

                        break;

                case ARG_MACHINE_ID:
                        r = sd_id128_from_string(optarg, &arg_machine_id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse machine id %s.", optarg);

                        break;

                case ARG_KERNEL_COMMAND_LINE:
                        r = free_and_strdup(&arg_kernel_cmdline, optarg);
                        if (r < 0)
                                return log_oom();

                        break;

                case ARG_PROMPT:
                        arg_prompt_locale = arg_prompt_keymap = arg_prompt_timezone = arg_prompt_hostname =
                                arg_prompt_root_password = arg_prompt_root_shell = true;
                        break;

                case ARG_PROMPT_LOCALE:
                        arg_prompt_locale = true;
                        break;

                case ARG_PROMPT_KEYMAP:
                        arg_prompt_keymap = true;
                        break;

                case ARG_PROMPT_TIMEZONE:
                        arg_prompt_timezone = true;
                        break;

                case ARG_PROMPT_HOSTNAME:
                        arg_prompt_hostname = true;
                        break;

                case ARG_PROMPT_ROOT_PASSWORD:
                        arg_prompt_root_password = true;
                        break;

                case ARG_PROMPT_ROOT_SHELL:
                        arg_prompt_root_shell = true;
                        break;

                case ARG_COPY:
                        arg_copy_locale = arg_copy_keymap = arg_copy_timezone = arg_copy_root_password =
                                arg_copy_root_shell = true;
                        break;

                case ARG_COPY_LOCALE:
                        arg_copy_locale = true;
                        break;

                case ARG_COPY_KEYMAP:
                        arg_copy_keymap = true;
                        break;

                case ARG_COPY_TIMEZONE:
                        arg_copy_timezone = true;
                        break;

                case ARG_COPY_ROOT_PASSWORD:
                        arg_copy_root_password = true;
                        break;

                case ARG_COPY_ROOT_SHELL:
                        arg_copy_root_shell = true;
                        break;

                case ARG_FORCE:
                        arg_force = true;
                        break;

                case ARG_DELETE_ROOT_PASSWORD:
                        arg_delete_root_password = true;
                        break;

                case ARG_WELCOME:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --welcome= argument: %s", optarg);

                        arg_welcome = r;
                        break;

                case ARG_RESET:
                        arg_reset = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_delete_root_password && (arg_copy_root_password || arg_root_password || arg_prompt_root_password))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--delete-root-password cannot be combined with other root password options.");

        if (arg_image && arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--root= and --image= cannot be used together.");

        if (!sd_id128_is_null(arg_machine_id) && !(arg_image || arg_root) && !arg_force)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--machine-id=/--setup-machine-id only works with --root= or --image=.");

        return 1;
}

static int reload_system_manager(sd_bus **bus) {
        int r;

        assert(bus);

        if (!*bus) {
                r = bus_connect_transport_systemd(BUS_TRANSPORT_LOCAL, NULL, RUNTIME_SCOPE_SYSTEM, bus);
                if (r < 0)
                        return bus_log_connect_error(r, BUS_TRANSPORT_LOCAL);
        }

        r = bus_service_manager_reload(*bus);
        if (r < 0)
                return r;

        log_info("Requested manager reload to apply locale configuration.");
        return 0;
}

static int reload_vconsole(sd_bus **bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        const char *object;
        int r;

        assert(bus);

        if (!*bus) {
                r = bus_connect_transport_systemd(BUS_TRANSPORT_LOCAL, NULL, RUNTIME_SCOPE_SYSTEM, bus);
                if (r < 0)
                        return bus_log_connect_error(r, BUS_TRANSPORT_LOCAL);
        }

        r = bus_wait_for_jobs_new(*bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch jobs: %m");

        r = bus_call_method(*bus, bus_systemd_mgr, "RestartUnit", &error, &reply,
                            "ss", "systemd-vconsole-setup.service", "replace");
        if (r < 0)
                return log_error_errno(r, "Failed to issue method call: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, object, BUS_WAIT_JOBS_LOG_ERROR, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for systemd-vconsole-setup.service/restart: %m");
        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        _cleanup_close_ int rfd = -EBADF;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup();

        umask(0022);

        bool offline = arg_root || arg_image;

        if (!offline) {
                /* If we are called without --root=/--image= let's honour the systemd.firstboot kernel
                 * command line option, because we are called to provision the host with basic settings (as
                 * opposed to some other file system tree/image) */

                bool enabled;
                r = proc_cmdline_get_bool("systemd.firstboot", /* flags = */ 0, &enabled);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse systemd.firstboot= kernel command line argument, ignoring: %m");
                if (r > 0 && !enabled) {
                        log_debug("Found systemd.firstboot=no kernel command line argument, turning off all prompts.");
                        arg_prompt_locale = arg_prompt_keymap = arg_prompt_timezone = arg_prompt_hostname = arg_prompt_root_password = arg_prompt_root_shell = false;
                }
        }

        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                arg_image_policy,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_VALIDATE_OS |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_FSCK |
                                DISSECT_IMAGE_GROWFS,
                                &mounted_dir,
                                &rfd,
                                &loop_device);
                if (r < 0)
                        return r;

                arg_root = strdup(mounted_dir);
                if (!arg_root)
                        return log_oom();
        } else {
                rfd = open(empty_to_root(arg_root), O_DIRECTORY|O_CLOEXEC);
                if (rfd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", empty_to_root(arg_root));
        }

        LOG_SET_PREFIX(arg_image ?: arg_root);

        /* We check these conditions here instead of in parse_argv() so that we can take the root directory
         * into account. */

        if (arg_locale && !locale_is_ok(rfd, arg_locale))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Locale %s is not installed.", arg_locale);
        if (arg_locale_messages && !locale_is_ok(rfd, arg_locale_messages))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Locale %s is not installed.", arg_locale_messages);

        if (arg_root_shell) {
                r = find_shell(rfd, arg_root_shell);
                if (r < 0)
                        return r;
        }

        r = process_reset(rfd);
        if (r < 0)
                return r;

        r = process_locale(rfd);
        if (r < 0)
                return r;
        if (r > 0 && !offline)
                (void) reload_system_manager(&bus);

        r = process_keymap(rfd);
        if (r < 0)
                return r;
        if (r > 0 && !offline)
                (void) reload_vconsole(&bus);

        r = process_timezone(rfd);
        if (r < 0)
                return r;

        r = process_hostname(rfd);
        if (r < 0)
                return r;

        r = process_machine_id(rfd);
        if (r < 0)
                return r;

        r = process_root_account(rfd);
        if (r < 0)
                return r;

        r = process_kernel_cmdline(rfd);
        if (r < 0)
                return r;

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
