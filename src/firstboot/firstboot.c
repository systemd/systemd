/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
#include <linux/loop.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "chase-symlinks.h"
#include "copy.h"
#include "creds-util.h"
#include "dissect-image.h"
#include "env-file.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "hostname-util.h"
#include "kbd-util.h"
#include "libcrypt-util.h"
#include "locale-util.h"
#include "main-func.h"
#include "memory-util.h"
#include "mkdir.h"
#include "mount-util.h"
#include "os-util.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "pwquality-util.h"
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

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_locale, freep);
STATIC_DESTRUCTOR_REGISTER(arg_locale_messages, freep);
STATIC_DESTRUCTOR_REGISTER(arg_keymap, freep);
STATIC_DESTRUCTOR_REGISTER(arg_timezone, freep);
STATIC_DESTRUCTOR_REGISTER(arg_hostname, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_password, erase_and_freep);

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

static void print_welcome(void) {
        _cleanup_free_ char *pretty_name = NULL, *ansi_color = NULL;
        static bool done = false;
        const char *pn, *ac;
        int r;

        if (!arg_welcome)
                return;

        if (done)
                return;

        r = parse_os_release(
                        arg_root,
                        "PRETTY_NAME", &pretty_name,
                        "ANSI_COLOR", &ansi_color);
        if (r < 0)
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to read os-release file, ignoring: %m");

        pn = isempty(pretty_name) ? "Linux" : pretty_name;
        ac = isempty(ansi_color) ? "0" : ansi_color;

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

                for (j = 0; j < n_columns; j ++) {
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

static bool locale_is_ok(const char *name) {

        if (arg_root)
                return locale_is_valid(name);

        return locale_is_installed(name) > 0;
}

static int prompt_locale(void) {
        _cleanup_strv_free_ char **locales = NULL;
        bool acquired_from_creds = false;
        int r;

        if (arg_locale || arg_locale_messages)
                return 0;

        r = read_credential("firstboot.locale", (void**) &arg_locale, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential firstboot.locale, ignoring: %m");
        else
                acquired_from_creds = true;

        r = read_credential("firstboot.locale-messages", (void**) &arg_locale_messages, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential firstboot.locale-message, ignoring: %m");
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
                print_welcome();

                r = prompt_loop("Please enter system locale name or number",
                                locales, 60, locale_is_ok, &arg_locale);
                if (r < 0)
                        return r;

                if (isempty(arg_locale))
                        return 0;

                r = prompt_loop("Please enter system message locale name or number",
                                locales, 60, locale_is_ok, &arg_locale_messages);
                if (r < 0)
                        return r;

                /* Suppress the messages setting if it's the same as the main locale anyway */
                if (streq_ptr(arg_locale, arg_locale_messages))
                        arg_locale_messages = mfree(arg_locale_messages);
        }

        return 0;
}

static int process_locale(void) {
        const char *etc_localeconf;
        char* locales[3];
        unsigned i = 0;
        int r;

        etc_localeconf = prefix_roota(arg_root, "/etc/locale.conf");
        if (laccess(etc_localeconf, F_OK) >= 0 && !arg_force) {
                log_debug("Found %s, assuming locale information has been configured.",
                          etc_localeconf);
                return 0;
        }

        if (arg_copy_locale && arg_root) {

                (void) mkdir_parents(etc_localeconf, 0755);
                r = copy_file("/etc/locale.conf", etc_localeconf, 0, 0644, 0, 0, COPY_REFLINK);
                if (r != -ENOENT) {
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy %s: %m", etc_localeconf);

                        log_info("%s copied.", etc_localeconf);
                        return 0;
                }
        }

        r = prompt_locale();
        if (r < 0)
                return r;

        if (!isempty(arg_locale))
                locales[i++] = strjoina("LANG=", arg_locale);
        if (!isempty(arg_locale_messages) && !streq_ptr(arg_locale_messages, arg_locale))
                locales[i++] = strjoina("LC_MESSAGES=", arg_locale_messages);

        if (i == 0)
                return 0;

        locales[i] = NULL;

        (void) mkdir_parents(etc_localeconf, 0755);
        r = write_env_file(etc_localeconf, locales);
        if (r < 0)
                return log_error_errno(r, "Failed to write %s: %m", etc_localeconf);

        log_info("%s written.", etc_localeconf);
        return 0;
}

static int prompt_keymap(void) {
        _cleanup_strv_free_ char **kmaps = NULL;
        int r;

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

        print_welcome();

        return prompt_loop("Please enter system keymap name or number",
                           kmaps, 60, keymap_is_valid, &arg_keymap);
}

static int process_keymap(void) {
        const char *etc_vconsoleconf;
        char **keymap;
        int r;

        etc_vconsoleconf = prefix_roota(arg_root, "/etc/vconsole.conf");
        if (laccess(etc_vconsoleconf, F_OK) >= 0 && !arg_force) {
                log_debug("Found %s, assuming console has been configured.",
                          etc_vconsoleconf);
                return 0;
        }

        if (arg_copy_keymap && arg_root) {

                (void) mkdir_parents(etc_vconsoleconf, 0755);
                r = copy_file("/etc/vconsole.conf", etc_vconsoleconf, 0, 0644, 0, 0, COPY_REFLINK);
                if (r != -ENOENT) {
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy %s: %m", etc_vconsoleconf);

                        log_info("%s copied.", etc_vconsoleconf);
                        return 0;
                }
        }

        r = prompt_keymap();
        if (r == -ENOENT)
                return 0; /* don't fail if no keymaps are installed */
        if (r < 0)
                return r;

        if (isempty(arg_keymap))
                return 0;

        keymap = STRV_MAKE(strjoina("KEYMAP=", arg_keymap));

        r = mkdir_parents(etc_vconsoleconf, 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create the parent directory of %s: %m", etc_vconsoleconf);

        r = write_env_file(etc_vconsoleconf, keymap);
        if (r < 0)
                return log_error_errno(r, "Failed to write %s: %m", etc_vconsoleconf);

        log_info("%s written.", etc_vconsoleconf);
        return 0;
}

static bool timezone_is_valid_log_error(const char *name) {
        return timezone_is_valid(name, LOG_ERR);
}

static int prompt_timezone(void) {
        _cleanup_strv_free_ char **zones = NULL;
        int r;

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

        print_welcome();

        r = prompt_loop("Please enter timezone name or number",
                        zones, 30, timezone_is_valid_log_error, &arg_timezone);
        if (r < 0)
                return r;

        return 0;
}

static int process_timezone(void) {
        const char *etc_localtime, *e;
        int r;

        etc_localtime = prefix_roota(arg_root, "/etc/localtime");
        if (laccess(etc_localtime, F_OK) >= 0 && !arg_force) {
                log_debug("Found %s, assuming timezone has been configured.",
                          etc_localtime);
                return 0;
        }

        if (arg_copy_timezone && arg_root) {
                _cleanup_free_ char *p = NULL;

                r = readlink_malloc("/etc/localtime", &p);
                if (r != -ENOENT) {
                        if (r < 0)
                                return log_error_errno(r, "Failed to read host timezone: %m");

                        (void) mkdir_parents(etc_localtime, 0755);
                        r = symlink_atomic(p, etc_localtime);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create %s symlink: %m", etc_localtime);

                        log_info("%s copied.", etc_localtime);
                        return 0;
                }
        }

        r = prompt_timezone();
        if (r < 0)
                return r;

        if (isempty(arg_timezone))
                return 0;

        e = strjoina("../usr/share/zoneinfo/", arg_timezone);

        (void) mkdir_parents(etc_localtime, 0755);
        r = symlink_atomic(e, etc_localtime);
        if (r < 0)
                return log_error_errno(r, "Failed to create %s symlink: %m", etc_localtime);

        log_info("%s written", etc_localtime);
        return 0;
}

static int prompt_hostname(void) {
        int r;

        if (arg_hostname)
                return 0;

        if (!arg_prompt_hostname) {
                log_debug("Prompting for hostname was not requested.");
                return 0;
        }

        print_welcome();
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

static int process_hostname(void) {
        const char *etc_hostname;
        int r;

        etc_hostname = prefix_roota(arg_root, "/etc/hostname");
        if (laccess(etc_hostname, F_OK) >= 0 && !arg_force) {
                log_debug("Found %s, assuming hostname has been configured.",
                          etc_hostname);
                return 0;
        }

        r = prompt_hostname();
        if (r < 0)
                return r;

        if (isempty(arg_hostname))
                return 0;

        r = write_string_file(etc_hostname, arg_hostname,
                              WRITE_STRING_FILE_CREATE | WRITE_STRING_FILE_SYNC | WRITE_STRING_FILE_MKDIR_0755 |
                              (arg_force ? WRITE_STRING_FILE_ATOMIC : 0));
        if (r < 0)
                return log_error_errno(r, "Failed to write %s: %m", etc_hostname);

        log_info("%s written.", etc_hostname);
        return 0;
}

static int process_machine_id(void) {
        const char *etc_machine_id;
        int r;

        etc_machine_id = prefix_roota(arg_root, "/etc/machine-id");
        if (laccess(etc_machine_id, F_OK) >= 0 && !arg_force) {
                log_debug("Found %s, assuming machine-id has been configured.",
                          etc_machine_id);
                return 0;
        }

        if (sd_id128_is_null(arg_machine_id)) {
                log_debug("Initialization of machine-id was not requested, skipping.");
                return 0;
        }

        r = write_string_file(etc_machine_id, SD_ID128_TO_STRING(arg_machine_id),
                              WRITE_STRING_FILE_CREATE | WRITE_STRING_FILE_SYNC | WRITE_STRING_FILE_MKDIR_0755 |
                              (arg_force ? WRITE_STRING_FILE_ATOMIC : 0));
        if (r < 0)
                return log_error_errno(r, "Failed to write machine id: %m");

        log_info("%s written.", etc_machine_id);
        return 0;
}

static int prompt_root_password(void) {
        const char *msg1, *msg2;
        int r;

        if (arg_root_password)
                return 0;

        if (get_credential_user_password("root", &arg_root_password, &arg_root_password_is_hashed) >= 0)
                return 0;

        if (!arg_prompt_root_password) {
                log_debug("Prompting for root password was not requested.");
                return 0;
        }

        print_welcome();
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

                r = quality_check_password(*a, "root", &error);
                if (r < 0)
                        return log_error_errno(r, "Failed to check quality of password: %m");
                if (r == 0)
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

static int find_shell(const char *path, const char *root) {
        int r;

        assert(path);

        if (!valid_shell(path))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s is not a valid shell", path);

        r = chase_symlinks(path, root, CHASE_PREFIX_ROOT, NULL, NULL);
        if (r < 0) {
                const char *p;
                p = prefix_roota(root, path);
                return log_error_errno(r, "Failed to resolve shell %s: %m", p);
        }

        return 0;
}

static int prompt_root_shell(void) {
        int r;

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

        print_welcome();
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

                r = find_shell(s, arg_root);
                if (r < 0)
                        continue;

                arg_root_shell = TAKE_PTR(s);
                break;
        }

        return 0;
}

static int write_root_passwd(const char *passwd_path, const char *password, const char *shell) {
        _cleanup_fclose_ FILE *original = NULL, *passwd = NULL;
        _cleanup_(unlink_and_freep) char *passwd_tmp = NULL;
        int r;

        assert(password);

        r = fopen_temporary_label("/etc/passwd", passwd_path, &passwd, &passwd_tmp);
        if (r < 0)
                return r;

        original = fopen(passwd_path, "re");
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
                        .pw_shell = (char *) (shell ?: default_root_shell(arg_root)),
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

        r = rename_and_apply_smack_floor_label(passwd_tmp, passwd_path);
        if (r < 0)
                return r;

        return 0;
}

static int write_root_shadow(const char *shadow_path, const char *hashed_password) {
        _cleanup_fclose_ FILE *original = NULL, *shadow = NULL;
        _cleanup_(unlink_and_freep) char *shadow_tmp = NULL;
        int r;

        assert(hashed_password);

        r = fopen_temporary_label("/etc/shadow", shadow_path, &shadow, &shadow_tmp);
        if (r < 0)
                return r;

        original = fopen(shadow_path, "re");
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

        r = rename_and_apply_smack_floor_label(shadow_tmp, shadow_path);
        if (r < 0)
                return r;

        return 0;
}

static int process_root_account(void) {
        _cleanup_close_ int lock = -1;
        _cleanup_(erase_and_freep) char *_hashed_password = NULL;
        const char *password, *hashed_password;
        const char *etc_passwd, *etc_shadow;
        int r;

        etc_passwd = prefix_roota(arg_root, "/etc/passwd");
        etc_shadow = prefix_roota(arg_root, "/etc/shadow");

        if (laccess(etc_passwd, F_OK) >= 0 && laccess(etc_shadow, F_OK) >= 0 && !arg_force) {
                log_debug("Found %s and %s, assuming root account has been initialized.",
                          etc_passwd, etc_shadow);
                return 0;
        }

        /* Don't create/modify passwd and shadow if not asked */
        if (!(arg_root_password || arg_prompt_root_password || arg_copy_root_password || arg_delete_root_password ||
              arg_root_shell || arg_prompt_root_shell || arg_copy_root_shell)) {
                log_debug("Initialization of root account was not requested, skipping.");
                return 0;
        }

        (void) mkdir_parents(etc_passwd, 0755);

        lock = take_etc_passwd_lock(arg_root);
        if (lock < 0)
                return log_error_errno(lock, "Failed to take a lock on %s: %m", etc_passwd);

        if (arg_copy_root_shell && arg_root) {
                struct passwd *p;

                errno = 0;
                p = getpwnam("root");
                if (!p)
                        return log_error_errno(errno_or_else(EIO), "Failed to find passwd entry for root: %m");

                r = free_and_strdup(&arg_root_shell, p->pw_shell);
                if (r < 0)
                        return log_oom();
        }

        r = prompt_root_shell();
        if (r < 0)
                return r;

        if (arg_copy_root_password && arg_root) {
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

        r = prompt_root_password();
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

        r = write_root_passwd(etc_passwd, password, arg_root_shell);
        if (r < 0)
                return log_error_errno(r, "Failed to write %s: %m", etc_passwd);

        log_info("%s written", etc_passwd);

        r = write_root_shadow(etc_shadow, hashed_password);
        if (r < 0)
                return log_error_errno(r, "Failed to write %s: %m", etc_shadow);

        log_info("%s written.", etc_shadow);
        return 0;
}

static int process_kernel_cmdline(void) {
        const char *etc_kernel_cmdline;
        int r;

        etc_kernel_cmdline = prefix_roota(arg_root, "/etc/kernel/cmdline");
        if (laccess(etc_kernel_cmdline, F_OK) >= 0 && !arg_force) {
                log_debug("Found %s, assuming kernel has been configured.",
                          etc_kernel_cmdline);
                return 0;
        }

        if (!arg_kernel_cmdline) {
                log_debug("Creation of /etc/kernel/cmdline was not requested, skipping.");
                return 0;
        }

        r = write_string_file(etc_kernel_cmdline, arg_kernel_cmdline,
                              WRITE_STRING_FILE_CREATE | WRITE_STRING_FILE_SYNC | WRITE_STRING_FILE_MKDIR_0755 |
                              (arg_force ? WRITE_STRING_FILE_ATOMIC : 0));
        if (r < 0)
                return log_error_errno(r, "Failed to write %s: %m", etc_kernel_cmdline);

        log_info("%s written.", etc_kernel_cmdline);
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
               "     --image=PATH                 Operate on an alternate filesystem image\n"
               "     --locale=LOCALE              Set primary locale (LANG=)\n"
               "     --locale-messages=LOCALE     Set message locale (LC_MESSAGES=)\n"
               "     --keymap=KEYMAP              Set keymap\n"
               "     --timezone=TIMEZONE          Set timezone\n"
               "     --hostname=NAME              Set hostname\n"
               "     --machine-ID=ID              Set machine ID\n"
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
               "     --setup-machine-id           Generate a new random machine ID\n"
               "     --force                      Overwrite existing files\n"
               "     --delete-root-password       Delete root password\n"
               "     --welcome=no                 Disable the welcome text\n"
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
                ARG_LOCALE,
                ARG_LOCALE_MESSAGES,
                ARG_KEYMAP,
                ARG_TIMEZONE,
                ARG_HOSTNAME,
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
                ARG_SETUP_MACHINE_ID,
                ARG_FORCE,
                ARG_DELETE_ROOT_PASSWORD,
                ARG_WELCOME,
        };

        static const struct option options[] = {
                { "help",                    no_argument,       NULL, 'h'                         },
                { "version",                 no_argument,       NULL, ARG_VERSION                 },
                { "root",                    required_argument, NULL, ARG_ROOT                    },
                { "image",                   required_argument, NULL, ARG_IMAGE                   },
                { "locale",                  required_argument, NULL, ARG_LOCALE                  },
                { "locale-messages",         required_argument, NULL, ARG_LOCALE_MESSAGES         },
                { "keymap",                  required_argument, NULL, ARG_KEYMAP                  },
                { "timezone",                required_argument, NULL, ARG_TIMEZONE                },
                { "hostname",                required_argument, NULL, ARG_HOSTNAME                },
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
                { "setup-machine-id",        no_argument,       NULL, ARG_SETUP_MACHINE_ID        },
                { "force",                   no_argument,       NULL, ARG_FORCE                   },
                { "delete-root-password",    no_argument,       NULL, ARG_DELETE_ROOT_PASSWORD    },
                { "welcome",                 required_argument, NULL, ARG_WELCOME                 },
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
                        r = find_shell(optarg, arg_root);
                        if (r < 0)
                                return r;

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

                case ARG_SETUP_MACHINE_ID:
                        r = sd_id128_randomize(&arg_machine_id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to generate randomized machine ID: %m");

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

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        /* We check if the specified locale strings are valid down here, so that we can take --root= into
         * account when looking for the locale files. */

        if (arg_locale && !locale_is_ok(arg_locale))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Locale %s is not installed.", arg_locale);
        if (arg_locale_messages && !locale_is_ok(arg_locale_messages))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Locale %s is not installed.", arg_locale_messages);

        if (arg_delete_root_password && (arg_copy_root_password || arg_root_password || arg_prompt_root_password))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--delete-root-password cannot be combined with other root password options");

        if (arg_image && arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *unlink_dir = NULL;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup();

        umask(0022);

        if (!arg_root && !arg_image) {
                bool enabled;

                /* If we are called without --root=/--image= let's honour the systemd.firstboot kernel
                 * command line option, because we are called to provision the host with basic settings (as
                 * opposed to some other file system tree/image) */

                r = proc_cmdline_get_bool("systemd.firstboot", &enabled);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse systemd.firstboot= kernel command line argument, ignoring: %m");
                if (r > 0 && !enabled) {
                        log_debug("Found systemd.firstboot=no kernel command line argument, terminating.");
                        return 0; /* disabled */
                }
        }

        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_VALIDATE_OS |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_FSCK |
                                DISSECT_IMAGE_GROWFS,
                                &unlink_dir,
                                &loop_device);
                if (r < 0)
                        return r;

                arg_root = strdup(unlink_dir);
                if (!arg_root)
                        return log_oom();
        }

        r = process_locale();
        if (r < 0)
                return r;

        r = process_keymap();
        if (r < 0)
                return r;

        r = process_timezone();
        if (r < 0)
                return r;

        r = process_hostname();
        if (r < 0)
                return r;

        r = process_machine_id();
        if (r < 0)
                return r;

        r = process_root_account();
        if (r < 0)
                return r;

        r = process_kernel_cmdline();
        if (r < 0)
                return r;

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
