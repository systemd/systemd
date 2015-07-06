/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/


#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <shadow.h>

#include "strv.h"
#include "fileio.h"
#include "copy.h"
#include "build.h"
#include "mkdir.h"
#include "time-util.h"
#include "path-util.h"
#include "random-util.h"
#include "locale-util.h"
#include "ask-password-api.h"
#include "terminal-util.h"
#include "hostname-util.h"

static char *arg_root = NULL;
static char *arg_locale = NULL;  /* $LANG */
static char *arg_locale_messages = NULL; /* $LC_MESSAGES */
static char *arg_timezone = NULL;
static char *arg_hostname = NULL;
static sd_id128_t arg_machine_id = {};
static char *arg_root_password = NULL;
static bool arg_prompt_locale = false;
static bool arg_prompt_timezone = false;
static bool arg_prompt_hostname = false;
static bool arg_prompt_root_password = false;
static bool arg_copy_locale = false;
static bool arg_copy_timezone = false;
static bool arg_copy_root_password = false;

static void clear_string(char *x) {

        if (!x)
                return;

        /* A delicious drop of snake-oil! */
        memset(x, 'x', strlen(x));
}

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
        _cleanup_free_ char *pretty_name = NULL;
        const char *os_release = NULL;
        static bool done = false;
        int r;

        if (done)
                return;

        os_release = prefix_roota(arg_root, "/etc/os-release");
        r = parse_env_file(os_release, NEWLINE,
                           "PRETTY_NAME", &pretty_name,
                           NULL);
        if (r == -ENOENT) {

                os_release = prefix_roota(arg_root, "/usr/lib/os-release");
                r = parse_env_file(os_release, NEWLINE,
                                   "PRETTY_NAME", &pretty_name,
                                   NULL);
        }

        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read os-release file: %m");

        printf("\nWelcome to your new installation of %s!\nPlease configure a few basic system settings:\n\n",
               isempty(pretty_name) ? "Linux" : pretty_name);

        press_any_key();

        done = true;
}

static int show_menu(char **x, unsigned n_columns, unsigned width, unsigned percentage) {
        unsigned n, per_column, i, j;
        unsigned break_lines, break_modulo;

        assert(n_columns > 0);

        n = strv_length(x);
        per_column = (n + n_columns - 1) / n_columns;

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

                        printf("%4u) %-*s", j * per_column + i + 1, width, e);
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

static int prompt_loop(const char *text, char **l, bool (*is_valid)(const char *name), char **ret) {
        int r;

        assert(text);
        assert(is_valid);
        assert(ret);

        for (;;) {
                _cleanup_free_ char *p = NULL;
                unsigned u;

                r = ask_string(&p, "%s %s (empty to skip): ", draw_special_char(DRAW_TRIANGULAR_BULLET), text);
                if (r < 0)
                        return log_error_errno(r, "Failed to query user: %m");

                if (isempty(p)) {
                        log_warning("No data entered, skipping.");
                        return 0;
                }

                r = safe_atou(p, &u);
                if (r >= 0) {
                        char *c;

                        if (u <= 0 || u > strv_length(l)) {
                                log_error("Specified entry number out of range.");
                                continue;
                        }

                        log_info("Selected '%s'.", l[u-1]);

                        c = strdup(l[u-1]);
                        if (!c)
                                return log_oom();

                        free(*ret);
                        *ret = c;
                        return 0;
                }

                if (!is_valid(p)) {
                        log_error("Entered data invalid.");
                        continue;
                }

                free(*ret);
                *ret = p;
                p = 0;
                return 0;
        }
}

static int prompt_locale(void) {
        _cleanup_strv_free_ char **locales = NULL;
        int r;

        if (arg_locale || arg_locale_messages)
                return 0;

        if (!arg_prompt_locale)
                return 0;

        r = get_locales(&locales);
        if (r < 0)
                return log_error_errno(r, "Cannot query locales list: %m");

        print_welcome();

        printf("\nAvailable Locales:\n\n");
        r = show_menu(locales, 3, 22, 60);
        if (r < 0)
                return r;

        putchar('\n');

        r = prompt_loop("Please enter system locale name or number", locales, locale_is_valid, &arg_locale);
        if (r < 0)
                return r;

        if (isempty(arg_locale))
                return 0;

        r = prompt_loop("Please enter system message locale name or number", locales, locale_is_valid, &arg_locale_messages);
        if (r < 0)
                return r;

        return 0;
}

static int process_locale(void) {
        const char *etc_localeconf;
        char* locales[3];
        unsigned i = 0;
        int r;

        etc_localeconf = prefix_roota(arg_root, "/etc/locale.conf");
        if (faccessat(AT_FDCWD, etc_localeconf, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                return 0;

        if (arg_copy_locale && arg_root) {

                mkdir_parents(etc_localeconf, 0755);
                r = copy_file("/etc/locale.conf", etc_localeconf, 0, 0644, 0);
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
        if (!isempty(arg_locale_messages) && !streq(arg_locale_messages, arg_locale))
                locales[i++] = strjoina("LC_MESSAGES=", arg_locale_messages);

        if (i == 0)
                return 0;

        locales[i] = NULL;

        mkdir_parents(etc_localeconf, 0755);
        r = write_env_file(etc_localeconf, locales);
        if (r < 0)
                return log_error_errno(r, "Failed to write %s: %m", etc_localeconf);

        log_info("%s written.", etc_localeconf);
        return 0;
}

static int prompt_timezone(void) {
        _cleanup_strv_free_ char **zones = NULL;
        int r;

        if (arg_timezone)
                return 0;

        if (!arg_prompt_timezone)
                return 0;

        r = get_timezones(&zones);
        if (r < 0)
                return log_error_errno(r, "Cannot query timezone list: %m");

        print_welcome();

        printf("\nAvailable Time Zones:\n\n");
        r = show_menu(zones, 3, 22, 30);
        if (r < 0)
                return r;

        putchar('\n');

        r = prompt_loop("Please enter timezone name or number", zones, timezone_is_valid, &arg_timezone);
        if (r < 0)
                return r;

        return 0;
}

static int process_timezone(void) {
        const char *etc_localtime, *e;
        int r;

        etc_localtime = prefix_roota(arg_root, "/etc/localtime");
        if (faccessat(AT_FDCWD, etc_localtime, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                return 0;

        if (arg_copy_timezone && arg_root) {
                _cleanup_free_ char *p = NULL;

                r = readlink_malloc("/etc/localtime", &p);
                if (r != -ENOENT) {
                        if (r < 0)
                                return log_error_errno(r, "Failed to read host timezone: %m");

                        mkdir_parents(etc_localtime, 0755);
                        if (symlink(p, etc_localtime) < 0)
                                return log_error_errno(errno, "Failed to create %s symlink: %m", etc_localtime);

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

        mkdir_parents(etc_localtime, 0755);
        if (symlink(e, etc_localtime) < 0)
                return log_error_errno(errno, "Failed to create %s symlink: %m", etc_localtime);

        log_info("%s written", etc_localtime);
        return 0;
}

static int prompt_hostname(void) {
        int r;

        if (arg_hostname)
                return 0;

        if (!arg_prompt_hostname)
                return 0;

        print_welcome();
        putchar('\n');

        for (;;) {
                _cleanup_free_ char *h = NULL;

                r = ask_string(&h, "%s Please enter hostname for new system (empty to skip): ", draw_special_char(DRAW_TRIANGULAR_BULLET));
                if (r < 0)
                        return log_error_errno(r, "Failed to query hostname: %m");

                if (isempty(h)) {
                        log_warning("No hostname entered, skipping.");
                        break;
                }

                if (!hostname_is_valid(h)) {
                        log_error("Specified hostname invalid.");
                        continue;
                }

                arg_hostname = h;
                h = NULL;
                break;
        }

        return 0;
}

static int process_hostname(void) {
        const char *etc_hostname;
        int r;

        etc_hostname = prefix_roota(arg_root, "/etc/hostname");
        if (faccessat(AT_FDCWD, etc_hostname, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                return 0;

        r = prompt_hostname();
        if (r < 0)
                return r;

        if (isempty(arg_hostname))
                return 0;

        mkdir_parents(etc_hostname, 0755);
        r = write_string_file(etc_hostname, arg_hostname, WRITE_STRING_FILE_CREATE);
        if (r < 0)
                return log_error_errno(r, "Failed to write %s: %m", etc_hostname);

        log_info("%s written.", etc_hostname);
        return 0;
}

static int process_machine_id(void) {
        const char *etc_machine_id;
        char id[SD_ID128_STRING_MAX];
        int r;

        etc_machine_id = prefix_roota(arg_root, "/etc/machine-id");
        if (faccessat(AT_FDCWD, etc_machine_id, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                return 0;

        if (sd_id128_equal(arg_machine_id, SD_ID128_NULL))
                return 0;

        mkdir_parents(etc_machine_id, 0755);
        r = write_string_file(etc_machine_id, sd_id128_to_string(arg_machine_id, id), WRITE_STRING_FILE_CREATE);
        if (r < 0)
                return log_error_errno(r, "Failed to write machine id: %m");

        log_info("%s written.", etc_machine_id);
        return 0;
}

static int prompt_root_password(void) {
        const char *msg1, *msg2, *etc_shadow;
        int r;

        if (arg_root_password)
                return 0;

        if (!arg_prompt_root_password)
                return 0;

        etc_shadow = prefix_roota(arg_root, "/etc/shadow");
        if (faccessat(AT_FDCWD, etc_shadow, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                return 0;

        print_welcome();
        putchar('\n');

        msg1 = strjoina(draw_special_char(DRAW_TRIANGULAR_BULLET), " Please enter a new root password (empty to skip): ");
        msg2 = strjoina(draw_special_char(DRAW_TRIANGULAR_BULLET), " Please enter new root password again: ");

        for (;;) {
                _cleanup_free_ char *a = NULL, *b = NULL;

                r = ask_password_tty(msg1, 0, false, NULL, &a);
                if (r < 0)
                        return log_error_errno(r, "Failed to query root password: %m");

                if (isempty(a)) {
                        log_warning("No password entered, skipping.");
                        break;
                }

                r = ask_password_tty(msg2, 0, false, NULL, &b);
                if (r < 0) {
                        log_error_errno(r, "Failed to query root password: %m");
                        clear_string(a);
                        return r;
                }

                if (!streq(a, b)) {
                        log_error("Entered passwords did not match, please try again.");
                        clear_string(a);
                        clear_string(b);
                        continue;
                }

                clear_string(b);
                arg_root_password = a;
                a = NULL;
                break;
        }

        return 0;
}

static int write_root_shadow(const char *path, const struct spwd *p) {
        _cleanup_fclose_ FILE *f = NULL;
        assert(path);
        assert(p);

        RUN_WITH_UMASK(0777)
                f = fopen(path, "wex");
        if (!f)
                return -errno;

        errno = 0;
        if (putspent(p, f) != 0)
                return errno ? -errno : -EIO;

        return fflush_and_check(f);
}

static int process_root_password(void) {

        static const char table[] =
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789"
                "./";

        struct spwd item = {
                .sp_namp = (char*) "root",
                .sp_min = -1,
                .sp_max = -1,
                .sp_warn = -1,
                .sp_inact = -1,
                .sp_expire = -1,
                .sp_flag = (unsigned long) -1, /* this appears to be what everybody does ... */
        };

        _cleanup_close_ int lock = -1;
        char salt[3+16+1+1];
        uint8_t raw[16];
        unsigned i;
        char *j;

        const char *etc_shadow;
        int r;

        etc_shadow = prefix_roota(arg_root, "/etc/shadow");
        if (faccessat(AT_FDCWD, etc_shadow, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                return 0;

        mkdir_parents(etc_shadow, 0755);

        lock = take_password_lock(arg_root);
        if (lock < 0)
                return lock;

        if (arg_copy_root_password && arg_root) {
                struct spwd *p;

                errno = 0;
                p = getspnam("root");
                if (p || errno != ENOENT) {
                        if (!p) {
                                if (!errno)
                                        errno = EIO;

                                log_error_errno(errno, "Failed to find shadow entry for root: %m");
                                return -errno;
                        }

                        r = write_root_shadow(etc_shadow, p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to write %s: %m", etc_shadow);

                        log_info("%s copied.", etc_shadow);
                        return 0;
                }
        }

        r = prompt_root_password();
        if (r < 0)
                return r;

        if (!arg_root_password)
                return 0;

        r = dev_urandom(raw, 16);
        if (r < 0)
                return log_error_errno(r, "Failed to get salt: %m");

        /* We only bother with SHA512 hashed passwords, the rest is legacy, and we don't do legacy. */
        assert_cc(sizeof(table) == 64 + 1);
        j = stpcpy(salt, "$6$");
        for (i = 0; i < 16; i++)
                j[i] = table[raw[i] & 63];
        j[i++] = '$';
        j[i] = 0;

        errno = 0;
        item.sp_pwdp = crypt(arg_root_password, salt);
        if (!item.sp_pwdp) {
                if (!errno)
                        errno = -EINVAL;

                log_error_errno(errno, "Failed to encrypt password: %m");
                return -errno;
        }

        item.sp_lstchg = (long) (now(CLOCK_REALTIME) / USEC_PER_DAY);

        r = write_root_shadow(etc_shadow, &item);
        if (r < 0)
                return log_error_errno(r, "Failed to write %s: %m", etc_shadow);

        log_info("%s written.", etc_shadow);
        return 0;
}

static void help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Configures basic settings of the system.\n\n"
               "  -h --help                    Show this help\n"
               "     --version                 Show package version\n"
               "     --root=PATH               Operate on an alternate filesystem root\n"
               "     --locale=LOCALE           Set primary locale (LANG=)\n"
               "     --locale-messages=LOCALE  Set message locale (LC_MESSAGES=)\n"
               "     --timezone=TIMEZONE       Set timezone\n"
               "     --hostname=NAME           Set host name\n"
               "     --machine-ID=ID           Set machine ID\n"
               "     --root-password=PASSWORD  Set root password\n"
               "     --root-password-file=FILE Set root password from file\n"
               "     --prompt-locale           Prompt the user for locale settings\n"
               "     --prompt-timezone         Prompt the user for timezone\n"
               "     --prompt-hostname         Prompt the user for hostname\n"
               "     --prompt-root-password    Prompt the user for root password\n"
               "     --prompt                  Prompt for all of the above\n"
               "     --copy-locale             Copy locale from host\n"
               "     --copy-timezone           Copy timezone from host\n"
               "     --copy-root-password      Copy root password from host\n"
               "     --copy                    Copy locale, timezone, root password\n"
               "     --setup-machine-id        Generate a new random machine ID\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_ROOT,
                ARG_LOCALE,
                ARG_LOCALE_MESSAGES,
                ARG_TIMEZONE,
                ARG_HOSTNAME,
                ARG_MACHINE_ID,
                ARG_ROOT_PASSWORD,
                ARG_ROOT_PASSWORD_FILE,
                ARG_PROMPT,
                ARG_PROMPT_LOCALE,
                ARG_PROMPT_TIMEZONE,
                ARG_PROMPT_HOSTNAME,
                ARG_PROMPT_ROOT_PASSWORD,
                ARG_COPY,
                ARG_COPY_LOCALE,
                ARG_COPY_TIMEZONE,
                ARG_COPY_ROOT_PASSWORD,
                ARG_SETUP_MACHINE_ID,
        };

        static const struct option options[] = {
                { "help",                 no_argument,       NULL, 'h'                      },
                { "version",              no_argument,       NULL, ARG_VERSION              },
                { "root",                 required_argument, NULL, ARG_ROOT                 },
                { "locale",               required_argument, NULL, ARG_LOCALE               },
                { "locale-messages",      required_argument, NULL, ARG_LOCALE_MESSAGES      },
                { "timezone",             required_argument, NULL, ARG_TIMEZONE             },
                { "hostname",             required_argument, NULL, ARG_HOSTNAME             },
                { "machine-id",           required_argument, NULL, ARG_MACHINE_ID           },
                { "root-password",        required_argument, NULL, ARG_ROOT_PASSWORD        },
                { "root-password-file",   required_argument, NULL, ARG_ROOT_PASSWORD_FILE   },
                { "prompt",               no_argument,       NULL, ARG_PROMPT               },
                { "prompt-locale",        no_argument,       NULL, ARG_PROMPT_LOCALE        },
                { "prompt-timezone",      no_argument,       NULL, ARG_PROMPT_TIMEZONE      },
                { "prompt-hostname",      no_argument,       NULL, ARG_PROMPT_HOSTNAME      },
                { "prompt-root-password", no_argument,       NULL, ARG_PROMPT_ROOT_PASSWORD },
                { "copy",                 no_argument,       NULL, ARG_COPY                 },
                { "copy-locale",          no_argument,       NULL, ARG_COPY_LOCALE          },
                { "copy-timezone",        no_argument,       NULL, ARG_COPY_TIMEZONE        },
                { "copy-root-password",   no_argument,       NULL, ARG_COPY_ROOT_PASSWORD   },
                { "setup-machine-id",     no_argument,       NULL, ARG_SETUP_MACHINE_ID     },
                {}
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_ROOT:
                        free(arg_root);
                        arg_root = path_make_absolute_cwd(optarg);
                        if (!arg_root)
                                return log_oom();

                        path_kill_slashes(arg_root);

                        if (path_equal(arg_root, "/")) {
                                free(arg_root);
                                arg_root = NULL;
                        }

                        break;

                case ARG_LOCALE:
                        if (!locale_is_valid(optarg)) {
                                log_error("Locale %s is not valid.", optarg);
                                return -EINVAL;
                        }

                        free(arg_locale);
                        arg_locale = strdup(optarg);
                        if (!arg_locale)
                                return log_oom();

                        break;

                case ARG_LOCALE_MESSAGES:
                        if (!locale_is_valid(optarg)) {
                                log_error("Locale %s is not valid.", optarg);
                                return -EINVAL;
                        }

                        free(arg_locale_messages);
                        arg_locale_messages = strdup(optarg);
                        if (!arg_locale_messages)
                                return log_oom();

                        break;

                case ARG_TIMEZONE:
                        if (!timezone_is_valid(optarg)) {
                                log_error("Timezone %s is not valid.", optarg);
                                return -EINVAL;
                        }

                        free(arg_timezone);
                        arg_timezone = strdup(optarg);
                        if (!arg_timezone)
                                return log_oom();

                        break;

                case ARG_ROOT_PASSWORD:
                        free(arg_root_password);
                        arg_root_password = strdup(optarg);
                        if (!arg_root_password)
                                return log_oom();

                        break;

                case ARG_ROOT_PASSWORD_FILE:
                        free(arg_root_password);
                        arg_root_password  = NULL;

                        r = read_one_line_file(optarg, &arg_root_password);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read %s: %m", optarg);

                        break;

                case ARG_HOSTNAME:
                        if (!hostname_is_valid(optarg)) {
                                log_error("Host name %s is not valid.", optarg);
                                return -EINVAL;
                        }

                        free(arg_hostname);
                        arg_hostname = strdup(optarg);
                        if (!arg_hostname)
                                return log_oom();

                        break;

                case ARG_MACHINE_ID:
                        if (sd_id128_from_string(optarg, &arg_machine_id) < 0) {
                                log_error("Failed to parse machine id %s.", optarg);
                                return -EINVAL;
                        }

                        break;

                case ARG_PROMPT:
                        arg_prompt_locale = arg_prompt_timezone = arg_prompt_hostname = arg_prompt_root_password = true;
                        break;

                case ARG_PROMPT_LOCALE:
                        arg_prompt_locale = true;
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

                case ARG_COPY:
                        arg_copy_locale = arg_copy_timezone = arg_copy_root_password = true;
                        break;

                case ARG_COPY_LOCALE:
                        arg_copy_locale = true;
                        break;

                case ARG_COPY_TIMEZONE:
                        arg_copy_timezone = true;
                        break;

                case ARG_COPY_ROOT_PASSWORD:
                        arg_copy_root_password = true;
                        break;

                case ARG_SETUP_MACHINE_ID:

                        r = sd_id128_randomize(&arg_machine_id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to generate randomized machine ID: %m");

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

int main(int argc, char *argv[]) {
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        r = process_locale();
        if (r < 0)
                goto finish;

        r = process_timezone();
        if (r < 0)
                goto finish;

        r = process_hostname();
        if (r < 0)
                goto finish;

        r = process_machine_id();
        if (r < 0)
                goto finish;

        r = process_root_password();
        if (r < 0)
                goto finish;

finish:
        free(arg_root);
        free(arg_locale);
        free(arg_locale_messages);
        free(arg_timezone);
        free(arg_hostname);
        clear_string(arg_root_password);
        free(arg_root_password);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
