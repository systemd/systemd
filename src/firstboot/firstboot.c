/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "ansi-color.h"
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
#include "dlopen-note.h"
#include "efi-loader.h"
#include "env-file.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "firstboot-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "image-policy.h"
#include "initrd-cpio.h"
#include "iovec-util.h"
#include "kbd-util.h"
#include "label-util.h"
#include "libcrypt-util.h"
#include "locale-setup.h"
#include "locale-util.h"
#include "lock-util.h"
#include "loop-util.h"
#include "machine-credential.h"
#include "main-func.h"
#include "memory-util.h"
#include "mount-util.h"
#include "os-util.h"
#include "parse-argument.h"
#include "password-quality-util.h"
#include "path-util.h"
#include "pe-addon.h"
#include "plymouth-util.h"
#include "prompt-util.h"
#include "runtime-scope.h"
#include "smack-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "vconsole-util.h"
#include "verbs.h"
#include "vfat-util.h"
#include "voa-util.h"

static char *arg_root = NULL;
static char *arg_image = NULL;
static char *arg_locale = NULL;  /* $LANG */
static char *arg_locale_messages = NULL; /* $LC_MESSAGES */
static char *arg_keymap = NULL;
static char *arg_timezone = NULL;
static char *arg_hostname = NULL;
static sd_id128_t arg_machine_id = {};
static char **arg_machine_tags = NULL;
static char *arg_root_password = NULL;
static char *arg_root_shell = NULL;
static char *arg_kernel_cmdline = NULL;
static bool arg_prompt_locale = false;
static bool arg_prompt_keymap = false;
static bool arg_prompt_keymap_auto = false;
static bool arg_prompt_timezone = false;
static bool arg_prompt_hostname = false;
static bool arg_prompt_root_password = false;
static bool arg_prompt_root_shell = false;
static bool arg_headless = false;
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
static bool arg_chrome = true;
static bool arg_mute_console = false;
static LabelContext *arg_label_context = NULL;
static char *arg_addon = NULL;
static MachineCredentialContext arg_keys = {};

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_locale, freep);
STATIC_DESTRUCTOR_REGISTER(arg_locale_messages, freep);
STATIC_DESTRUCTOR_REGISTER(arg_keymap, freep);
STATIC_DESTRUCTOR_REGISTER(arg_timezone, freep);
STATIC_DESTRUCTOR_REGISTER(arg_hostname, freep);
STATIC_DESTRUCTOR_REGISTER(arg_machine_tags, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_password, erase_and_freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_shell, freep);
STATIC_DESTRUCTOR_REGISTER(arg_kernel_cmdline, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);
STATIC_DESTRUCTOR_REGISTER(arg_label_context, mac_label_context_freep);
STATIC_DESTRUCTOR_REGISTER(arg_addon, freep);
STATIC_DESTRUCTOR_REGISTER(arg_keys, machine_credential_context_done);

COMMAND(
        "systemd-firstboot\0",
        "Configure basic settings of the system.",
        .man_pages = "systemd-firstboot(1)\0",
);

static bool welcome_done = false;

static void print_welcome(int rfd, sd_varlink **mute_console_link) {
        _cleanup_free_ char *pretty_name = NULL, *os_name = NULL, *ansi_color = NULL, *fancy_name = NULL;
        const char *pn, *ac;
        int r;

        assert(rfd >= 0);
        assert(mute_console_link);

        /* Needs to be called before mute_console or it will garble the screen */
        if (arg_welcome)
                (void) plymouth_hide_splash();

        if (!*mute_console_link && arg_mute_console)
                (void) mute_console(mute_console_link);

        if (!arg_welcome)
                return;

        if (welcome_done) {
                putchar('\n'); /* Add some breathing room between multiple prompts */
                return;
        }

        (void) terminal_reset_defensive_locked(STDOUT_FILENO, /* flags= */ 0);

        if (arg_chrome)
                chrome_show("Initial Setup", /* bottom= */ NULL);

        r = parse_os_release_at(rfd,
                                "PRETTY_NAME", &pretty_name,
                                "FANCY_NAME", &fancy_name,
                                "NAME", &os_name,
                                "ANSI_COLOR", &ansi_color);
        if (r < 0)
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to read os-release file, ignoring: %m");

        pn = os_release_pretty_name(pretty_name, os_name);
        ac = isempty(ansi_color) ? "0" : ansi_color;

        if (use_fancy_name(unescape_fancy_name(&fancy_name)))
                printf(ANSI_HIGHLIGHT "Welcome to " ANSI_NORMAL "%s" ANSI_HIGHLIGHT "!" ANSI_NORMAL "\n", fancy_name);
        else if (colors_enabled())
                printf(ANSI_HIGHLIGHT "Welcome to " ANSI_NORMAL "\x1B[%sm%s" ANSI_HIGHLIGHT "!" ANSI_NORMAL "\n", ac, pn);
        else
                printf("Welcome to %s!\n", pn);

        putchar('\n');
        if (emoji_enabled()) {
                fputs(glyph(GLYPH_SPARKLES), stdout);
                putchar(' ');
        }
        printf("Please configure the system!\n\n");

        welcome_done = true;
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

static int locale_is_ok(const char *name, void *userdata) {
        int rfd = ASSERT_FD(PTR_TO_FD(userdata)), r;

        r = dir_fd_is_root(rfd);
        if (r < 0)
                log_debug_errno(r, "Unable to determine if operating on host root directory, assuming we are: %m");

        return r != 0 ? locale_is_installed(name) > 0 : locale_is_valid(name);
}

static bool headless_skips_prompt_for(const char *what) {
        assert(what);

        if (!arg_headless)
                return false;

        log_debug("Running headless, not prompting for %s.", what);
        return true;
}

static int prompt_locale(int rfd, sd_varlink **mute_console_link) {
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
                if (headless_skips_prompt_for("locale"))
                        return 0;

                print_welcome(rfd, mute_console_link);

                _cleanup_free_ char *prefill = NULL;
                (void) locale_lang_from_efi(&prefill, LOCALE_REQUIRE_INSTALLED|LOCALE_SUPPRESS_EN_US);

                r = prompt_loop("Please enter the new system locale name or number",
                                GLYPH_WORLD,
                                prefill,
                                locales,
                                /* accepted= */ NULL,
                                /* ellipsize_percentage= */ 60,
                                /* n_columns= */ 3,
                                /* column_width= */ 20,
                                locale_is_ok,
                                /* refresh= */ NULL,
                                FD_TO_PTR(rfd),
                                PROMPT_MAY_SKIP|PROMPT_SHOW_MENU,
                                &arg_locale);
                if (r < 0)
                        return r;
                if (isempty(arg_locale))
                        return 0;

                r = prompt_loop("Please enter the new system message locale name or number",
                                GLYPH_WORLD,
                                /* prefill= */ NULL,
                                locales,
                                /* accepted= */ NULL,
                                /* ellipsize_percentage= */ 60,
                                /* n_columns= */ 3,
                                /* column_width= */ 20,
                                locale_is_ok,
                                /* refresh= */ NULL,
                                FD_TO_PTR(rfd),
                                PROMPT_MAY_SKIP|PROMPT_SHOW_MENU,
                                &arg_locale_messages);
                if (r < 0)
                        return r;

                /* Suppress the messages setting if it's the same as the main locale anyway */
                if (streq_ptr(arg_locale, arg_locale_messages))
                        arg_locale_messages = mfree(arg_locale_messages);
        }

        return 0;
}

static int process_locale(int rfd, sd_varlink **mute_console_link) {
        _cleanup_close_ int pfd = -EBADF;
        _cleanup_free_ char *f = NULL;
        char* locales[3];
        unsigned i = 0;
        int r;

        assert(rfd >= 0);

        pfd = chase_and_open_parent_at(rfd, rfd, etc_locale_conf(),
                                       CHASE_MKDIR_0755|CHASE_WARN|CHASE_NOFOLLOW,
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
                r = copy_file_atomic_at(AT_FDCWD, etc_locale_conf(), pfd, f, 0644, /* copy_flags= */ 0);
                if (r != -ENOENT) {
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy host's /etc/locale.conf: %m");

                        log_info("Copied host's /etc/locale.conf.");
                        return 0;
                }
        }

        r = prompt_locale(rfd, mute_console_link);
        if (r < 0)
                return r;

        if (!isempty(arg_locale))
                locales[i++] = strjoina("LANG=", arg_locale);
        if (!isempty(arg_locale_messages) && !streq_ptr(arg_locale_messages, arg_locale))
                locales[i++] = strjoina("LC_MESSAGES=", arg_locale_messages);

        if (i == 0)
                return 0;

        locales[i] = NULL;

        r = write_env_file_label(
                        pfd,
                        f,
                        /* headers= */ NULL,
                        locales,
                        WRITE_ENV_FILE_LABEL,
                        arg_label_context);
        if (r < 0)
                return log_error_errno(r, "Failed to write /etc/locale.conf: %m");

        log_info("/etc/locale.conf written.");
        return 1;
}

static int keymap_is_ok(const char* name, void *userdata) {
        int rfd = ASSERT_FD(PTR_TO_FD(userdata)), r;

        r = dir_fd_is_root(rfd);
        if (r < 0)
                log_debug_errno(r, "Unable to determine if operating on host root directory, assuming we are: %m");

        return r != 0 ? keymap_exists(name) > 0 : keymap_is_valid(name);
}

static int prompt_keymap(int rfd, sd_varlink **mute_console_link) {
        _cleanup_strv_free_ char **kmaps = NULL;
        int r;

        assert(rfd >= 0);

        if (arg_keymap)
                return 0;

        _cleanup_free_ char *km = NULL;
        r = read_credential("firstboot.keymap", (void**) &km, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential firstboot.keymap, ignoring: %m");
        else if (!keymap_is_valid(km))
                log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Keymap '%s' supplied via credential is not valid, ignoring.", km);
        else {
                log_debug("Acquired keymap from credential.");
                arg_keymap = TAKE_PTR(km);
                return 0;
        }

        bool b;
        if (arg_prompt_keymap_auto) {
                _cleanup_free_ char *ttyname = NULL;

                r = getttyname_harder(STDOUT_FILENO, &ttyname);
                if (r < 0) {
                        log_debug_errno(r, "Cannot determine TTY we are connected, ignoring: %m");
                        b = false; /* if we can't resolve this, it's probably not a VT */
                } else {
                        b = tty_is_vc_resolve(ttyname);
                        log_debug("Detected connection to local console: %s", yes_no(b));
                }
        } else
                b = arg_prompt_keymap;
        if (!b) {
                log_debug("Prompting for keymap was not requested.");
                return 0;
        }

        if (headless_skips_prompt_for("keymap"))
                return 0;

        r = get_keymaps(&kmaps);
        if (r == -ENOENT) /* no keymaps installed */
                return log_debug_errno(r, "No keymaps are installed.");
        if (r < 0)
                return log_error_errno(r, "Failed to read keymaps: %m");

        print_welcome(rfd, mute_console_link);

        _cleanup_free_ char *prefill = NULL;
        (void) vconsole_keymap_from_efi(&prefill);

        return prompt_loop(
                        "Please enter the new keymap name or number",
                        GLYPH_KEYBOARD,
                        prefill,
                        kmaps,
                        /* accepted= */ NULL,
                        /* ellipsize_percentage= */ 60,
                        /* n_columns= */ 3,
                        /* column_width= */ 20,
                        keymap_is_ok,
                        /* refresh= */ NULL,
                        FD_TO_PTR(rfd),
                        PROMPT_MAY_SKIP|PROMPT_SHOW_MENU,
                        &arg_keymap);
}

static int process_keymap(int rfd, sd_varlink **mute_console_link) {
        _cleanup_close_ int pfd = -EBADF;
        _cleanup_free_ char *f = NULL;
        _cleanup_strv_free_ char **keymap = NULL;
        int r;

        assert(rfd >= 0);

        pfd = chase_and_open_parent_at(rfd, rfd, etc_vconsole_conf(),
                                       CHASE_MKDIR_0755|CHASE_WARN|CHASE_NOFOLLOW,
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
                r = copy_file_atomic_at(AT_FDCWD, etc_vconsole_conf(), pfd, f, 0644, /* copy_flags= */ 0);
                if (r != -ENOENT) {
                        if (r < 0)
                                return log_error_errno(r, "Failed to copy host's /etc/vconsole.conf: %m");

                        log_info("Copied host's /etc/vconsole.conf.");
                        return 0;
                }
        }

        r = prompt_keymap(rfd, mute_console_link);
        if (r == -ENOENT)
                return 0; /* don't fail if no keymaps are installed */
        if (r < 0)
                return r;

        if (isempty(arg_keymap))
                return 0;

        VCContext vc = {
                .keymap = arg_keymap,
        };
        _cleanup_(x11_context_clear) X11Context xc = {};

        r = vconsole_convert_to_x11(&vc, /* verify= */ NULL, &xc);
        if (r < 0)
                return log_error_errno(r, "Failed to convert keymap data: %m");

        r = vconsole_serialize(&vc, &xc, &keymap);
        if (r < 0)
                return log_error_errno(r, "Failed to serialize keymap data: %m");

        r = write_vconsole_conf(pfd, f, keymap);
        if (r < 0)
                return log_error_errno(r, "Failed to write /etc/vconsole.conf: %m");

        log_info("/etc/vconsole.conf written.");
        return 1;
}

static int timezone_is_ok(const char *name, void *userdata) {
        return timezone_is_valid(name, LOG_DEBUG);
}

static int prompt_timezone(int rfd, sd_varlink **mute_console_link) {
        _cleanup_strv_free_ char **zones = NULL;
        int r;

        assert(rfd >= 0);

        if (arg_timezone)
                return 0;

        _cleanup_free_ char *tz = NULL;
        r = read_credential("firstboot.timezone", (void**) &tz, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential firstboot.timezone, ignoring: %m");
        else if (!timezone_is_valid(tz, LOG_DEBUG))
                log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Timezone '%s' supplied via credential is not valid, ignoring.", tz);
        else {
                log_debug("Acquired timezone from credential.");
                arg_timezone = TAKE_PTR(tz);
                return 0;
        }

        if (!arg_prompt_timezone) {
                log_debug("Prompting for timezone was not requested.");
                return 0;
        }

        if (headless_skips_prompt_for("timezone"))
                return 0;

        r = get_timezones(&zones);
        if (r < 0)
                return log_error_errno(r, "Cannot query timezone list: %m");

        print_welcome(rfd, mute_console_link);

        return prompt_loop(
                        "Please enter the new timezone name or number",
                        GLYPH_CLOCK,
                        /* prefill= */ NULL,
                        zones,
                        /* accepted= */ NULL,
                        /* ellipsize_percentage= */ 30,
                        /* n_columns= */ 3,
                        /* column_width= */ 20,
                        timezone_is_ok,
                        /* refresh= */ NULL,
                        FD_TO_PTR(rfd),
                        PROMPT_MAY_SKIP|PROMPT_SHOW_MENU,
                        &arg_timezone);
}

static int process_timezone(int rfd, sd_varlink **mute_console_link) {
        _cleanup_close_ int pfd = -EBADF;
        _cleanup_free_ char *f = NULL, *relpath = NULL;
        const char *e;
        int r;

        assert(rfd >= 0);

        pfd = chase_and_open_parent_at(rfd, rfd, etc_localtime(),
                                       CHASE_MKDIR_0755|CHASE_WARN|CHASE_NOFOLLOW,
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

                r = readlink_malloc(etc_localtime(), &s);
                if (r != -ENOENT) {
                        if (r < 0)
                                return log_error_errno(r, "Failed to read host's /etc/localtime: %m");

                        r = symlinkat_atomic_full_label(s, pfd, f, SYMLINK_LABEL, arg_label_context);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create /etc/localtime symlink: %m");

                        log_info("Copied host's /etc/localtime.");
                        return 0;
                }
        }

        r = prompt_timezone(rfd, mute_console_link);
        if (r < 0)
                return r;

        if (isempty(arg_timezone))
                return 0;

        e = strjoina("/usr/share/zoneinfo/", arg_timezone);
        r = path_make_relative_parent(etc_localtime(), e, &relpath);
        if (r < 0)
                return r;

        r = symlinkat_atomic_full_label(relpath, pfd, f, SYMLINK_LABEL, arg_label_context);
        if (r < 0)
                return log_error_errno(r, "Failed to create /etc/localtime symlink: %m");

        log_info("/etc/localtime written");
        return 0;
}

static int hostname_is_ok(const char *name, void *userdata) {
        return hostname_is_valid(name, VALID_HOSTNAME_TRAILING_DOT);
}

static int prompt_hostname(int rfd, sd_varlink **mute_console_link) {
        int r;

        assert(rfd >= 0);

        if (arg_hostname)
                return 0;

        _cleanup_free_ char *hn = NULL;
        r = read_credential("firstboot.hostname", (void**) &hn, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential firstboot.hostname, ignoring: %m");
        else if (!hostname_is_valid(hn, VALID_HOSTNAME_TRAILING_DOT|VALID_HOSTNAME_QUESTION_MARK|VALID_HOSTNAME_WORD_TOKEN))
                log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Hostname '%s' supplied via credential is not valid, ignoring.", hn);
        else {
                log_debug("Acquired hostname from credentials.");
                arg_hostname = TAKE_PTR(hn);
                hostname_cleanup(arg_hostname);
                return 0;
        }

        if (!arg_prompt_hostname) {
                log_debug("Prompting for hostname was not requested.");
                return 0;
        }

        if (headless_skips_prompt_for("hostname"))
                return 0;

        print_welcome(rfd, mute_console_link);

        r = prompt_loop("Please enter the new hostname",
                        GLYPH_LABEL,
                        /* prefill= */ NULL,
                        /* menu= */ NULL,
                        /* accepted= */ NULL,
                        /* ellipsize_percentage= */ 100,
                        /* n_columns= */ 3,
                        /* column_width= */ 20,
                        hostname_is_ok,
                        /* refresh= */ NULL,
                        FD_TO_PTR(rfd),
                        PROMPT_MAY_SKIP,
                        &arg_hostname);
        if (r < 0)
                return r;

        if (arg_hostname)
                hostname_cleanup(arg_hostname);

        return 0;
}

static int process_hostname(int rfd, sd_varlink **mute_console_link) {
        _cleanup_close_ int pfd = -EBADF;
        _cleanup_free_ char *f = NULL;
        int r;

        assert(rfd >= 0);

        pfd = chase_and_open_parent_at(rfd, rfd, etc_hostname(), CHASE_MKDIR_0755|CHASE_WARN, &f);
        if (pfd < 0)
                return log_error_errno(pfd, "Failed to chase /etc/hostname: %m");

        r = should_configure(pfd, f);
        if (r == 0)
                log_debug("Found /etc/hostname, assuming hostname has been configured.");
        if (r <= 0)
                return r;

        r = prompt_hostname(rfd, mute_console_link);
        if (r < 0)
                return r;

        if (isempty(arg_hostname))
                return 0;

        /* On running systems we have a machine ID, so resolve any '?'/'$' wildcards now and persist them.
         * This "freezes" the name, so later word list updates do not change it. When operating on an offline
         * image (--root=/--image=) the target's machine ID is not known yet, so write the template verbatim
         * and let it be resolved on each first boot. */
        const char *hostname = arg_hostname;
        _cleanup_free_ char *resolved = NULL;
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        if (!arg_root) {
                r = hostname_substitute_wildcards(arg_hostname, &resolved);
                if (r < 0)
                        log_warning_errno(r, "Failed to resolve wildcards in hostname '%s', writing it verbatim: %m", arg_hostname);
                else if (!hostname_is_valid(resolved, VALID_HOSTNAME_TRAILING_DOT))
                        log_warning("Resolved hostname '%s' is invalid, writing template '%s' verbatim instead.", resolved, arg_hostname);
                else {
                        hostname = resolved;

                        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.Hostname");
                        if (r < 0)
                                log_warning_errno(r, "Failed to connect to systemd-hostnamed, writing /etc/hostname directly: %m");
                }
        }

        if (vl) {
                sd_json_variant *reply = NULL;
                const char *error_id = NULL;
                r = sd_varlink_callbo(
                                vl,
                                "io.systemd.Hostname.SetStaticHostname",
                                &reply,
                                &error_id,
                                SD_JSON_BUILD_PAIR_STRING("newValue", hostname));
                if (r < 0)
                        log_warning_errno(r, "Failed to call io.systemd.Hostname.SetStaticHostname, writing /etc/hostname directly: %m");
                else if (error_id)
                        log_warning_errno(sd_varlink_error_to_errno(error_id, reply),
                                          "Failed to set static hostname, writing /etc/hostname directly: %s", error_id);
                else {
                        log_info("Static hostname configured via systemd-hostnamed.");
                        return 0;
                }
        }

        r = write_string_file_full_label(
                        pfd, f, hostname,
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_SYNC|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_LABEL,
                        /* ts= */ NULL, /* label_fn= */ NULL, arg_label_context);
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

        pfd = chase_and_open_parent_at(rfd, rfd, "/etc/machine-id",
                                       CHASE_MKDIR_0755|CHASE_WARN|CHASE_NOFOLLOW,
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

        r = write_string_file_full_label(pfd, "machine-id", SD_ID128_TO_STRING(arg_machine_id),
                                   WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_SYNC|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_LABEL,
                                   /* ts= */ NULL, /* label_fn= */ NULL, arg_label_context);
        if (r < 0)
                return log_error_errno(r, "Failed to write /etc/machine-id: %m");

        log_info("/etc/machine-id written.");
        return 0;
}

static int process_machine_tags(int rfd) {
        int r;

        assert(rfd >= 0);

        _cleanup_free_ char *f = NULL;
        _cleanup_close_ int pfd = chase_and_open_parent_at(
                        /* root_fd= */ rfd,
                        /* dir_fd= */ rfd,
                        "/etc/machine-info",
                        CHASE_MKDIR_0755|CHASE_WARN|CHASE_NOFOLLOW,
                        &f);
        if (pfd < 0)
                return log_error_errno(pfd, "Failed to chase /etc/machine-info parent: %m");

        r = should_configure(pfd, f);
        if (r == 0)
                log_debug("Found /etc/machine-info, assuming machine tags have been configured.");
        if (r <= 0)
                return r;

        if (!arg_machine_tags) {
                _cleanup_free_ char *tags = NULL;
                r = read_credential("firstboot.machine-tags", (void**) &tags, /* ret_size= */ NULL);
                if (r < 0)
                        log_debug_errno(r, "Failed to read credential firstboot.machine-tags, ignoring: %m");
                else {
                        _cleanup_strv_free_ char **l = NULL;
                        r = machine_tags_from_string(tags, /* graceful= */ false, &l);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse machine tags '%s', ignoring credential: %m", tags);
                        else {
                                strv_free_and_replace(arg_machine_tags, l);
                                log_debug("Acquired machine tags list from credentials.");
                        }
                }
        }

        /* NB: We do not prompt for machine tags, at least not for now */

        if (!arg_machine_tags) {
                log_debug("Initialization of machine tags was not requested, skipping.");
                return 0;
        }

        _cleanup_free_ char *j = strv_join(arg_machine_tags, ":");
        if (!j)
                return log_oom();

        _cleanup_free_ char *c = strjoin("TAGS=\"", j, "\"\n");
        if (!c)
                return log_oom();

        r = write_string_file_full_label(
                        pfd,
                        "machine-info",
                        c,
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_SYNC|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_LABEL,
                        /* ts= */ NULL, /* label_fn= */ NULL, arg_label_context);
        if (r < 0)
                return log_error_errno(r, "Failed to write /etc/machine-info: %m");

        log_info("/etc/machine-info written.");
        return 0;
}

static int prompt_root_password(int rfd, sd_varlink **mute_console_link) {
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

        if (headless_skips_prompt_for("root password"))
                return 0;

        print_welcome(rfd, mute_console_link);

        msg1 = "Please enter the new root password (empty to skip):";
        msg2 = "Please enter the new root password again:";

        suggest_passwords();

        for (;;) {
                _cleanup_strv_free_erase_ char **a = NULL, **b = NULL;
                _cleanup_free_ char *error = NULL;

                AskPasswordRequest req = {
                        .tty_fd = -EBADF,
                        .message = msg1,
                        .until = USEC_INFINITY,
                        .hup_fd = -EBADF,
                };

                r = ask_password_tty(&req, /* flags= */ 0, &a);
                if (r < 0)
                        return log_error_errno(r, "Failed to query root password: %m");
                if (strv_length(a) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Received multiple passwords, where we expected one.");

                if (isempty(*a)) {
                        log_info("No password entered, skipping.");
                        break;
                }

                r = check_password_quality(*a, /* old= */ NULL, "root", &error);
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_warning("Password quality check is not supported, proceeding anyway.");
                else if (r < 0)
                        return log_error_errno(r, "Failed to check password quality: %m");
                else if (r == 0)
                        log_warning("Password is weak, accepting anyway: %s", error);

                req.message = msg2;

                r = ask_password_tty(&req, /* flags= */ 0, &b);
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

        r = chaseat(rfd, rfd, path, /* flags= */ 0, /* ret_path= */ NULL, /* ret_fd= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve shell %s: %m", path);

        return 0;
}

static int shell_is_ok(const char *path, void *userdata) {
        int rfd = ASSERT_FD(PTR_TO_FD(userdata));

        return find_shell(rfd, path) >= 0;
}

static int prompt_root_shell(int rfd, sd_varlink **mute_console_link) {
        int r;

        assert(rfd >= 0);

        if (arg_root_shell)
                return 0;

        r = read_credential("passwd.shell.root", (void**) &arg_root_shell, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential passwd.shell.root, ignoring: %m");
        else {
                r = find_shell(rfd, arg_root_shell);
                if (r < 0)
                        return r;

                log_debug("Acquired root shell from credential.");
                return 0;
        }

        if (!arg_prompt_root_shell) {
                log_debug("Prompting for root shell was not requested.");
                return 0;
        }

        if (headless_skips_prompt_for("root shell"))
                return 0;

        print_welcome(rfd, mute_console_link);

        return prompt_loop(
                        "Please enter the new root shell",
                        GLYPH_SHELL,
                        /* prefill= */ NULL,
                        /* menu= */ NULL,
                        /* accepted= */ NULL,
                        /* ellipsize_percentage= */ 0,
                        /* n_columns= */ 3,
                        /* column_width= */ 20,
                        shell_is_ok,
                        /* refresh= */ NULL,
                        FD_TO_PTR(rfd),
                        PROMPT_MAY_SKIP,
                        &arg_root_shell);
}

static int write_root_passwd(int rfd, int etc_fd, const char *password, const char *shell) {
        _cleanup_fclose_ FILE *original = NULL, *passwd = NULL;
        _cleanup_(unlink_and_freep) char *passwd_tmp = NULL;
        int r;
        bool found = false;

        r = fopen_temporary_at_label(etc_fd, "passwd", "passwd", &passwd, &passwd_tmp, arg_label_context);
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
                                if (password)
                                        i->pw_passwd = (char *) password;
                                if (shell)
                                        i->pw_shell = (char *) shell;
                                found = true;
                        }

                        r = putpwent_sane(i, passwd);
                        if (r < 0)
                                return r;
                }
                if (r < 0)
                        return r;

        } else {
                r = fchmod(fileno(passwd), 0644);
                if (r < 0)
                        return -errno;
        }

        if (!found) {
                struct passwd root = {
                        .pw_name = (char *) "root",
                        .pw_passwd = (char *) (password ?: PASSWORD_SEE_SHADOW),
                        .pw_uid = 0,
                        .pw_gid = 0,
                        .pw_gecos = (char *) "Super User",
                        .pw_dir = (char *) "/root",
                        .pw_shell = (char *) (shell ?: default_root_shell_at(rfd)),
                };

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
        bool found = false;

        r = fopen_temporary_at_label(etc_fd, "shadow", "shadow", &shadow, &shadow_tmp, arg_label_context);
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
                                if (hashed_password) {
                                        i->sp_pwdp = (char *) hashed_password;
                                        i->sp_lstchg = (long) (now(CLOCK_REALTIME) / USEC_PER_DAY);
                                }
                                found = true;
                        }

                        r = putspent_sane(i, shadow);
                        if (r < 0)
                                return r;
                }
                if (r < 0)
                        return r;

        } else {
                r = fchmod(fileno(shadow), 0000);
                if (r < 0)
                        return -errno;
        }

        if (!found) {
                struct spwd root = {
                        .sp_namp = (char*) "root",
                        .sp_pwdp = (char *) (hashed_password ?: PASSWORD_LOCKED_AND_INVALID),
                        .sp_lstchg = (long) (now(CLOCK_REALTIME) / USEC_PER_DAY),
                        .sp_min = -1,
                        .sp_max = -1,
                        .sp_warn = -1,
                        .sp_inact = -1,
                        .sp_expire = -1,
                        .sp_flag = ULONG_MAX, /* this appears to be what everybody does ... */
                };

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

static int process_root_account(int rfd, sd_varlink **mute_console_link) {
        _cleanup_close_ int pfd = -EBADF;
        _cleanup_(release_lock_file) LockFile lock = LOCK_FILE_INIT;
        _cleanup_(erase_and_freep) char *_hashed_password = NULL;
        const char *password, *hashed_password;
        int k = 0, r;

        assert(rfd >= 0);

        pfd = chase_and_open_parent_at(rfd, rfd, "/etc/passwd",
                                       CHASE_MKDIR_0755|CHASE_WARN|CHASE_NOFOLLOW,
                                       NULL);
        if (pfd < 0)
                return log_error_errno(pfd, "Failed to chase /etc/passwd: %m");

        /* Ensure that passwd and shadow are in the same directory and are not symlinks. */

        FOREACH_STRING(s, "passwd", "shadow") {
                r = verify_regular_at(pfd, s, /* follow= */ false);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Verification of /etc/%s being regular file failed: %m", s);

                r = should_configure(pfd, s);
                if (r < 0)
                        return r;

                k += r;
        }

        if (k == 0) {
                log_debug("Found /etc/passwd and /etc/shadow, assuming root account has been initialized.");
                return 0;
        }

        r = make_lock_file_at(pfd, ETC_PASSWD_LOCK_FILENAME, LOCK_EX, &lock);
        if (r < 0)
                return log_error_errno(r, "Failed to take a lock on /etc/passwd: %m");

        k = dir_fd_is_root(rfd);
        if (k < 0)
                return log_error_errno(k, "Failed to check if directory file descriptor is root: %m");

        if (arg_copy_root_shell && k == 0) {
                _cleanup_free_ struct passwd *p = NULL;

                r = getpwnam_malloc("root", &p);
                if (r < 0)
                        return log_error_errno(r, "Failed to find passwd entry for root: %m");

                r = free_and_strdup(&arg_root_shell, p->pw_shell);
                if (r < 0)
                        return log_oom();
        }

        r = prompt_root_shell(rfd, mute_console_link);
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

        r = prompt_root_password(rfd, mute_console_link);
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

        } else if (arg_delete_root_password) {
                password = PASSWORD_SEE_SHADOW;
                hashed_password = PASSWORD_NONE;
        } else if (!arg_root_password && arg_prompt_root_password) {
                /* If the user was prompted, but no password was supplied, lock the account. */
                password = PASSWORD_SEE_SHADOW;
                hashed_password = PASSWORD_LOCKED_AND_INVALID;
        } else
                /* Leave the password as is. */
                password = hashed_password = NULL;

        /* Don't create/modify passwd and shadow if there's nothing to do. */
        if (!(password || hashed_password || arg_root_shell)) {
                log_debug("Initialization of root account was not requested, skipping.");
                return 0;
        }

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

        pfd = chase_and_open_parent_at(rfd, rfd, "/etc/kernel/cmdline",
                                       CHASE_MKDIR_0755|CHASE_WARN|CHASE_NOFOLLOW,
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

        r = write_string_file_full_label(pfd, "cmdline", arg_kernel_cmdline,
                                   WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_SYNC|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_LABEL,
                                   /* ts= */ NULL, /* label_fn= */ NULL, arg_label_context);
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

        pfd = chase_and_open_parent_at(rfd, rfd, path, CHASE_WARN|CHASE_NOFOLLOW, &f);
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
                       etc_locale_conf(),
                       etc_vconsole_conf(),
                       etc_hostname(),
                       "/etc/machine-id",
                       "/etc/kernel/cmdline",
                       etc_localtime()) {
                r = reset_one(rfd, p);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int parse_key_argument(const char *s) {
        int r;

        assert(s);

        /* Takes "KEYRING:[NAME=]PATH". The certificate in the file becomes the credential
         * "keyring-setup.KEYRING.NAME", which systemd-keyring-setup enrolls into the kernel keyring at boot,
         * with NAME defaulting to the file name without its suffix. */

        const char *e = strchr(s, ':');
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing keyring in '%s', expected KEYRING:[NAME=]PATH.", s);

        _cleanup_free_ char *keyring = strndup(s, e - s);
        if (!keyring)
                return log_oom();
        if (!STR_IN_SET(keyring, "dm-verity", "fs-verity", "bpf"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown keyring '%s', expected dm-verity, fs-verity or bpf.", keyring);

        /* A '=' only separates the name if it comes before any '/', so that a path containing '=' can be
         * passed without a name */
        _cleanup_free_ char *name = NULL, *path = NULL;
        const char *k = e + 1, *eq = strchr(k, '='), *slash = strchr(k, '/');
        if (eq && (!slash || eq < slash)) {
                name = strndup(k, eq - k);
                path = strdup(eq + 1);
        } else {
                _cleanup_free_ char *fn = NULL;
                r = path_extract_filename(k, &fn);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract file name from '%s': %m", k);

                char *dot = strrchr(fn, '.');
                if (dot && dot != fn)
                        *dot = 0;

                name = TAKE_PTR(fn);
                path = strdup(k);
        }
        if (!name || !path)
                return log_oom();

        if (isempty(path))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing key file path in '%s'.", s);
        if (isempty(name) || name[0] == '.')
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing key name in '%s'.", s);
        if (!voa_identifier_is_valid(name, /* allow_colon= */ false))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid key name '%s', expected lowercase letters, digits, '.', '_' and '-'.", name);

        _cleanup_free_ char *id = strjoin("keyring-setup.", keyring, ".", name);
        if (!id)
                return log_oom();
        if (!credential_name_valid(id))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid key name '%s'.", name);

        /* The file is read securely as it might not be a public key after all, and with the limit the
         * credential has at boot, rather than silently cut off there */
        _cleanup_(erase_and_freep) char *data = NULL;
        size_t size;
        r = read_full_file_full(
                        AT_FDCWD, path,
                        /* offset= */ UINT64_MAX,
                        CREDENTIAL_SIZE_MAX,
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_FAIL_WHEN_LARGER,
                        /* bind_name= */ NULL,
                        &data, &size);
        if (r < 0)
                return log_error_errno(r, "Failed to read key file '%s': %m", path);
        if (size == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "Key file '%s' is empty.", path);

        r = machine_credential_add(&arg_keys, id, data, size);
        if (r == -EEXIST)
                return log_error_errno(r, "Key '%s' specified more than once.", name);
        if (r < 0)
                return log_error_errno(r, "Failed to add key '%s': %m", name);

        return 0;
}

static int addon_add_credential(MachineCredentialContext *creds, const char *id, const char *value) {
        int r;

        assert(creds);
        assert(id);

        if (!value)
                return 0;

        r = machine_credential_add(creds, id, value, SIZE_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to add credential '%s': %m", id);

        log_debug("Added credential '%s' to addon.", id);
        return 1;
}

static int write_addon(void) {
        _cleanup_(machine_credential_context_done) MachineCredentialContext creds = {};
        int r;

        assert(arg_addon);
        assert(arg_image);

        /* Instead of applying the settings to the image, turn them into the credentials systemd-firstboot
         * (and PID 1, for the machine ID) consume at boot, pack them into a cpio that an initrd addon
         * carries, and drop that addon into the ESP of the image, so that it customizes an otherwise
         * immutable image. The kernel command line goes into the addon as such. */

        r = addon_add_credential(&creds, "firstboot.locale", arg_locale);
        if (r < 0)
                return r;
        r = addon_add_credential(&creds, "firstboot.locale-messages", arg_locale_messages);
        if (r < 0)
                return r;
        r = addon_add_credential(&creds, "firstboot.keymap", arg_keymap);
        if (r < 0)
                return r;
        r = addon_add_credential(&creds, "firstboot.timezone", arg_timezone);
        if (r < 0)
                return r;
        r = addon_add_credential(&creds, "firstboot.hostname", arg_hostname);
        if (r < 0)
                return r;

        if (arg_machine_tags) {
                _cleanup_free_ char *tags = strv_join(arg_machine_tags, ":");
                if (!tags)
                        return log_oom();

                r = addon_add_credential(&creds, "firstboot.machine-tags", tags);
                if (r < 0)
                        return r;
        }

        if (arg_root_password) {
                /* Never ship the plaintext password, hash it here if needed */
                _cleanup_(erase_and_freep) char *hashed = NULL;
                const char *p = arg_root_password;

                if (!arg_root_password_is_hashed) {
                        r = hash_password(arg_root_password, &hashed);
                        if (r < 0)
                                return log_error_errno(r, "Failed to hash password: %m");
                        p = hashed;
                }

                r = addon_add_credential(&creds, "passwd.hashed-password.root", p);
                if (r < 0)
                        return r;
        }

        r = addon_add_credential(&creds, "passwd.shell.root", arg_root_shell);
        if (r < 0)
                return r;

        if (!sd_id128_is_null(arg_machine_id)) {
                r = addon_add_credential(&creds, "system.machine_id", SD_ID128_TO_STRING(arg_machine_id));
                if (r < 0)
                        return r;
        }

        FOREACH_ARRAY(k, arg_keys.credentials, arg_keys.n_credentials) {
                r = machine_credential_add(&creds, k->id, k->data, k->size);
                if (r < 0)
                        return log_error_errno(r, "Failed to add key '%s': %m", k->id);
        }

        if (creds.n_credentials == 0 && isempty(arg_kernel_cmdline))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No settings specified, refusing to write an empty addon.");

        /* The credentials are subject to the same limit at boot, hence refuse what would be dropped there */
        uint64_t total = 0;
        FOREACH_ARRAY(k, creds.credentials, creds.n_credentials)
                total += k->size;
        if (total > CREDENTIALS_TOTAL_SIZE_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "Credentials are %s in total, which exceeds the limit of %s.",
                                       FORMAT_BYTES(total), FORMAT_BYTES(CREDENTIALS_TOTAL_SIZE_MAX));

        /* Serialize against other instances writing into the same image. An OFD lock, so that it cannot
         * get into the way of mtools, should it take a BSD lock on the image itself. */
        _cleanup_close_ int image_fd = open(arg_image, O_RDWR|O_CLOEXEC);
        if (image_fd < 0)
                return log_error_errno(errno, "Failed to open image '%s': %m", arg_image);

        r = lock_generic(image_fd, LOCK_UNPOSIX, LOCK_EX);
        if (r < 0)
                return log_error_errno(r, "Failed to lock image '%s': %m", arg_image);

        _cleanup_(iovec_done_erase) struct iovec cpio = {};
        if (creds.n_credentials > 0) {
                r = initrd_cpio_credentials_to_memory(&creds, &cpio);
                if (r < 0)
                        return r;
        }

        /* Find the partition the stub will look for addons on, without mounting anything: dissect the
         * partition table only. The stub loads addons from the partition the UKI was loaded from, which is
         * the XBOOTLDR partition if the image has one, and the ESP otherwise. */
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        r = dissect_image_file_and_warn(
                        arg_image,
                        /* verity= */ NULL,
                        /* mount_options= */ NULL,
                        arg_image_policy,
                        /* filter= */ NULL,
                        DISSECT_IMAGE_READ_ONLY|DISSECT_IMAGE_GPT_ONLY,
                        &m);
        if (r < 0)
                return r;
        PartitionDesignator boot = m->partitions[PARTITION_XBOOTLDR].found ? PARTITION_XBOOTLDR : PARTITION_ESP;
        if (!m->partitions[boot].found)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO), "Image '%s' has neither an XBOOTLDR partition nor an EFI System Partition.", arg_image);

        /* mtools wants paths, hence build the addon in a temporary file */
        _cleanup_(unlink_and_freep) char *addon_path = NULL;
        r = tempfn_random_child(/* p= */ NULL, "addon", &addon_path);
        if (r < 0)
                return log_error_errno(r, "Failed to generate temporary file name: %m");

        _cleanup_close_ int addon_fd = open(addon_path, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600);
        if (addon_fd < 0)
                return log_error_errno(errno, "Failed to create temporary file '%s': %m", addon_path);

        const char *stub = secure_getenv("SYSTEMD_ADDON_STUB") ?: PE_ADDON_STUB_PATH;
        r = pe_addon_make(stub, arg_kernel_cmdline, &cpio, addon_fd);
        if (r < 0)
                return r;

        uint64_t offset = m->partitions[boot].offset;

        r = vfat_mkdir(arg_image, offset, "loader/addons");
        if (r < 0)
                return r;

        _cleanup_free_ char *dest = strjoin("loader/addons/", arg_addon, ".addon.efi");
        if (!dest)
                return log_oom();

        r = vfat_copy_file(arg_image, offset, addon_path, dest);
        if (r < 0)
                return r;

        log_info("Wrote addon '%s' with %zu credential%s to the %s of '%s'.",
                 dest, creds.n_credentials, creds.n_credentials == 1 ? "" : "s",
                 boot == PARTITION_XBOOTLDR ? "XBOOTLDR partition" : "ESP", arg_image);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };
        int r;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("root", "PATH", "Operate on an alternate filesystem root"):
                        r = parse_path_argument(opts.arg, true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image", "PATH", "Operate on disk image as filesystem root"):
                        r = parse_path_argument(opts.arg, false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image-policy", "POLICY", "Specify disk image dissection policy"):
                        r = parse_image_policy_argument(opts.arg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("addon", "NAME", "Write settings as PE addon into the boot partition of the image"):
                        /* The name becomes a file name on a FAT file system, which mtools has its own
                         * ideas about, hence be as strict as for boot loader entries */
                        if (!efi_loader_entry_name_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid addon name: %s", opts.arg);

                        r = free_and_strdup_warn(&arg_addon, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("key", "KEYRING:[NAME=]PATH", "Provision a certificate for a kernel keyring via the addon"):
                        r = parse_key_argument(opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("locale", "LOCALE", "Set primary locale (LANG=)"):
                        r = free_and_strdup_warn(&arg_locale, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("locale-messages", "LOCALE", "Set message locale (LC_MESSAGES=)"):
                        r = free_and_strdup_warn(&arg_locale_messages, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("keymap", "KEYMAP", "Set keymap"):
                        if (!keymap_is_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Keymap %s is not valid.", opts.arg);

                        r = free_and_strdup_warn(&arg_keymap, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("timezone", "TIMEZONE", "Set timezone"):
                        if (!timezone_is_valid(opts.arg, LOG_ERR))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Timezone %s is not valid.", opts.arg);

                        r = free_and_strdup_warn(&arg_timezone, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("hostname", "NAME", "Set hostname"):
                        if (!hostname_is_valid(opts.arg, VALID_HOSTNAME_TRAILING_DOT|VALID_HOSTNAME_QUESTION_MARK|VALID_HOSTNAME_WORD_TOKEN))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Host name %s is not valid.", opts.arg);

                        r = free_and_strdup_warn(&arg_hostname, opts.arg);
                        if (r < 0)
                                return r;

                        hostname_cleanup(arg_hostname);
                        break;

                OPTION_LONG("setup-machine-id", NULL, "Set a random machine ID"):
                        r = sd_id128_randomize(&arg_machine_id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to generate randomized machine ID: %m");
                        break;

                OPTION_LONG("machine-id", "ID", "Set specified machine ID"):
                        r = sd_id128_from_string(opts.arg, &arg_machine_id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse machine id %s.", opts.arg);
                        break;

                OPTION_LONG("machine-tags", "TAG[:…]", "Set machine tags"): {
                        _cleanup_strv_free_ char **tags = NULL;
                        r = machine_tags_from_string(opts.arg, /* graceful= */ false, &tags);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse machine tags '%s': %m", opts.arg);

                        strv_free_and_replace(arg_machine_tags, tags);
                        break;
                }

                OPTION_LONG("root-password", "PASSWORD", "Set root password from plaintext password"):
                        r = free_and_strdup_warn(&arg_root_password, opts.arg);
                        if (r < 0)
                                return r;

                        arg_root_password_is_hashed = false;
                        break;

                OPTION_LONG("root-password-file", "FILE", "Set root password from file"):
                        arg_root_password = mfree(arg_root_password);

                        r = read_one_line_file(opts.arg, &arg_root_password);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read %s: %m", opts.arg);

                        arg_root_password_is_hashed = false;
                        break;

                OPTION_LONG("root-password-hashed", "HASH", "Set root password from hashed password"):
                        r = free_and_strdup_warn(&arg_root_password, opts.arg);
                        if (r < 0)
                                return r;

                        arg_root_password_is_hashed = true;
                        break;

                OPTION_LONG("root-shell", "SHELL", "Set root shell"):
                        r = free_and_strdup_warn(&arg_root_shell, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("kernel-command-line", "CMDLINE", "Set kernel command line"):
                        r = free_and_strdup_warn(&arg_kernel_cmdline, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("prompt-locale", NULL, "Prompt the user for locale settings"):
                        arg_prompt_locale = true;
                        break;

                OPTION_LONG("prompt-keymap", NULL, "Prompt the user for keymap settings"):
                        arg_prompt_keymap = true;
                        arg_prompt_keymap_auto = false;
                        break;

                OPTION_LONG("prompt-keymap-auto", NULL,
                            "Prompt the user for keymap settings if invoked on local console"):
                        arg_prompt_keymap_auto = true;
                        break;

                OPTION_LONG("prompt-timezone", NULL, "Prompt the user for timezone"):
                        arg_prompt_timezone = true;
                        break;

                OPTION_LONG("prompt-hostname", NULL, "Prompt the user for hostname"):
                        arg_prompt_hostname = true;
                        break;

                OPTION_LONG("prompt-root-password", NULL, "Prompt the user for root password"):
                        arg_prompt_root_password = true;
                        break;

                OPTION_LONG("prompt-root-shell", NULL, "Prompt the user for root shell"):
                        arg_prompt_root_shell = true;
                        break;

                OPTION_LONG("prompt", NULL, "Prompt for all of the above"):
                        arg_prompt_locale = arg_prompt_keymap = arg_prompt_timezone = arg_prompt_hostname =
                                arg_prompt_root_password = arg_prompt_root_shell = true;
                        arg_prompt_keymap_auto = false;
                        break;

                OPTION_LONG("copy-locale", NULL, "Copy locale from host"):
                        arg_copy_locale = true;
                        break;

                OPTION_LONG("copy-keymap", NULL, "Copy keymap from host"):
                        arg_copy_keymap = true;
                        break;

                OPTION_LONG("copy-timezone", NULL, "Copy timezone from host"):
                        arg_copy_timezone = true;
                        break;

                OPTION_LONG("copy-root-password", NULL, "Copy root password from host"):
                        arg_copy_root_password = true;
                        break;

                OPTION_LONG("copy-root-shell", NULL, "Copy root shell from host"):
                        arg_copy_root_shell = true;
                        break;

                OPTION_LONG("copy", NULL, "Copy all of the above"):
                        arg_copy_locale = arg_copy_keymap = arg_copy_timezone = arg_copy_root_password =
                                arg_copy_root_shell = true;
                        break;

                OPTION_LONG("force", NULL, "Overwrite existing files"):
                        arg_force = true;
                        break;

                OPTION_LONG("delete-root-password", NULL, "Delete root password"):
                        arg_delete_root_password = true;
                        break;

                OPTION_LONG("welcome", "BOOL", "Whether to show the welcome text"):
                        r = parse_boolean_argument("--welcome=", opts.arg, &arg_welcome);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("chrome", "BOOL",
                            "Whether to show a color bar at top and bottom of terminal"):
                        r = parse_boolean_argument("--chrome=", opts.arg, &arg_chrome);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("mute-console", "BOOL",
                            "Whether to disallow kernel/PID 1 writes to the console while running"):
                        r = parse_boolean_argument("--mute-console=", opts.arg, &arg_mute_console);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("reset", NULL, "Remove existing files"):
                        arg_reset = true;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
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

        if (arg_keys.n_credentials > 0 && !arg_addon)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--key= requires --addon=.");

        if (arg_addon) {
                if (!arg_image)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--addon= requires --image=.");

                /* In addon mode we never look inside the image, hence everything that needs its file
                 * system tree is unavailable: prompting (it validates against the installed locales and
                 * keymaps), copying from the host (it would need the image's /etc to compare against), and
                 * modifying files. */
                if (arg_prompt_locale || arg_prompt_keymap || arg_prompt_keymap_auto || arg_prompt_timezone ||
                    arg_prompt_hostname || arg_prompt_root_password || arg_prompt_root_shell)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--addon= cannot be combined with --prompt*.");
                if (arg_copy_locale || arg_copy_keymap || arg_copy_timezone || arg_copy_root_password || arg_copy_root_shell)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--addon= cannot be combined with --copy*.");
                if (arg_reset || arg_force || arg_delete_root_password)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--addon= cannot be combined with --reset, --force or --delete-root-password.");

                /* Normally the locales are checked against what is installed in the target, which we can't
                 * do here. The system consuming the credential doesn't validate them either, hence at least
                 * check the syntax. */
                if (arg_locale && !locale_is_valid(arg_locale))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Locale %s is not valid.", arg_locale);
                if (arg_locale_messages && !locale_is_valid(arg_locale_messages))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Locale %s is not valid.", arg_locale_messages);
                if (arg_root_shell && !valid_shell(arg_root_shell))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s is not a valid shell.", arg_root_shell);
        }

        return 1;
}

static int reload_system_manager(sd_bus **bus) {
        int r;

        assert(bus);

        if (!*bus) {
                r = bus_connect_transport_systemd(BUS_TRANSPORT_LOCAL, NULL, RUNTIME_SCOPE_SYSTEM, bus);
                if (r < 0)
                        return bus_log_connect_error(r, BUS_TRANSPORT_LOCAL, RUNTIME_SCOPE_SYSTEM);
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
                        return bus_log_connect_error(r, BUS_TRANSPORT_LOCAL, RUNTIME_SCOPE_SYSTEM);
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

        r = bus_wait_for_jobs_one(w, object, BUS_WAIT_JOBS_LOG_ERROR);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for systemd-vconsole-setup.service/restart: %m");
        return 0;
}

static void end_marker(void) {

        if (!welcome_done)
                return;

        printf("\n%sExiting first boot settings tool.%s\n\n", ansi_grey(), ansi_normal());
        fflush(stdout);
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        _cleanup_close_ int rfd = -EBADF;
        int r;

        LIBBLKID_NOTE(recommended);
        LIBCRYPT_NOTE(recommended);
        LIBCRYPTO_NOTE(suggested);
        LIBCRYPTSETUP_NOTE(suggested);
        LIBMOUNT_NOTE(recommended);
        LIBSELINUX_NOTE(recommended);
        PASSWORD_NOTE(suggested);
        TPM2_NOTE(suggested);

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

                FirstBootMode mode;
                _cleanup_free_ char *bad = NULL;
                r = firstboot_mode_from_cmdline(&mode, &bad);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse systemd.firstboot= kernel command line argument%s: %m",
                                               bad ? strjoina(" (invalid value '", bad, "')") : "");
                if (mode == FIRSTBOOT_NO) {
                        log_debug("Found systemd.firstboot=no kernel command line argument, turning off all prompts.");
                        arg_prompt_locale = arg_prompt_keymap = arg_prompt_keymap_auto = arg_prompt_timezone = arg_prompt_hostname = arg_prompt_root_password = arg_prompt_root_shell = false;
                } else if (mode == FIRSTBOOT_HEADLESS) {
                        log_debug("Found systemd.firstboot=headless kernel command line argument, skipping interactive prompts but keeping non-interactive auto-configuration.");
                        arg_headless = true;
                }
        }

        if (arg_addon)
                return write_addon();

        r = mac_init();
        if (r < 0)
                return r;

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
                                DISSECT_IMAGE_GROWFS |
                                DISSECT_IMAGE_ALLOW_USERSPACE_VERITY,
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

        r = mac_label_context_new(arg_root, &arg_label_context);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize label context for root '%s': %m", arg_root);

        LOG_SET_PREFIX(arg_image ?: arg_root);
        DEFER_VOID_CALL(end_marker);
        DEFER_VOID_CALL(chrome_hide);

        /* We check these conditions here instead of in parse_argv() so that we can take the root directory
         * into account. */

        if (arg_keymap && !keymap_is_ok(arg_keymap, FD_TO_PTR(rfd)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Keymap %s is not installed.", arg_keymap);
        if (arg_locale && !locale_is_ok(arg_locale, FD_TO_PTR(rfd)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Locale %s is not installed.", arg_locale);
        if (arg_locale_messages && !locale_is_ok(arg_locale_messages, FD_TO_PTR(rfd)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Locale %s is not installed.", arg_locale_messages);

        if (arg_root_shell) {
                r = find_shell(rfd, arg_root_shell);
                if (r < 0)
                        return r;
        }

        r = process_reset(rfd);
        if (r < 0)
                return r;

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *mute_console_link = NULL;
        r = process_locale(rfd, &mute_console_link);
        if (r < 0)
                return r;
        if (r > 0 && !offline)
                (void) reload_system_manager(&bus);

        r = process_keymap(rfd, &mute_console_link);
        if (r < 0)
                return r;
        if (r > 0 && !offline)
                (void) reload_vconsole(&bus);

        r = process_timezone(rfd, &mute_console_link);
        if (r < 0)
                return r;

        r = process_hostname(rfd, &mute_console_link);
        if (r < 0)
                return r;

        r = process_root_account(rfd, &mute_console_link);
        if (r < 0)
                return r;

        r = process_kernel_cmdline(rfd);
        if (r < 0)
                return r;

        r = process_machine_id(rfd);
        if (r < 0)
                return r;

        r = process_machine_tags(rfd);
        if (r < 0)
                return r;

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
