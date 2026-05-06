/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-varlink.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "blockdev-list.h"
#include "build.h"
#include "build-path.h"
#include "chase.h"
#include "conf-files.h"
#include "constants.h"
#include "efi-loader.h"
#include "efivars.h"
#include "env-file.h"
#include "escape.h"
#include "fd-util.h"
#include "find-esp.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "help-util.h"
#include "image-policy.h"
#include "json-util.h"
#include "locale-setup.h"
#include "log.h"
#include "loop-util.h"
#include "machine-credential.h"
#include "main-func.h"
#include "mount-util.h"
#include "options.h"
#include "os-util.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "prompt-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "varlink-util.h"

static char *arg_node = NULL;
static bool arg_welcome = true;
static int arg_erase = -1;            /* tri-state */
static bool arg_confirm = true;
static bool arg_summary = true;
static char **arg_definitions = NULL;
static char *arg_kernel_image = NULL;
static bool arg_reboot = false;
static int arg_touch_variables = -1;  /* tri-state */
static MachineCredentialContext arg_credentials = {};
static bool arg_copy_locale = true;
static bool arg_copy_keymap = true;
static bool arg_copy_timezone = true;
static bool arg_chrome = true;
static bool arg_mute_console = false;

STATIC_DESTRUCTOR_REGISTER(arg_node, freep);
STATIC_DESTRUCTOR_REGISTER(arg_definitions, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_kernel_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_credentials, machine_credential_context_done);

static int help(void) {
        int r;

        _cleanup_(table_unrefp) Table *options = NULL;
        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        help_cmdline("[OPTIONS...] [DEVICE]");
        help_abstract("Installs the OS to another block device.");
        help_section("Options:");

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("systemd-sysinstall", "8");

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("welcome", "no", "Disable the welcome text"):
                        r = parse_boolean_argument("--welcome=", opts.arg, &arg_welcome);
                        if (r < 0)
                                return r;

                        break;

                OPTION_LONG("erase", "BOOL", "Whether to erase the target disk"):
                        r = parse_tristate_argument_with_auto("--erase=", opts.arg, &arg_erase);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("confirm", "no", "Disable query for confirmation"):
                        r = parse_boolean_argument("--confirm=", opts.arg, &arg_confirm);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("summary", "no", "Disable summary before beginning operation"):
                        r = parse_boolean_argument("--summary=", opts.arg, &arg_summary);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("definitions", "DIR", "Find partition definitions in specified directory"): {
                        _cleanup_free_ char *path = NULL;
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &path);
                        if (r < 0)
                                return r;
                        if (strv_consume(&arg_definitions, TAKE_PTR(path)) < 0)
                                return log_oom();
                        break;
                }

                OPTION_LONG("reboot", "BOOL", "Whether to reboot after installation is complete"):
                        r = parse_boolean_argument("--reboot=", opts.arg, &arg_reboot);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("variables", "BOOL", "Whether to modify EFI variables"):
                        r = parse_tristate_argument_with_auto("--variables=", opts.arg, &arg_touch_variables);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("kernel", "IMAGE", "Explicitly pick kernel image to install"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_kernel_image);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("set-credential", "ID:VALUE", "Install a credential with literal value to target system"):
                        r = machine_credential_set(&arg_credentials, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("load-credential", "ID:PATH", "Load a credential to install to new system from file or AF_UNIX stream socket"):
                        r = machine_credential_load(&arg_credentials, opts.arg);
                        if (r < 0)
                                return r;

                        break;

                OPTION_LONG("copy-locale", "no", "Don't copy current locale to target system"):
                        r = parse_boolean_argument("--copy-locale=", opts.arg, &arg_copy_locale);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("copy-keymap", "no", "Don't copy current keymap to target system"):
                        r = parse_boolean_argument("--copy-keymap=", opts.arg, &arg_copy_keymap);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("copy-timezone", "no", "Don't copy current timezone to target system"):
                        r = parse_boolean_argument("--copy-timezone=", opts.arg, &arg_copy_timezone);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("chrome", "no", "Whether to show a color bar at top and bottom of terminal"):
                        r = parse_boolean_argument("--chrome=", opts.arg, &arg_chrome);
                        if (r < 0)
                                return r;

                        break;

                OPTION_LONG("mute-console", "BOOL", "Whether to disallow kernel/PID 1 writes to the console while running"):
                        r = parse_boolean_argument("--mute-console=", opts.arg, &arg_mute_console);
                        if (r < 0)
                                return r;
                        break;
                }

        char **args = option_parser_get_args(&opts);

        if (strv_length(args) > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too many arguments.");
        if (!strv_isempty(args)) {
                arg_node = strdup(args[0]);
                if (!arg_node)
                        return log_oom();
        }

        return 1;
}

static int print_welcome(sd_varlink **mute_console_link) {
        _cleanup_free_ char *pretty_name = NULL, *os_name = NULL, *ansi_color = NULL, *fancy_name = NULL;
        const char *pn, *ac;
        int r;

        assert(mute_console_link);

        if (!*mute_console_link && arg_mute_console)
                (void) mute_console(mute_console_link);

        if (!arg_welcome)
                return 0;

        r = parse_os_release(
                        /* root= */ NULL,
                        "PRETTY_NAME", &pretty_name,
                        "FANCY_NAME",  &fancy_name,
                        "NAME",        &os_name,
                        "ANSI_COLOR",  &ansi_color);
        if (r < 0)
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to read os-release file, ignoring: %m");

        pn = os_release_pretty_name(pretty_name, os_name);
        ac = isempty(ansi_color) ? "0" : ansi_color;

        if (use_fancy_name(unescape_fancy_name(&fancy_name)))
                printf(ANSI_HIGHLIGHT "Welcome to the " ANSI_NORMAL "%s" ANSI_HIGHLIGHT " Installer!" ANSI_NORMAL "\n", fancy_name);
        else if (colors_enabled())
                printf(ANSI_HIGHLIGHT "Welcome to the " ANSI_NORMAL "\x1B[%sm%s" ANSI_HIGHLIGHT " Installer!" ANSI_NORMAL "\n", ac, pn);
        else
                printf("Welcome to the %s Installer!\n", pn);

        putchar('\n');

        return 0;
}

static int connect_to_repart(sd_varlink **link) {
        int r;

        assert(link);

        if (*link) {
                /* Reset the time-out to default here, since we are reusing the connection, but might enqueue
                 * a different operation */
                r = sd_varlink_set_relative_timeout(*link, 0);
                if (r < 0)
                        return r;

                return 0;
        }

        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *repart = NULL;
        fd = pin_callout_binary("systemd-repart", &repart);
        if (fd < 0)
                return log_error_errno(fd, "Failed to find systemd-repart binary: %m");

        r = sd_varlink_connect_exec(link, repart, /* argv= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to systemd-repart: %m");

        return 1;
}

static int acquire_device_list(
                sd_varlink **link,
                char ***ret_menu,
                char ***ret_accepted) {
        int r;

        r = connect_to_repart(link);
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **menu = NULL, **accepted = NULL;

        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_collectbo(
                        *link,
                        "io.systemd.Repart.ListCandidateDevices",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR_BOOLEAN("ignoreRoot", true));
        if (r < 0)
                return log_error_errno(r, "Failed to issue io.systemd.Repart.ListCandidateDevices() varlink call: %m");
        if (streq_ptr(error_id, "io.systemd.Repart.NoCandidateDevices"))
                log_debug("No candidate devices found.");
        else if (error_id) {
                r = sd_varlink_error_to_errno(error_id, reply); /* If this is a system errno style error, output it with %m */
                if (r != -EBADR)
                        return log_error_errno(r, "Failed to issue io.systemd.Repart.ListCandidateDevices() varlink call: %m");

                return log_error_errno(r, "Failed to issue io.systemd.Repart.ListCandidateDevices() varlink call: %s", error_id);
        } else {
                sd_json_variant *i;
                JSON_VARIANT_ARRAY_FOREACH(i, reply) {
                        _cleanup_(block_device_done) BlockDevice bd = BLOCK_DEVICE_NULL;

                        static const sd_json_dispatch_field dispatch_table[] = {
                                { "node",     SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(BlockDevice, node),     SD_JSON_MANDATORY },
                                { "symlinks", SD_JSON_VARIANT_ARRAY,  sd_json_dispatch_strv,   offsetof(BlockDevice, symlinks), 0                 },
                                {}
                        };

                        r = sd_json_dispatch(i, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, &bd);
                        if (r < 0)
                                return r;

                        if (strv_extend(&accepted, bd.node) < 0)
                                return log_oom();
                        if (strv_extend_strv(&accepted, bd.symlinks, /* filter_duplicates= */ true) < 0)
                                return log_oom();

                        /* Prefer the by-id and by-loop-ref because they typically contain the strings most
                         * directly understood by the user */
                        const char *n = strv_find_prefix(bd.symlinks, "/dev/disk/by-id/");
                        if (!n)
                                n = strv_find_prefix(bd.symlinks, "/dev/disk/by-loop-ref/");
                        if (!n)
                                n = bd.node;

                        if (strv_extend(&menu, n) < 0)
                                return log_oom();
                }
        }

        *ret_menu = TAKE_PTR(menu);
        *ret_accepted = TAKE_PTR(accepted);
        return 0;
}

static int device_is_valid(const char *node, void *userdata) {

        if (!path_is_valid(node) || !path_is_absolute(node)) {
                log_error("Not a valid absolute file system path, refusing: %s", node);
                return false;
        }

        struct stat st;
        if (stat(node, &st) < 0) {
                log_error_errno(errno, "Failed to check if '%s' is a valid block device node: %m", node);
                return false;
        }
        if (!S_ISBLK(st.st_mode)) {
                log_error("Path '%s' does not refer to a valid block device node, refusing.", node);
                return false;
        }

        return true;
}

static int refresh_devices(char ***ret_menu, char ***ret_accepted, void *userdata) {
        sd_varlink **repart_link = ASSERT_PTR(userdata);

        (void) acquire_device_list(repart_link, ret_menu, ret_accepted);
        return 0;
}

static int prompt_block_device(sd_varlink **repart_link, char **ret_node) {
        int r;

        putchar('\n');

        _cleanup_strv_free_ char **menu = NULL, **accepted = NULL;
        (void) acquire_device_list(repart_link, &menu, &accepted);

        r = prompt_loop("Please enter target disk device",
                        GLYPH_COMPUTER_DISK,
                        menu,
                        accepted,
                        /* ellipsize_percentage= */ 20,
                        /* n_columns= */ 1,
                        /* column_width= */ 80,
                        device_is_valid,
                        refresh_devices,
                        /* userdata= */ repart_link,
                        PROMPT_SHOW_MENU|PROMPT_SHOW_MENU_NOW|PROMPT_MAY_SKIP|PROMPT_HIDE_SKIP_HINT|PROMPT_HIDE_MENU_HINT,
                        ret_node);
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ECANCELED), "Installation cancelled.");

        return 0;
}

static int read_space_metrics(
                sd_json_variant *v,
                uint64_t *min_size,
                uint64_t *current_size,
                uint64_t *need_free) {

        int r;

        struct {
                uint64_t min_size;
                uint64_t current_size;
                uint64_t need_free;
        } p = {
                .min_size = UINT64_MAX,
                .current_size = UINT64_MAX,
                .need_free = UINT64_MAX,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "minimalSizeBytes", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, voffsetof(p, min_size),     0 },
                { "currentSizeBytes", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, voffsetof(p, current_size), 0 },
                { "needFreeBytes",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, voffsetof(p, need_free),    0 },
                {}
        };

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return r;

        if (min_size)
                *min_size = p.min_size;
        if (current_size)
                *current_size = p.current_size;
        if (need_free)
                *need_free = p.need_free;

        return 0;
}

static int invoke_repart(
                sd_varlink **link,
                const char *node,
                bool erase,
                bool dry_run,
                uint64_t *min_size,        /* initialized both on success and error */
                uint64_t *current_size,    /* ditto */
                uint64_t *need_free) {     /* ditto */

        int r;

        assert(link);

        /* Note, if dry_run is true, then ENOSPC, E2BIG, EHWPOISON will not be logged about beyond LOG_DEBUG,
         * but all other errors will be */

        r = connect_to_repart(link);
        if (r < 0) {
                read_space_metrics(/* v= */ NULL, min_size, current_size, need_free);
                return r;
        }

        if (!dry_run) {
                /* Seeding the partitions might be very slow, disable timeout */
                r = sd_varlink_set_relative_timeout(*link, UINT64_MAX);
                if (r < 0)
                        return log_error_errno(r, "Failed to disable IPC timeout: %m");
        }

        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_callbo(
                        *link,
                        "io.systemd.Repart.Run",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR_STRING("node", node),
                        SD_JSON_BUILD_PAIR_STRING("empty", erase ? "force" : "allow"),
                        SD_JSON_BUILD_PAIR_BOOLEAN("dryRun", dry_run),
                        SD_JSON_BUILD_PAIR_CONDITION(!!arg_definitions, "definitions", SD_JSON_BUILD_STRV(arg_definitions)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("deferPartitionsEmpty", true),
                        SD_JSON_BUILD_PAIR_BOOLEAN("deferPartitionsFactoryReset", true));
        if (r < 0) {
                read_space_metrics(/* v= */ NULL, min_size, current_size, need_free);
                return log_error_errno(r, "Failed to issue io.systemd.Repart.Run() varlink call: %m");
        }
        if (error_id) {
                if (streq(error_id, "io.systemd.Repart.InsufficientFreeSpace")) {
                        (void) read_space_metrics(reply, min_size, current_size, need_free);
                        return log_full_errno(
                                        dry_run ? LOG_DEBUG : LOG_ERR,
                                        SYNTHETIC_ERRNO(ENOSPC),
                                        "Not enough free space on disk, cannot install.");
                }
                if (streq(error_id, "io.systemd.Repart.DiskTooSmall")) {
                        (void) read_space_metrics(reply, min_size, current_size, need_free);
                        return log_full_errno(
                                        dry_run ? LOG_DEBUG : LOG_ERR,
                                        SYNTHETIC_ERRNO(E2BIG),
                                        "Disk too small for installation, cannot install.");
                }

                /* For all other errors reset the metrics */
                read_space_metrics(/* v= */ NULL, min_size, current_size, need_free);

                if (streq(error_id, "io.systemd.Repart.ConflictingDiskLabelPresent"))
                        return log_full_errno(
                                        dry_run ? LOG_DEBUG : LOG_ERR,
                                        SYNTHETIC_ERRNO(EHWPOISON),
                                        "A conflicting disk label is already present on the target disk, cannot install unless disk is erased.");

                r = sd_varlink_error_to_errno(error_id, reply); /* If this is a system errno style error, output it with %m */
                if (r != -EBADR)
                        return log_error_errno(r, "Failed to issue io.systemd.Repart.Run() varlink call: %m");

                return log_error_errno(r, "Failed to issue io.systemd.Repart.Run() varlink call: %s", error_id);
        }

        (void) read_space_metrics(reply, min_size, current_size, need_free);

        return 0;
}

static int prompt_erase(
                bool can_add,
                int *ret_erase) {
        int r;

        assert(ret_erase);

        putchar('\n');

        char **l = can_add ? STRV_MAKE("keep", "erase") : STRV_MAKE("erase");

        _cleanup_free_ char *reply = NULL;
        r = prompt_loop(can_add ?
                        "Please type 'keep' to install the OS in addition to what the disk already contains, or 'erase' to erase all data on the disk" :
                        "Please type 'erase' to confirm that all data on the disk shall be erased",
                        GLYPH_BROOM,
                        /* menu= */ l,
                        /* accepted= */ l,
                        /* ellipsize_percentage= */ 20,
                        /* n_columns= */ 2,
                        /* column_width= */ 40,
                        /* is_valid= */ NULL,
                        /* refresh= */ NULL,
                        /* userdata= */ NULL,
                        PROMPT_SHOW_MENU|PROMPT_MAY_SKIP|PROMPT_HIDE_MENU_HINT|PROMPT_HIDE_SKIP_HINT,
                        &reply);
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ECANCELED), "Installation cancelled.");

        if (streq(reply, "erase"))
                *ret_erase = true;
        else if (streq(reply, "keep"))
                *ret_erase = false;
        else
                assert_not_reached();

        return 0;
}

static int prompt_touch_variables(void) {
        int r;

        if (arg_touch_variables >= 0)
                return 0;

        putchar('\n');

        char **l = STRV_MAKE("yes", "no");

        _cleanup_free_ char *reply = NULL;
        r = prompt_loop("Type 'yes' to register OS installation in firmware variables of the local system, 'no' otherwise",
                        GLYPH_ROCKET,
                        /* menu= */ l,
                        /* accepted= */ l,
                        /* ellipsize_percentage= */ 20,
                        /* n_columns= */ 2,
                        /* column_width= */ 40,
                        /* is_valid= */ NULL,
                        /* refresh= */ NULL,
                        /* userdata= */ NULL,
                        PROMPT_SHOW_MENU|PROMPT_MAY_SKIP|PROMPT_HIDE_MENU_HINT|PROMPT_HIDE_SKIP_HINT,
                        &reply);
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ECANCELED), "Installation cancelled.");

        r = parse_boolean(reply);
        if (r < 0)
                return log_error_errno(r, "Failed to parse reply: %s", reply);

        arg_touch_variables = r;

        return 0;
}

static int prompt_confirm(void) {
        int r;

        if (!arg_confirm)
                return 0;

        putchar('\n');

        char **l = STRV_MAKE("yes", "no");

        _cleanup_free_ char *reply = NULL;
        r = prompt_loop(arg_summary ? "Please type 'yes' to confirm the choices above and begin the installation" :
                                      "Please type 'yes' to begin the installation",
                        GLYPH_WARNING_SIGN,
                        /* menu= */ l,
                        /* accepted= */ l,
                        /* ellipsize_percentage= */ 20,
                        /* n_columns= */ 2,
                        /* column_width= */ 40,
                        /* is_valid= */ NULL,
                        /* refresh= */ NULL,
                        /* userdata= */ NULL,
                        PROMPT_SHOW_MENU|PROMPT_MAY_SKIP|PROMPT_HIDE_MENU_HINT|PROMPT_HIDE_SKIP_HINT,
                        &reply);
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ECANCELED), "Installation cancelled.");

        if (!streq(reply, "yes"))
                return log_error_errno(SYNTHETIC_ERRNO(ECANCELED), "Installation not confirmed, cancelling.");

        return 0;
}

static int validate_run(sd_varlink **repart_link, const char *node) {
        int r;

        assert(repart_link);
        assert(node);

        /* First loop: either with explicitly configured --erase= value, or false. A second loop only if not configured explicitly. */
        bool try_erase = arg_erase > 0, conflicting_disk_label = false;
        for (;;) {
                uint64_t min_size = UINT64_MAX, current_size = UINT64_MAX, need_free = UINT64_MAX;
                r = invoke_repart(
                                repart_link,
                                node,
                                try_erase,
                                /* dry_run= */ true,
                                &min_size,
                                &current_size,
                                &need_free);
                if (r == -ENOSPC) {
                        /* The disk is large enough, but there's not enough unallocated space. Hence proceed, but require erasing */
                        if (try_erase || arg_erase >= 0)
                                return log_error_errno(r, "The selected disk is big enough for the installation but does not have enough free space.");

                        log_notice("The selected disk is big enough for the installation but does not have enough free space. Installation will require erasing.");
                        if (need_free != UINT64_MAX)
                                log_info("Required free space is %s.", FORMAT_BYTES(need_free));

                        try_erase = true;
                } else if (r == -E2BIG) {
                        /* Won't fit, whatever we do */
                        log_error_errno(r, "The selected disk is not large enough for an OS installation.");
                        if (current_size != UINT64_MAX)
                                log_info("The size of the selected disk is %s, but a minimal size of %s is required.",
                                         FORMAT_BYTES(current_size),
                                         FORMAT_BYTES(min_size));
                        return r;
                } else if (r == -EHWPOISON) {
                        if (try_erase || arg_erase >= 0)
                                return log_error_errno(r, "The selected disk contains a conflicting disk label, refusing.");

                        log_debug("Disk contains a conflicting disk label, checking if we could install the OS after erasing it.");
                        try_erase = true;
                        conflicting_disk_label = true;
                        continue;
                } else if (r < 0)
                        /* invoke_repart() already logged about all other errors */
                        return r;
                else
                        /* Nice, we can add the OS to the disk, without erasing anything. */
                        log_info("The selected disk has enough free space for an installation of the OS.");

                if (conflicting_disk_label)
                        log_warning("A conflicting disk label has been found, and must be erased for installation.");

                if (arg_erase < 0) {
                        r = prompt_erase(/* can_add= */ !try_erase, &arg_erase);
                        if (r < 0)
                                return r;
                }

                return 0;
        }
}

static int show_summary(void) {
        int r;

        if (!arg_summary)
                return 0;

        printf("\n"
               "%sSummary:%s\n", ansi_underline(), ansi_normal());

        _cleanup_(table_unrefp) Table *table = table_new_vertical();
        if (!table)
                return log_oom();

        r = table_add_many(
                        table,
                        TABLE_FIELD, "Selected Disk",
                        TABLE_STRING, arg_node,
                        TABLE_FIELD, "Erase Disk",
                        TABLE_BOOLEAN, arg_erase,
                        TABLE_SET_COLOR, arg_erase ? ansi_highlight_red() : NULL,
                        TABLE_FIELD, "Register in Firmware",
                        TABLE_BOOLEAN, arg_touch_variables);
        if (r < 0)
                return table_log_add_error(r);

        static const char * const map[] = {
                "firstboot.keymap",          "Keyboard Map",
                "firstboot.locale",          "Locale",
                "firstboot.locale-messages", "Locale (Messages)",
                "firstboot.timezone",        "Timezone",
                NULL
        };

        STRV_FOREACH_PAIR(id, text, map) {
                MachineCredential *c = machine_credential_find(&arg_credentials, *id);
                if (!c)
                        continue;

                _cleanup_free_ char *escaped = cescape_length(c->data, c->size);
                if (!escaped)
                        return log_oom();

                r = table_add_many(
                                table,
                                TABLE_FIELD, *text,
                                TABLE_STRING, escaped);
                if (r < 0)
                        return table_log_add_error(r);
        }

        unsigned n_extra_credentials = 0;
        FOREACH_ARRAY(cred, arg_credentials.credentials, arg_credentials.n_credentials) {
                bool covered = false;

                STRV_FOREACH_PAIR(id, text, map)
                        if (streq(*id, cred->id)) {
                                covered = true;
                                break;
                        }

                if (!covered)
                        n_extra_credentials++;
        }

        if (n_extra_credentials > 0) {
                r = table_add_many(
                                table,
                                TABLE_FIELD, "Extra Credentials",
                                TABLE_UINT, n_extra_credentials);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_print(table);
        if (r < 0)
                return r;

        return 0;
}

static int find_current_kernel(
                char **ret_filename,
                int *ret_fd) {

        int r;

        sd_id128_t uuid;
        r = efi_stub_get_device_part_uuid(&uuid);
        if (r == -ENOENT)
                return log_error_errno(r, "Cannot find current kernel, no stub partition UUID passed via EFI variables.");
        if (r < 0)
                return log_error_errno(r, "Unable to determine stub partition UUID: %m");

        _cleanup_free_ char *image = NULL;
        r = efi_get_variable_path(EFI_LOADER_VARIABLE_STR("StubImageIdentifier"), &image);
        if (r == -ENOENT)
                return log_error_errno(r, "Cannot find current kernel, no stub EFI binary path passed.");
        if (r < 0)
                return log_error_errno(r, "Unable to determine stub EFI binary path: %m");

        /* Note: we search for the *host* ESP here (i.e. the one the current EFI paths relate to), not the
         * one of the target image */

        _cleanup_free_ char *partition_path = NULL;
        _cleanup_close_ int partition_fd = -EBADF;
        sd_id128_t partition_uuid;
        r = find_esp_and_warn_full(
                        /* root= */ NULL,
                        /* path= */ NULL,
                        /* unprivileged_mode= */ false,
                        &partition_path,
                        &partition_fd,
                        /* ret_part= */ NULL,
                        /* ret_pstart= */ NULL,
                        /* ret_psize= */ NULL,
                        &partition_uuid,
                        /* ret_devid= */ NULL);
        if (r < 0 && r != -ENOKEY)
                return r;
        if (r < 0 || !sd_id128_equal(uuid, partition_uuid)) {
                partition_path = mfree(partition_path);
                partition_fd = safe_close(partition_fd);

                r = find_xbootldr_and_warn_full(
                                /* root= */ NULL,
                                /* path= */ NULL,
                                /* unprivileged_mode= */ false,
                                &partition_path,
                                &partition_fd,
                                &partition_uuid,
                                /* ret_devid= */ NULL);
                if (r < 0 && r != -ENOKEY)
                        return r;

                if (r < 0 || !sd_id128_equal(uuid, partition_uuid))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Unable to find UKI on ESP/XBOOTLDR partitions.");
        }

        _cleanup_free_ char *resolved = NULL;
        _cleanup_close_ int fd = chase_and_openat(
                        /* root_fd= */ partition_fd,
                        /* dir_fd= */ partition_fd,
                        image,
                        CHASE_PROHIBIT_SYMLINKS|CHASE_MUST_BE_REGULAR,
                        O_RDONLY|O_CLOEXEC,
                        &resolved);
        if (fd < 0)
                return log_error_errno(fd, "Failed to find EFI binary '%s' on partition '%s': %m", image, partition_path);

        _cleanup_free_ char *fn = NULL;
        r = path_extract_filename(resolved, &fn);
        if (r < 0)
                return log_error_errno(r, "Failed to extract UKI file name from '%s': %m", resolved);

        if (ret_filename)
                *ret_filename = TAKE_PTR(fn);
        if (ret_fd)
                *ret_fd = TAKE_FD(fd);

        return 0;
}

static int connect_to_bootctl(sd_varlink **link) {
        int r;

        assert(link);

        if (*link)
                return 0;

        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *bootctl = NULL;
        fd = pin_callout_binary("bootctl", &bootctl);
        if (fd < 0)
                return log_error_errno(fd, "Failed to find bootctl binary: %m");

        r = sd_varlink_connect_exec(link, bootctl, /* argv= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to bootctl: %m");

        r = sd_varlink_set_allow_fd_passing_output(*link, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable fd passing to bootctl: %m");

        return 1;
}

static int invoke_bootctl_install(
                sd_varlink **link,
                const char *root_dir,
                int root_fd) {
        int r;

        assert(link);
        assert(root_dir);
        assert(root_fd >= 0);

        r = connect_to_bootctl(link);
        if (r < 0)
                return r;

        int fd_idx = sd_varlink_push_dup_fd(*link, root_fd);
        if (fd_idx < 0)
                return log_error_errno(fd_idx, "Failed to submit root fd onto Varlink connection: %m");

        const char *error_id = NULL;
        r = varlink_callbo_and_log(
                        *link,
                        "io.systemd.BootControl.Install",
                        /* reply= */ NULL,
                        &error_id,
                        SD_JSON_BUILD_PAIR_STRING("operation", "new"),
                        SD_JSON_BUILD_PAIR_INTEGER("rootFileDescriptor", fd_idx),
                        SD_JSON_BUILD_PAIR_STRING("rootDirectory", root_dir),
                        SD_JSON_BUILD_PAIR_BOOLEAN("touchVariables", arg_touch_variables));
        if (r < 0)
                return r;

        return 0;
}

static int invoke_bootctl_link(
                sd_varlink **link,
                const char *root_dir,
                int root_fd,
                char **encrypted_credentials) {
        int r;

        assert(link);
        assert(root_dir);
        assert(root_fd >= 0);

        r = connect_to_bootctl(link);
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        STRV_FOREACH_PAIR(name, value, encrypted_credentials) {
                _cleanup_free_ char *j = strjoin(*name, ".cred");
                if (!j)
                        return log_oom();

                r = sd_json_variant_append_arraybo(
                                &array,
                                SD_JSON_BUILD_PAIR_STRING("filename", j),
                                SD_JSON_BUILD_PAIR_BASE64("data", *value, strlen(*value)));
                if (r < 0)
                        return log_error_errno(r, "Failed to append credential to message: %m");
        }

        int root_fd_idx = sd_varlink_push_dup_fd(*link, root_fd);
        if (root_fd_idx < 0)
                return log_error_errno(root_fd_idx, "Failed to submit root fd onto Varlink connection: %m");

        _cleanup_free_ char *kernel_filename = NULL;
        _cleanup_close_ int kernel_fd = -EBADF;
        if (arg_kernel_image) {
                r = path_extract_filename(arg_kernel_image, &kernel_filename);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from kernel path '%s': %m", arg_kernel_image);
                if (r == O_DIRECTORY)
                        return log_error_errno(SYNTHETIC_ERRNO(EISDIR), "Kernel path '%s' refers to directory, must be regular file, refusing.", arg_kernel_image);

                kernel_fd = xopenat_full(XAT_FDROOT, arg_kernel_image, O_RDONLY|O_CLOEXEC, XO_REGULAR, MODE_INVALID);
                if (kernel_fd < 0)
                        return log_error_errno(kernel_fd, "Failed to open kernel image '%s': %m", arg_kernel_image);

        } else {
                r = find_current_kernel(&kernel_filename, &kernel_fd);
                if (r < 0)
                        return r;
        }

        int kernel_fd_idx = sd_varlink_push_dup_fd(*link, kernel_fd);
        if (kernel_fd_idx < 0)
                return log_error_errno(kernel_fd_idx, "Failed to submit kernel fd onto Varlink connection: %m");

        const char *error_id = NULL;
        r = varlink_callbo_and_log(
                        *link,
                        "io.systemd.BootControl.Link",
                        /* reply= */ NULL,
                        &error_id,
                        SD_JSON_BUILD_PAIR_INTEGER("rootFileDescriptor", root_fd_idx),
                        SD_JSON_BUILD_PAIR_STRING("rootDirectory", root_dir),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("kernelFilename", kernel_filename),
                        SD_JSON_BUILD_PAIR_INTEGER("kernelFileDescriptor", kernel_fd_idx),
                        SD_JSON_BUILD_PAIR_CONDITION(!!array, "extraFiles", SD_JSON_BUILD_VARIANT(array)));
        if (r < 0)
                return r;

        return 0;
}

static int maybe_reboot(void) {
        int r;

        if (!arg_reboot)
                return 0;

        log_notice("%s%sSystem will reboot now.",
                   emoji_enabled() ? glyph(GLYPH_CIRCLE_ARROW) : "", emoji_enabled() ? " " : "");

        if (!any_key_to_proceed())
                return 0;

        log_notice("%s%sInitiating reboot.",
                   emoji_enabled() ? glyph(GLYPH_CIRCLE_ARROW) : "", emoji_enabled() ? " " : "");

        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        r = sd_varlink_connect_address(&link, "/run/systemd/io.systemd.Shutdown");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to systemd-logind: %m");

        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = varlink_callbo_and_log(
                        link,
                        "io.systemd.Shutdown.Reboot",
                        &reply,
                        &error_id);
        if (r < 0)
                return r;

        return 0;
}

static int read_credential_locale(void) {
        int r;

        if (!arg_copy_locale)
                return 0;

        if (machine_credential_find(&arg_credentials, "firstboot.locale") ||
            machine_credential_find(&arg_credentials, "firstboot.locale-messages"))
                return 0;

        /* For the main locale we check the two env vars, and if neither is there, we use LC_NUMERIC, since
         * it seems to be one of the most fundamental ones, and is not LC_MESSAGES for which we have a
         * separate setting after all */
        const char *l = getenv("LC_ALL") ?: getenv("LANG") ?: setlocale(LC_NUMERIC, NULL);
        if (l) {
                r = machine_credential_add(&arg_credentials, "firstboot.locale", l, /* size= */ SIZE_MAX);
                if (r < 0)
                        return log_oom();
        }

        const char *m = setlocale(LC_MESSAGES, NULL);
        if (m && !streq_ptr(m, l)) {
                r = machine_credential_add(&arg_credentials, "firstboot.locale-messages", m, /* size= */ SIZE_MAX);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int read_credential_keymap(void) {
        int r;

        if (!arg_copy_keymap)
                return 0;

        if (machine_credential_find(&arg_credentials, "firstboot.keymap"))
                return 0;

        _cleanup_free_ char *keymap = NULL;
        r = parse_env_file(
                        /* f= */ NULL,
                        etc_vconsole_conf(),
                        "KEYMAP", &keymap);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to parse '%s': %m", etc_vconsole_conf());

        if (!isempty(keymap)) {
                r = machine_credential_add(&arg_credentials, "firstboot.keymap", keymap, /* size= */ SIZE_MAX);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int read_credential_timezone(void) {
        int r;

        if (!arg_copy_timezone)
                return 0;

        if (machine_credential_find(&arg_credentials, "firstboot.timezone"))
                return 0;

        _cleanup_free_ char *tz = NULL;
        r = get_timezone_prefer_env(&tz);
        if (r < 0)
                log_warning_errno(r, "Failed to read timezone, skipping timezone propagation: %m");
        else {
                r = machine_credential_add(&arg_credentials, "firstboot.timezone", tz, /* size= */ SIZE_MAX);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int read_credentials(void) {
        int r;

        r = read_credential_locale();
        if (r < 0)
                return r;

        r = read_credential_keymap();
        if (r < 0)
                return r;

        r = read_credential_timezone();
        if (r < 0)
                return r;

        return 0;
}

static int connect_to_creds(sd_varlink **link) {
        int r;

        assert(link);

        if (*link)
                return 0;

        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *creds = NULL;
        fd = pin_callout_binary("systemd-creds", &creds);
        if (fd < 0)
                return log_error_errno(fd, "Failed to find systemd-creds binary: %m");

        r = sd_varlink_connect_exec(link, creds, /* argv= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to systemd-creds: %m");

        return 1;
}

static int encrypt_one_credential(sd_varlink **link, const MachineCredential *input, char ***encrypted) {
        int r;

        assert(link);
        assert(input);
        assert(encrypted);

        log_info("Encrypting credential '%s'...", input->id);

        r = connect_to_creds(link);
        if (r < 0)
                return r;

        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = varlink_callbo_and_log(
                        *link,
                        "io.systemd.Credentials.Encrypt",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR_STRING("name", input->id),
                        SD_JSON_BUILD_PAIR_BASE64("data", input->data, input->size),
                        SD_JSON_BUILD_PAIR_STRING("scope", "system"),
                        /* We pick the 'auto_initrd' key for this, since we want TPM if available, but are fine with NULL if not */
                        SD_JSON_BUILD_PAIR_STRING("withKey", "auto_initrd"));
        if (r < 0)
                return r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "blob", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, 0 },
                {}
        };

        const char *blob = NULL;
        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &blob);
        if (r < 0)
                return r;

        r = strv_extend_many(encrypted, input->id, blob);
        if (r < 0)
                return r;

        return 0;
}

static int encrypt_credentials(sd_varlink **link, char ***encrypted) {
        int r;

        assert(link);
        assert(encrypted);

        FOREACH_ARRAY(cred, arg_credentials.credentials, arg_credentials.n_credentials) {
                r = encrypt_one_credential(link, cred, encrypted);
                if (r < 0)
                        return r;
        }

        return 0;
}

static const ImagePolicy image_policy = {
        .n_policies = 4,
        .policies = {
                /* We mount / and /usr/ so that we can get access to /etc/machine-id and /etc/kernel/ */
                { PARTITION_ROOT,     PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_USR,      PARTITION_POLICY_VERITY|PARTITION_POLICY_SIGNED|PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_ESP,      PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
                { PARTITION_XBOOTLDR, PARTITION_POLICY_UNPROTECTED|PARTITION_POLICY_ABSENT },
        },
        .default_flags = PARTITION_POLICY_IGNORE,
};

static int settle_definitions(void) {
        int r;

        if (arg_definitions)
                return 0;

        /* If /usr/lib/repart.sysinstall.d/ is populated, use it, otherwise use the regular definition
         * files */

        _cleanup_strv_free_ char **files = NULL;
        r = conf_files_list_strv(
                        &files,
                        ".conf",
                        /* root= */ NULL,
                        CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED|CONF_FILES_WARN|CONF_FILES_DONT_PREFIX_ROOT,
                        (const char**) CONF_PATHS_STRV("repart.sysinstall.d"));
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate *.conf files: %m");

        if (!strv_isempty(files)) {
                arg_definitions = strv_copy(CONF_PATHS_STRV("repart.sysinstall.d"));
                if (!arg_definitions)
                        return log_oom();
        }

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        setlocale(LC_ALL, "");

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup();

        r = settle_definitions();
        if (r < 0)
                return r;

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *mute_console_link = NULL;
        if (arg_welcome) {
                if (arg_mute_console)
                        (void) mute_console(&mute_console_link);

                (void) terminal_reset_defensive_locked(STDOUT_FILENO, /* flags= */ 0);

                if (arg_chrome)
                        chrome_show("Operating System Installer", /* bottom= */ NULL);
        }

        DEFER_VOID_CALL(chrome_hide);

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *repart_link = NULL;
        if (arg_node) {
                r = print_welcome(&mute_console_link);
                if (r < 0)
                        return r;

                r = validate_run(&repart_link, arg_node);
                if (r < 0)
                        return r;
        } else {
                /* Determine the minimum disk size */
                uint64_t min_size = UINT64_MAX;
                r = invoke_repart(
                                &repart_link,
                                /* node= */ NULL,
                                /* erase= */ true,
                                /* dry_run= */ true,
                                &min_size,
                                /* current_size= */ NULL,
                                /* need_free= */ NULL);
                if (r < 0)
                        return r;

                r = print_welcome(&mute_console_link);
                if (r < 0)
                        return r;

                log_info("Required minimal installation disk size is %s.", FORMAT_BYTES(min_size));

                for (;;) {
                        _cleanup_free_ char *node = NULL;
                        r = prompt_block_device(&repart_link, &node);
                        if (r < 0)
                                return r;

                        r = validate_run(&repart_link, node);
                        if (IN_SET(r, -ENOSPC, -E2BIG, -EHWPOISON)) /* Device is no fit, pick other */
                                continue;
                        if (r < 0)
                                return r;

                        arg_node = TAKE_PTR(node);
                        break;
                }
        }

        r = prompt_touch_variables();
        if (r < 0)
                return r;

        r = read_credentials();
        if (r < 0)
                return r;

        /* Verify we have everything we need */
        assert(arg_node);
        assert(arg_erase >= 0);
        assert(arg_touch_variables >= 0);

        r = show_summary();
        if (r < 0)
                return r;

        r = prompt_confirm();
        if (r < 0)
                return r;

        putchar('\n');

        log_notice("%s%sEncrypting credentials...",
                   emoji_enabled() ? glyph(GLYPH_LOCK_AND_KEY) : "", emoji_enabled() ? " " : "");

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *creds_link = NULL;
        _cleanup_strv_free_ char **encrypted_credentials = NULL;
        r = encrypt_credentials(&creds_link, &encrypted_credentials);
        if (r < 0)
                return r;

        log_notice("%s%sInstalling partitions...",
                   emoji_enabled() ? glyph(GLYPH_COMPUTER_DISK) : "", emoji_enabled() ? " " : "");

        /* Do the main part of the installation */
        r = invoke_repart(
                        &repart_link,
                        arg_node,
                        arg_erase,
                        /* dry_run= */ false,
                        /* min_size= */ NULL,
                        /* current_size= */ NULL,
                        /* need_free= */ NULL);
        if (r < 0)
                return r;

        log_notice("%s%sMounting partitions...",
                   emoji_enabled() ? glyph(GLYPH_COMPUTER_DISK) : "", emoji_enabled() ? " " : "");

        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *root_dir = NULL;
        _cleanup_close_ int root_fd = -EBADF;
        r = mount_image_privately_interactively(
                        arg_node,
                        &image_policy,
                        DISSECT_IMAGE_REQUIRE_ROOT |
                        DISSECT_IMAGE_RELAX_VAR_CHECK |
                        DISSECT_IMAGE_ALLOW_USERSPACE_VERITY |
                        DISSECT_IMAGE_DISCARD_ANY |
                        DISSECT_IMAGE_GPT_ONLY |
                        DISSECT_IMAGE_FSCK |
                        DISSECT_IMAGE_USR_NO_ROOT |
                        DISSECT_IMAGE_ADD_PARTITION_DEVICES |
                        DISSECT_IMAGE_PIN_PARTITION_DEVICES,
                        &root_dir,
                        &root_fd,
                        &loop_device);
        if (r < 0)
                return log_error_errno(r, "Failed to mount new image: %m");

        log_notice("%s%sInstalling kernel...",
                   emoji_enabled() ? glyph(GLYPH_COMPUTER_DISK) : "", emoji_enabled() ? " " : "");

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *bootctl_link = NULL;
        r = invoke_bootctl_link(&bootctl_link, root_dir, root_fd, encrypted_credentials);
        if (r < 0)
                return r;

        log_notice("%s%sInstalling boot loader...",
                   emoji_enabled() ? glyph(GLYPH_COMPUTER_DISK) : "", emoji_enabled() ? " " : "");

        r = invoke_bootctl_install(&bootctl_link, root_dir, root_fd);
        if (r < 0)
                return r;

        log_notice("%s%sUnmounting partitions...",
                   emoji_enabled() ? glyph(GLYPH_COMPUTER_DISK) : "", emoji_enabled() ? " " : "");

        root_fd = safe_close(root_fd);
        r = umount_recursive(root_dir, /* flags= */ 0);
        if (r < 0)
                log_warning_errno(r, "Failed to unmount target disk, proceeding anyway: %m");
        loop_device = loop_device_unref(loop_device);
        sync();

        log_notice("%s%sInstallation succeeded.",
                   emoji_enabled() ? glyph(GLYPH_SPARKLES) : "", emoji_enabled() ? " " : "");

        r = maybe_reboot();
        if (r < 0)
                return r;

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
