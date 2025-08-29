/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-varlink.h"
#include "sd-bus.h"

#include "alloc-util.h"
#include "blockdev-list.h"
#include "build.h"
#include "build-path.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "constants.h"
#include "fd-util.h"
#include "format-util.h"
#include "json-util.h"
#include "log.h"
#include "login-util.h"
#include "main-func.h"
#include "os-util.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "prompt-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "varlink-util.h"

static char *arg_node = NULL;
static bool arg_welcome = true;
static int arg_erase = -1; /* tri-state */
static bool arg_confirm = true;
static char **arg_definitions = NULL;
static bool arg_reboot = true;

STATIC_DESTRUCTOR_REGISTER(arg_node, freep);
STATIC_DESTRUCTOR_REGISTER(arg_definitions, strv_freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-sysinstall", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [DEVICE]\n\n"
               "Installs the OS to another block device.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --definitions=DIR    Find partition definitions in specified directory\n"
               "     --welcome=no         Disable the welcome text\n"
               "     --erase=BOOL         Whether to erase the target disk\n"
               "     --confirm=no         Disable query for confirmation\n"
               "     --reboot=BOOL        Whether to reboot after installation is complete\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_WELCOME,
                ARG_ERASE,
                ARG_CONFIRM,
                ARG_DEFINITIONS,
                ARG_REBOOT,
        };

        static const struct option options[] = {
                { "help",        no_argument,       NULL, 'h'             },
                { "version",     no_argument,       NULL, ARG_VERSION     },
                { "welcome",     required_argument, NULL, ARG_WELCOME     },
                { "erase",       required_argument, NULL, ARG_ERASE       },
                { "confirm",     required_argument, NULL, ARG_CONFIRM     },
                { "definitions", required_argument, NULL, ARG_DEFINITIONS },
                { "reboot",      required_argument, NULL, ARG_REBOOT      },
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

                case ARG_WELCOME:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --welcome= argument: %s", optarg);

                        arg_welcome = r;
                        break;

                case ARG_ERASE:
                        r = parse_tristate_argument("--erase", optarg, &arg_erase);
                        if (r < 0)
                                return r;
                        break;

                case ARG_CONFIRM:
                        r = parse_boolean_argument("--confirm", optarg, &arg_confirm);
                        if (r < 0)
                                return r;
                        break;

                case ARG_DEFINITIONS: {
                        _cleanup_free_ char *path = NULL;
                        r = parse_path_argument(optarg, false, &path);
                        if (r < 0)
                                return r;
                        if (strv_consume(&arg_definitions, TAKE_PTR(path)) < 0)
                                return log_oom();
                        break;
                }

                case ARG_REBOOT:
                        r = parse_boolean_argument("--confirm", optarg, &arg_reboot);
                        if (r < 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (argc > optind+1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too many arguments.");
        if (argc == optind+1) {
                arg_node = strdup(argv[optind]);
                if (!arg_node)
                        return log_oom();
        }

        if (!arg_definitions) {
                arg_definitions = strv_copy(CONF_PATHS_STRV("repart.sysinstall.d"));
                if (!arg_definitions)
                        return log_oom();
        }

        return 1;
}

static int print_welcome(void) {
        _cleanup_free_ char *pretty_name = NULL, *os_name = NULL, *ansi_color = NULL;
        static bool done = false;
        const char *pn, *ac;
        int r;

        if (!arg_welcome)
                return 0;

        if (done) {
                putchar('\n'); /* Add some breathing room between multiple prompts */
                return 0;
        }

        r = parse_os_release(
                        /* root= */ NULL,
                        "PRETTY_NAME", &pretty_name,
                        "NAME",        &os_name,
                        "ANSI_COLOR",  &ansi_color);
        if (r < 0)
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to read os-release file, ignoring: %m");

        pn = os_release_pretty_name(pretty_name, os_name);
        ac = isempty(ansi_color) ? "0" : ansi_color;

        if (colors_enabled())
                printf("\n"
                       ANSI_HIGHLIGHT "Welcome to the " ANSI_NORMAL "\x1B[%sm%s" ANSI_HIGHLIGHT " Installer!" ANSI_NORMAL "\n", ac, pn);
        else
                printf("\nWelcome to the %s Installer!\n", pn);

        putchar('\n');
        if (emoji_enabled()) {
                fputs(glyph(GLYPH_ROCKET), stdout);
                putchar(' ');
        }

        printf("Please configure the future installation!\n");
        done = true;

        if (!any_key_to_proceed())
                return -ECANCELED;

        return 0;
}

static int connect_to_repart(sd_varlink **link) {
        int r;

        assert(link);

        if (*link)
                return 0;

        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *repart = NULL;
        fd = pin_callout_binary("systemd-repart", &repart);
        if (fd < 0)
                return log_error_errno(fd, "Failed to find systemd-repart binary: %m");

        r = sd_varlink_connect_exec(
                        link,
                        repart,
                        /* argv= */ NULL);
                        /* "valgrind", */
                        /* STRV_MAKE("valgrind", repart)); */
        if (r < 0)
                return log_error_errno(r, "Failed to connect systemd-repart: %m");

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

static bool device_is_valid(const char *node, void *userdata) {

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

static int prompt_block_device(sd_varlink **repart_link, char **ret_node) {
        int r;

        r = print_welcome();
        if (r < 0)
                return r;

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
                        /* userdata= */ NULL,
                        PROMPT_SHOW_MENU|PROMPT_SHOW_MENU_NOW|PROMPT_MAY_SKIP|PROMPT_HIDE_SKIP_HINT|PROMPT_HIDE_MENU_HINT,
                        ret_node);
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ECANCELED), "Installation cancelled.");

        putchar('\n');

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
                int erase,
                bool dry_run,
                uint64_t *min_size,        /* initialized both on success and error */
                uint64_t *current_size,    /* ditto */
                uint64_t *need_free) {     /* ditto */

        int r;

        assert(link);
        assert(erase >= 0);

        /* Note, in dry_run is true, then ENOSPC, E2BIG, EHWPOISON will not be logged about beyond LOG_DEBUG,
         * but all other errors will be */

        r = connect_to_repart(link);
        if (r < 0) {
                read_space_metrics(/* reply= */ NULL, min_size, current_size, need_free);
                return r;
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
                        SD_JSON_BUILD_PAIR_STRV("definitions", arg_definitions));
        if (r < 0) {
                read_space_metrics(/* reply= */ NULL, min_size, current_size, need_free);
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
                read_space_metrics(/* reply= */ NULL, min_size, current_size, need_free);

                if (streq(error_id, "io.systemd.Repart.ConflictingDiskLabelPresent")) {
                        return log_full_errno(
                                        dry_run ? LOG_DEBUG : LOG_ERR,
                                        SYNTHETIC_ERRNO(EHWPOISON),
                                        "A conflicting disk label is already present on the target disk, cannot install unless disk is erased.");
                }

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

        r = print_welcome();
        if (r < 0)
                return r;

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
                        /* validate= */ NULL,
                        /* userdata= */ NULL,
                        PROMPT_SHOW_MENU|PROMPT_MAY_SKIP|PROMPT_HIDE_MENU_HINT|PROMPT_HIDE_SKIP_HINT,
                        &reply);
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ECANCELED), "Installation cancelled.");

        putchar('\n');

        if (streq(reply, "erase"))
                *ret_erase = true;
        else if (streq(reply, "keep"))
                *ret_erase = false;
        else
                assert_not_reached();

        return 0;
}

static int prompt_confirm(void) {
        int r;

        if (!arg_confirm)
                return 0;

        r = print_welcome();
        if (r < 0)
                return r;

        char **l = STRV_MAKE("yes", "no");

        _cleanup_free_ char *reply = NULL;
        r = prompt_loop("Please type 'yes' to confirm the choices above",
                        GLYPH_WARNING_SIGN,
                        /* menu= */ l,
                        /* accepted= */ l,
                        /* ellipsize_percentage= */ 20,
                        /* n_columns= */ 2,
                        /* column_width= */ 40,
                        /* validate= */ NULL,
                        /* userdata= */ NULL,
                        PROMPT_SHOW_MENU|PROMPT_MAY_SKIP|PROMPT_HIDE_MENU_HINT|PROMPT_HIDE_SKIP_HINT,
                        &reply);
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ECANCELED), "Installation cancelled.");

        if (!streq(reply, "yes"))
                return log_error_errno(SYNTHETIC_ERRNO(ECANCELED), "Installation not confirmed, cancelling.");

        putchar('\n');

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

static int run(int argc, char *argv[]) {
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup();

        if (arg_welcome)  {
                (void) terminal_reset_defensive_locked(STDOUT_FILENO, /* flags= */ 0);
                chrome_show("Operating System Installer", /* bottom= */ NULL);
        }

        DEFER_VOID_CALL(chrome_hide);

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *repart_link = NULL;

        if (arg_node) {
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

                r = print_welcome();
                if (r < 0)
                        return r;

                log_notice("Required minimal installation disk size is %s.", FORMAT_BYTES(min_size));

                for (;;) {
                        _cleanup_free_ char *node = NULL;
                        r = prompt_block_device(&repart_link, &node);
                        if (r < 0)
                                return r;

                        r = validate_run(&repart_link, node);
                        if (r < 0)
                                return r;
                        if (IN_SET(r, -ENOSPC, -E2BIG, -EHWPOISON)) /* Device is no fit, pick other */
                                continue;

                        arg_node = TAKE_PTR(node);
                        break;
                }
        }

        assert(arg_node);
        assert(arg_erase >= 0);

        fprintf(stderr,
                "%sSummary:%s\n"
                "\tSelected disk: %s%s%s\n"
                "\t        Erase: %s%s%s\n",
                ansi_underline(), ansi_normal(),
                ansi_highlight(), arg_node, ansi_normal(),
                arg_erase ? ansi_highlight_red() : ansi_highlight_green(),
                yes_no(arg_erase),
                ansi_normal());

        r = prompt_confirm();
        if (r < 0)
                return r;

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
                return log_error_errno(r, "Installation failed: %m");

        log_notice("%s%sInstallation succeeded.", glyph(GLYPH_SPARKLES), emoji_enabled() ? " " : "");

        if (arg_reboot) {
                log_info("System will reboot now.");

                if (any_key_to_proceed()) {
                        log_info("Initiating reboot.");

                        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
                        r = sd_bus_open_system(&bus);
                        if (r < 0)
                                return log_error_errno(r, "Failed to open bus connection: %m");

                        /* _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL; */
                        /* r = bus_call_method( */
                        /*                 bus, */
                        /*                 bus_login_mgr, */
                        /*                 "RebootWithFlags", */
                        /*                 &error, */
                        /*                 /\* reply= *\/ NULL, */
                        /*                 "t", (uint64_t) SD_LOGIND_ROOT_CHECK_INHIBITORS); */
                        /* if (r < 0) */
                        /*         return log_error_errno(r, "Failed to issue reboot request: %s", bus_error_message(&error, r)); */

                        return 0;
                }
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
