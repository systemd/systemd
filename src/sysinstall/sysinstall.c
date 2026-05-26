/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "blockdev-list.h"
#include "build.h"
#include "build-path.h"
#include "bus-polkit.h"
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
#include "hashmap.h"
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
#include "string-table.h"
#include "strv.h"
#include "terminal-util.h"
#include "varlink-util.h"
#include "varlink-io.systemd.Sysinstall.h"

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
static bool arg_varlink = false;

STATIC_DESTRUCTOR_REGISTER(arg_node, freep);
STATIC_DESTRUCTOR_REGISTER(arg_definitions, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_kernel_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_credentials, machine_credential_context_done);

typedef enum ProgressPhase {
        PROGRESS_VALIDATE_BLOCK_DEVICE,
        PROGRESS_LOAD_CREDENTIALS,
        PROGRESS_ENCRYPT_CREDENTIALS,

        /* The same progress phases as repart */
        PROGRESS_LOADING_DEFINITIONS,
        PROGRESS_LOADING_TABLE,
        PROGRESS_OPENING_COPY_BLOCK_SOURCES,
        PROGRESS_ACQUIRING_PARTITION_LABELS,
        PROGRESS_MINIMIZING,
        PROGRESS_PLACING,
        PROGRESS_WIPING_DISK,
        PROGRESS_WIPING_PARTITION,
        PROGRESS_COPYING_PARTITION,
        PROGRESS_FORMATTING_PARTITION,
        PROGRESS_ADJUSTING_PARTITION,
        PROGRESS_WRITING_TABLE,
        PROGRESS_REREADING_TABLE,

        PROGRESS_MOUNT_PARTITIONS,
        PROGRESS_INSTALL_KERNEL,
        PROGRESS_INSTALL_BOOTLOADER,
        PROGRESS_UNMOUNT_PARTITIONS,
        _PROGRESS_PHASE_MAX,
        _PROGRESS_PHASE_INVALID = -EINVAL,
} ProgressPhase;

static const char *progress_phase_table[_PROGRESS_PHASE_MAX] = {
        [PROGRESS_VALIDATE_BLOCK_DEVICE]      = "validate-block-device",
        [PROGRESS_LOAD_CREDENTIALS]           = "load-credentials",
        [PROGRESS_ENCRYPT_CREDENTIALS]        = "encrypt-credentials",

        [PROGRESS_LOADING_DEFINITIONS]        = "loading-definitions",
        [PROGRESS_LOADING_TABLE]              = "loading-table",
        [PROGRESS_OPENING_COPY_BLOCK_SOURCES] = "opening-copy-block-sources",
        [PROGRESS_ACQUIRING_PARTITION_LABELS] = "acquiring-partition-labels",
        [PROGRESS_MINIMIZING]                 = "minimizing",
        [PROGRESS_PLACING]                    = "placing",
        [PROGRESS_WIPING_DISK]                = "wiping-disk",
        [PROGRESS_WIPING_PARTITION]           = "wiping-partition",
        [PROGRESS_COPYING_PARTITION]          = "copying-partition",
        [PROGRESS_FORMATTING_PARTITION]       = "formatting-partition",
        [PROGRESS_ADJUSTING_PARTITION]        = "adjusting-partition",
        [PROGRESS_WRITING_TABLE]              = "writing-table",
        [PROGRESS_REREADING_TABLE]            = "rereading-table",

        [PROGRESS_MOUNT_PARTITIONS]           = "mount-partitions",
        [PROGRESS_INSTALL_KERNEL]             = "install-kernel",
        [PROGRESS_INSTALL_BOOTLOADER]         = "install-bootloader",
        [PROGRESS_UNMOUNT_PARTITIONS]         = "unmount-partitions",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(progress_phase, ProgressPhase);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(progress_phase, ProgressPhase);

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

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0) {
                arg_varlink = true;
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
                        /* prefill= */ NULL,
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

static const char* repart_to_sysinstall_error_id(const char *error_id) {

        if (error_id == NULL)
                return NULL;

        if (streq(error_id, "io.systemd.Repart.InsufficientFreeSpace"))
                return "io.systemd.Sysinstall.InsufficientFreeSpace";
        if (streq(error_id, "io.systemd.Repart.DiskTooSmall"))
                return "io.systemd.Sysinstall.DiskTooSmall";
        if (streq(error_id, "io.systemd.Repart.ConflictingDiskLabelPresent"))
                return "io.systemd.Sysinstall.ConflictingDiskLabelPresent";

        return NULL;
}

typedef struct RepartResult {
        uint64_t *min_size;
        uint64_t *current_size;
        uint64_t *need_free;
        char **error_id;
        int ret;
        sd_varlink *output_link;
} RepartResult;

static int notify_progress(
                sd_varlink *link,
                ProgressPhase phase,
                const char *object,
                unsigned percent) {

        int r;

        assert(phase >= 0);
        assert(phase < _PROGRESS_PHASE_MAX);

        /* Send progress information, via sd_notify() and via varlink (if client asked for it by setting "more" flag) */

        _cleanup_free_ char *n = NULL;
        if (asprintf(&n,
                     "STATUS=Phase %1$s\n"
                     "X_SYSTEMD_PHASE=%1$s",
                     progress_phase_to_string(phase)) < 0)
                return log_oom_debug();

        if (percent != UINT_MAX)
                if (strextendf(&n, "\nX_SYSTEMD_PHASE_PROGRESS=%u", percent) < 0)
                        return log_oom_debug();

        r = sd_notify(/* unset_environment= */ false, n);
        if (r < 0)
                log_debug_errno(r, "Failed to send sd_notify() progress notification, ignoring: %m");

        if (link) {
                r = sd_varlink_notifybo(
                                link,
                                JSON_BUILD_PAIR_ENUM("phase", progress_phase_to_string(phase)),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("object", object),
                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("progress", percent, UINT_MAX));
                if (r < 0)
                        log_debug_errno(r, "Failed to send varlink notify progress notification, ignoring: %m");

                r = sd_varlink_flush(link);
                if (r < 0)
                        log_debug_errno(r, "Failed to flush varlink notify progress notification, ignoring: %m");
        }

        return 0;
}

static int handle_repart_reply(
                sd_varlink *link,
                sd_json_variant *reply,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        RepartResult *result = userdata;
        int r;

        assert(result);

        struct {
                uint64_t min_size;
                uint64_t current_size;
                uint64_t need_free;

                const char *phase;
                const char *object;
                unsigned progress;
        } p = {
                .min_size = UINT64_MAX,
                .current_size = UINT64_MAX,
                .need_free = UINT64_MAX,
                .progress = UINT_MAX,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "minimalSizeBytes", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, voffsetof(p, min_size),     0 },
                { "currentSizeBytes", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, voffsetof(p, current_size), 0 },
                { "needFreeBytes",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, voffsetof(p, need_free),    0 },
                { "phase",            _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_const_string, voffsetof(p, phase),        0 },
                { "object",           _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_const_string, voffsetof(p, object),       0 },
                { "progress",         _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,   voffsetof(p, progress),     0 },
                {}
        };

        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return result->ret = r;

        *result->min_size = p.min_size;
        *result->current_size = p.current_size;
        *result->need_free = p.need_free;

        if (error_id) {
                *result->error_id = strdup(error_id);
                if (!*result->error_id)
                        return result->ret = log_oom();

                if (!(streq(error_id, "io.systemd.Repart.InsufficientFreeSpace") ||
                      streq(error_id, "io.systemd.Repart.DiskTooSmall") ||
                      streq(error_id, "io.systemd.Repart.ConflictingDiskLabelPresent"))) {

                        r = sd_varlink_error_to_errno(error_id, reply); /* If this is a system errno style error, output it with %m */
                        if (r != -EBADR)
                                return result->ret = log_error_errno(r, "Failed to issue io.systemd.Repart.Run() varlink call: %m");

                        return result->ret = log_error_errno(r, "Failed to issue io.systemd.Repart.Run() varlink call: %s", error_id);
                }
        }

        if (p.phase) {
                ProgressPhase phase = progress_phase_from_string(json_dashify((char *) p.phase));
                if (phase < 0)
                        log_warning_errno(phase, "Failed to parse progress phase sent by io.systemd.Repart.Run() varlink call: %m");
                else
                        (void) notify_progress(result->output_link, phase, p.object, p.progress);
        }

        return result->ret = 0;
}

static int invoke_repart_with_progress(
                sd_varlink **link,
                const char *node,
                bool erase,
                bool dry_run,
                char **definitions,
                sd_varlink *output_link,
                char **ret_error_id,
                uint64_t *min_size,        /* initialized both on success and error */
                uint64_t *current_size,    /* ditto */
                uint64_t *need_free) {     /* ditto */

        int r;

        assert(link);

        r = connect_to_repart(link);
        if (r < 0) {
                return r;
        }

        /* Seeding the partitions might be very slow, disable timeout */
        r = sd_varlink_set_relative_timeout(*link, UINT64_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to disable IPC timeout: %m");

         RepartResult result = {
                .min_size = min_size,
                .current_size = current_size,
                .need_free = need_free,
                .error_id = ret_error_id,
                .output_link = output_link,
        };

        sd_varlink_set_userdata(*link, &result);

        r = sd_varlink_bind_reply(*link, handle_repart_reply);
        if (r < 0) {
                return log_error_errno(r, "Failed to bind repart reply callback: %m");
        }

        r = sd_varlink_observebo(
                        *link,
                        "io.systemd.Repart.Run",
                        SD_JSON_BUILD_PAIR_STRING("node", node),
                        SD_JSON_BUILD_PAIR_STRING("empty", erase ? "force" : "allow"),
                        SD_JSON_BUILD_PAIR_BOOLEAN("dryRun", dry_run),
                        SD_JSON_BUILD_PAIR_CONDITION(!!definitions, "definitions", SD_JSON_BUILD_STRV(definitions)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("deferPartitionsEmpty", true),
                        SD_JSON_BUILD_PAIR_BOOLEAN("deferPartitionsFactoryReset", true));
        if (r < 0) {
                return log_error_errno(r, "Failed to issue io.systemd.Repart.Run() varlink call: %m");
        }

        for (;;) {
                r = sd_varlink_is_idle(*link);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if varlink connection is idle: %m");
                if (r > 0)
                        break;

                r = sd_varlink_process(*link);
                if (r < 0)
                        return log_error_errno(r, "Failed to process varlink connection: %m");
                if (r != 0)
                        continue;

                r = sd_varlink_wait(*link, USEC_INFINITY);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for varlink connection events: %m");
        }

        return result.ret;
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
                char **definitions,
                char **ret_error,
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
                        SD_JSON_BUILD_PAIR_CONDITION(!!definitions, "definitions", SD_JSON_BUILD_STRV(definitions)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("deferPartitionsEmpty", true),
                        SD_JSON_BUILD_PAIR_BOOLEAN("deferPartitionsFactoryReset", true));
        if (r < 0) {
                read_space_metrics(/* v= */ NULL, min_size, current_size, need_free);
                return log_error_errno(r, "Failed to issue io.systemd.Repart.Run() varlink call: %m");
        }
        if (error_id) {
                if (ret_error)
                        *ret_error = strdup(error_id);

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
                        /* prefill= */ NULL,
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
                        /* prefill= */ "yes",
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
                        /* prefill= */ NULL,
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
                                arg_definitions,
                                /* ret_error= */ NULL,
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
                bool variables,
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
                        SD_JSON_BUILD_PAIR_BOOLEAN("touchVariables", variables));
        if (r < 0)
                return r;

        return 0;
}

static int invoke_bootctl_link(
                sd_varlink **link,
                const char *kernel_image,
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
        if (kernel_image) {
                r = path_extract_filename(kernel_image, &kernel_filename);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from kernel path '%s': %m", kernel_image);
                if (r == O_DIRECTORY)
                        return log_error_errno(SYNTHETIC_ERRNO(EISDIR), "Kernel path '%s' refers to directory, must be regular file, refusing.", kernel_image);

                kernel_fd = xopenat_full(XAT_FDROOT, kernel_image, O_RDONLY|O_CLOEXEC, XO_REGULAR, MODE_INVALID);
                if (kernel_fd < 0)
                        return log_error_errno(kernel_fd, "Failed to open kernel image '%s': %m", kernel_image);

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

static int read_credential_locale(MachineCredentialContext *credentials) {
        int r;

        if (machine_credential_find(credentials, "firstboot.locale") ||
            machine_credential_find(credentials, "firstboot.locale-messages"))
                return 0;

        /* For the main locale we check the two env vars, and if neither is there, we use LC_NUMERIC, since
         * it seems to be one of the most fundamental ones, and is not LC_MESSAGES for which we have a
         * separate setting after all */
        const char *l = getenv("LC_ALL") ?: getenv("LANG") ?: setlocale(LC_NUMERIC, NULL);
        if (l) {
                r = machine_credential_add(credentials, "firstboot.locale", l, /* size= */ SIZE_MAX);
                if (r < 0)
                        return log_oom();
        }

        const char *m = setlocale(LC_MESSAGES, NULL);
        if (m && !streq_ptr(m, l)) {
                r = machine_credential_add(credentials, "firstboot.locale-messages", m, /* size= */ SIZE_MAX);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int read_credential_keymap(MachineCredentialContext *credentials) {
        int r;

        if (machine_credential_find(credentials, "firstboot.keymap"))
                return 0;

        _cleanup_free_ char *keymap = NULL;
        r = parse_env_file(
                        /* f= */ NULL,
                        etc_vconsole_conf(),
                        "KEYMAP", &keymap);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to parse '%s': %m", etc_vconsole_conf());

        if (!isempty(keymap)) {
                r = machine_credential_add(credentials, "firstboot.keymap", keymap, /* size= */ SIZE_MAX);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int read_credential_timezone(MachineCredentialContext *credentials) {
        int r;

        if (machine_credential_find(credentials, "firstboot.timezone"))
                return 0;

        _cleanup_free_ char *tz = NULL;
        r = get_timezone_prefer_env(&tz);
        if (r < 0)
                log_warning_errno(r, "Failed to read timezone, skipping timezone propagation: %m");
        else {
                r = machine_credential_add(credentials, "firstboot.timezone", tz, /* size= */ SIZE_MAX);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int read_credentials(MachineCredentialContext *credentials, bool copy_locale, bool copy_keymap, bool copy_timezone) {
        int r;

        if (copy_locale) {
                r = read_credential_locale(credentials);
                if (r < 0)
                        return r;
        }

        if (copy_keymap) {
                r = read_credential_keymap(credentials);
                if (r < 0)
                        return r;
        }

        if (copy_timezone) {
                r = read_credential_timezone(credentials);
                if (r < 0)
                        return r;
        }

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

static int encrypt_credentials(sd_varlink **link, MachineCredentialContext credentials, char ***encrypted) {
        int r;

        assert(link);
        assert(encrypted);

        FOREACH_ARRAY(cred, credentials.credentials, credentials.n_credentials) {
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

static int settle_definitions(char ***definitions) {

        int r;

        if (*definitions) {
                return 0;
        }

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
                *definitions = strv_copy(CONF_PATHS_STRV("repart.sysinstall.d"));
                if (*definitions)
                        return log_oom();
        }

        return 0;
}

static int fetch_candidate_devices_reply(
                sd_varlink *repart_link,
                sd_json_variant *reply,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {
        sd_varlink *link = ASSERT_PTR(userdata);

        if (error_id) {
                if (streq(error_id, "io.systemd.Repart.NoCandidateDevices"))
                        return sd_varlink_set_sentinel(link, "io.systemd.Sysinstall.NoCandidateDevices");

                return sd_varlink_set_sentinel(link, error_id);
        }

        if (FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES))
                return sd_varlink_notify(link, reply);
        else
                return sd_varlink_reply(link, reply);
}

static int vl_method_list_candidate_devices(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {
        int r;
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *repart_link = NULL;

        Hashmap **polkit_registry = ASSERT_PTR(userdata);

        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.sysinstall.ListCandidateDevices",
                        /* details= */ NULL,
                        polkit_registry);
        if (r <= 0)
                return r;

        r = connect_to_repart(&repart_link);
        if (r < 0)
                return r;

        sd_varlink_set_userdata(repart_link, link);

        r = sd_varlink_bind_reply(repart_link, fetch_candidate_devices_reply);
        if (r < 0)
                return r;

        r = sd_varlink_observebo(
                        repart_link,
                        "io.systemd.Repart.ListCandidateDevices",
                        SD_JSON_BUILD_PAIR_BOOLEAN("ignoreRoot", true));

        if (r < 0) {
                return log_error_errno(
                                r,
                                "Failed to issue io.systemd.Repart.ListCandidateDevices() varlink call: %m");
        }

        for (;;) {
                r = sd_varlink_is_idle(repart_link);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if varlink connection is idle: %m");
                if (r > 0)
                        break;

                r = sd_varlink_process(repart_link);
                if (r < 0)
                        return log_error_errno(r, "Failed to process varlink connection: %m");
                if (r != 0)
                        continue;

                r = sd_varlink_wait(repart_link, USEC_INFINITY);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for varlink connection events: %m");
        }

        return 0;
}

typedef struct RunParameters {
        char *node;
        bool dry_run;
        char **definitions;
        bool erase;
        bool variables;
        char *kernel_image;
        bool copy_locale;
        bool copy_keymap;
        bool copy_timezone;
        char **set_credentials;
        char **load_credentials;
} RunParameters;

static void run_parameters_done(RunParameters *p) {
        assert(p);

        p->node = mfree(p->node);
        p->definitions = strv_free(p->definitions);
        p->kernel_image = mfree(p->kernel_image);
        p->set_credentials = strv_free(p->set_credentials);
        p->load_credentials = strv_free(p->load_credentials);
}

static int vl_method_run(
                sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "node",            SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(RunParameters, node),             SD_JSON_NULLABLE                  },
                { "dryRun",          SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(RunParameters, dry_run),          SD_JSON_MANDATORY                 },
                { "definitions",     SD_JSON_VARIANT_ARRAY,   json_dispatch_strv_path,  offsetof(RunParameters, definitions),      SD_JSON_NULLABLE | SD_JSON_STRICT },
                { "erase",           SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(RunParameters, erase),            SD_JSON_MANDATORY                 },
                { "variables",       SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(RunParameters, variables),        SD_JSON_NULLABLE                  },
                { "kernelImage",     SD_JSON_VARIANT_STRING,  json_dispatch_path,       offsetof(RunParameters, kernel_image),     SD_JSON_NULLABLE | SD_JSON_STRICT },
                { "copyLocale",      SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(RunParameters, copy_locale),      SD_JSON_NULLABLE                  },                 
                { "copyKeymap",      SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(RunParameters, copy_keymap),      SD_JSON_NULLABLE                  },
                { "copyTimezone",    SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(RunParameters, copy_timezone),    SD_JSON_NULLABLE                  },
                { "setCredentials",  SD_JSON_VARIANT_ARRAY,   sd_json_dispatch_strv,    offsetof(RunParameters, set_credentials),  SD_JSON_NULLABLE | SD_JSON_STRICT },
                { "loadCredentials", SD_JSON_VARIANT_ARRAY,   json_dispatch_strv_path,  offsetof(RunParameters, load_credentials), SD_JSON_NULLABLE | SD_JSON_STRICT },
                {}
        };

        int r;

        assert(link);

        Hashmap **polkit_registry = ASSERT_PTR(userdata);

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.sysinstall.Run",
                        /* details= */ NULL,
                        polkit_registry);
        if (r <= 0)
                return r;

        _cleanup_(run_parameters_done) RunParameters p = {};
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        /* If no device node is specified, this is a dry run. Refuse if the caller claims otherwise. */
        if (!p.node && !p.dry_run)
                return sd_varlink_error_invalid_parameter_name(link, "dryRun");

        r = settle_definitions(&p.definitions);
        if (r < 0)
                return r;

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *repart_link = NULL;

        if (p.dry_run || p.node == NULL) {
                _cleanup_free_ char *repart_error = NULL;
                uint64_t min_size = UINT64_MAX, current_size = UINT64_MAX, need_free = UINT64_MAX;

                r = invoke_repart(
                                &repart_link,
                                p.node,
                                p.erase,
                                /* dry_run= */ true,
                                p.definitions,
                                &repart_error,
                                &min_size,
                                &current_size,
                                &need_free);
                if (r < 0) {
                        const char *sysinstall_error = repart_to_sysinstall_error_id(repart_error);

                        if (sysinstall_error) {
                                return sd_varlink_errorbo(
                                                link,
                                                sysinstall_error,
                                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("currentSizeBytes", current_size, UINT64_MAX),
                                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("needFreeBytes", need_free, UINT64_MAX),
                                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("minimalSizeBytes", min_size, UINT64_MAX));
                        }

                        return r;
                } else {
                        return sd_varlink_replybo(
                                        link,
                                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("currentSizeBytes", current_size, UINT64_MAX),
                                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("needFreeBytes", need_free, UINT64_MAX),
                                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("minimalSizeBytes", min_size, UINT64_MAX));
                }
        }

        sd_varlink *output_link = NULL;
        if (FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                output_link = link;

        (void) notify_progress(output_link, PROGRESS_LOAD_CREDENTIALS, /* object= */ NULL, UINT_MAX);

        _cleanup_(machine_credential_context_done) MachineCredentialContext credentials = {};

        STRV_FOREACH(credential, p.set_credentials) {
                r = machine_credential_set(&credentials, *credential);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(credential, p.load_credentials) {
                r = machine_credential_load(&credentials, *credential);
                if (r < 0)
                        return r;
        }

        r = read_credentials(&credentials, p.copy_locale, p.copy_keymap, p.copy_timezone);
        if (r < 0)
                return r;

        (void) notify_progress(output_link, PROGRESS_ENCRYPT_CREDENTIALS, /* object= */ NULL, UINT_MAX);

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *creds_link = NULL;
        _cleanup_strv_free_ char **encrypted_credentials = NULL;
        r = encrypt_credentials(&creds_link, credentials, &encrypted_credentials);
        if (r < 0)
                return r;

        /* Do the main part of the installation */
        _cleanup_free_ char *repart_error = NULL;
        uint64_t min_size = UINT64_MAX, current_size = UINT64_MAX, need_free = UINT64_MAX;

        r = invoke_repart_with_progress(
                        &repart_link,
                        p.node,
                        p.erase,
                        /* dry_run= */ true,
                        p.definitions,
                        link,
                        &repart_error,
                        &min_size,
                        &current_size,
                        &need_free);
        if (r < 0) {
                const char *sysinstall_error = repart_to_sysinstall_error_id(repart_error);

                if (sysinstall_error)
                        return sd_varlink_errorbo(
                                        link,
                                        sysinstall_error,
                                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("currentSizeBytes", current_size, UINT64_MAX),
                                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("needFreeBytes", need_free, UINT64_MAX),
                                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("minimalSizeBytes", min_size, UINT64_MAX));
                return r;
        }

        (void) notify_progress(output_link, PROGRESS_MOUNT_PARTITIONS, /* object= */ NULL, UINT_MAX);

        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *root_dir = NULL;
        _cleanup_close_ int root_fd = -EBADF;
        r = mount_image_privately_interactively(
                        p.node,
                        &image_policy,
                        DISSECT_IMAGE_REQUIRE_ROOT | DISSECT_IMAGE_RELAX_VAR_CHECK |
                        DISSECT_IMAGE_ALLOW_USERSPACE_VERITY | DISSECT_IMAGE_DISCARD_ANY |
                        DISSECT_IMAGE_GPT_ONLY | DISSECT_IMAGE_FSCK |
                        DISSECT_IMAGE_USR_NO_ROOT | DISSECT_IMAGE_ADD_PARTITION_DEVICES |
                        DISSECT_IMAGE_PIN_PARTITION_DEVICES,
                        &root_dir,
                        &root_fd,
                        &loop_device);
        if (r < 0)
                return log_error_errno(r, "Failed to mount new image: %m");

        (void) notify_progress(output_link, PROGRESS_INSTALL_KERNEL, /* object= */ NULL, UINT_MAX);

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *bootctl_link = NULL;
        r = invoke_bootctl_link(&bootctl_link, p.kernel_image, root_dir, root_fd, encrypted_credentials);
        if (r < 0)
                return r;

        (void) notify_progress(output_link, PROGRESS_INSTALL_BOOTLOADER, /* object= */ NULL, UINT_MAX);

        r = invoke_bootctl_install(&bootctl_link, p.variables, root_dir, root_fd);
        if (r < 0)
                return r;

        (void) notify_progress(output_link, PROGRESS_UNMOUNT_PARTITIONS, /* object= */ NULL, UINT_MAX);

        root_fd = safe_close(root_fd);
        r = umount_recursive(root_dir, /* flags= */ 0);
        if (r < 0)
                log_warning_errno(r, "Failed to unmount target disk, proceeding anyway: %m");
        loop_device = loop_device_unref(loop_device);
        sync();

        return sd_varlink_reply(link, NULL);
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        _cleanup_hashmap_free_ Hashmap *polkit_registry = NULL;
        int r;

        /* Invocation as Varlink service */

        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_INHERIT_USERDATA,
                        /* userdata= */ &polkit_registry);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_Sysinstall);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.Sysinstall.ListCandidateDevices", vl_method_list_candidate_devices,
                        "io.systemd.Sysinstall.Run",                  vl_method_run);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static void end_marker(void) {

        if (!arg_welcome)
                return;

        printf("\n%sExiting first boot settings tool.%s\n\n", ansi_grey(), ansi_normal());
        fflush(stdout);
}

static int run(int argc, char *argv[]) {
        int r;

        setlocale(LC_ALL, "");

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        log_setup();

        if (arg_varlink)
                return vl_server();

        r = settle_definitions(&arg_definitions);
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

        DEFER_VOID_CALL(end_marker);
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
                                arg_definitions,
                                /* ret_error= */ NULL,
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

        r = read_credentials(&arg_credentials, arg_copy_locale, arg_copy_keymap, arg_copy_timezone);
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
        r = encrypt_credentials(&creds_link, arg_credentials, &encrypted_credentials);
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
                        arg_definitions,
                        /* ret_error= */ NULL,
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
        r = invoke_bootctl_link(&bootctl_link, arg_kernel_image, root_dir, root_fd, encrypted_credentials);
        if (r < 0)
                return r;

        log_notice("%s%sInstalling boot loader...",
                   emoji_enabled() ? glyph(GLYPH_COMPUTER_DISK) : "", emoji_enabled() ? " " : "");

        r = invoke_bootctl_install(&bootctl_link, arg_touch_variables, root_dir, root_fd);
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
