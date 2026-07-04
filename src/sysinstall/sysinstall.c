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
#include "varlink-io.systemd.SysInstall.h"
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
static bool arg_varlink = false;

STATIC_DESTRUCTOR_REGISTER(arg_node, freep);
STATIC_DESTRUCTOR_REGISTER(arg_definitions, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_kernel_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_credentials, machine_credential_context_done);

typedef enum ProgressPhase {
        PROGRESS_ENCRYPT_CREDENTIALS,
        PROGRESS_INSTALL_PARTITIONS,
        PROGRESS_MOUNT_PARTITIONS,
        PROGRESS_INSTALL_KERNEL,
        PROGRESS_INSTALL_BOOTLOADER,
        PROGRESS_UNMOUNT_PARTITIONS,
        _PROGRESS_PHASE_MAX,
        _PROGRESS_PHASE_INVALID = -EINVAL,
} ProgressPhase;

static const char *progress_phase_table[_PROGRESS_PHASE_MAX] = {
        [PROGRESS_ENCRYPT_CREDENTIALS] = "encrypt-credentials",
        [PROGRESS_INSTALL_PARTITIONS]  = "install-partitions",
        [PROGRESS_MOUNT_PARTITIONS]    = "mount-partitions",
        [PROGRESS_INSTALL_KERNEL]      = "install-kernel",
        [PROGRESS_INSTALL_BOOTLOADER]  = "install-bootloader",
        [PROGRESS_UNMOUNT_PARTITIONS]  = "unmount-partitions",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(progress_phase, ProgressPhase);

static const char *progress_phase_log_table[_PROGRESS_PHASE_MAX] = {
        [PROGRESS_ENCRYPT_CREDENTIALS] = "Encrypting credentials...",
        [PROGRESS_INSTALL_PARTITIONS]  = "Installing partitions...",
        [PROGRESS_MOUNT_PARTITIONS]    = "Mounting partitions...",
        [PROGRESS_INSTALL_KERNEL]      = "Installing kernel...",
        [PROGRESS_INSTALL_BOOTLOADER]  = "Installing boot loader...",
        [PROGRESS_UNMOUNT_PARTITIONS]  = "Unmounting partitions...",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(progress_phase_log, ProgressPhase);

typedef enum DeviceFit {
        DEVICE_FIT_ENOUGH_FREE_SPACE,
        DEVICE_FIT_INSUFFICIENT_FREE_SPACE,
        DEVICE_FIT_DISK_TOO_SMALL,
        DEVICE_FIT_CONFLICTING_DISK_LABEL_PRESENT,
        _DEVICE_FIT_MAX,
        _DEVICE_FIT_INVALID = -EINVAL,
} DeviceFit;

static const char *device_fit_table[_DEVICE_FIT_MAX] = {
        [DEVICE_FIT_ENOUGH_FREE_SPACE]              = "enough-free-space",
        [DEVICE_FIT_INSUFFICIENT_FREE_SPACE]        = "insufficient-free-space",
        [DEVICE_FIT_DISK_TOO_SMALL]                 = "disk-too-small",
        [DEVICE_FIT_CONFLICTING_DISK_LABEL_PRESENT] = "conflicting-disk-label-present",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(device_fit, DeviceFit);

typedef struct SysInstallContext {
        bool copy_locale;
        bool copy_keymap;
        bool copy_timezone;
        MachineCredentialContext credentials;
        char **definitions;
        bool erase;
        char *node;
        char *kernel_filename;
        int kernel_fd;
        bool touch_variables;

        sd_varlink *repart_link;

        sd_varlink *link; /* If 'more' is used on the Varlink call, we'll send progress info over this link */
} SysInstallContext;

static void sysinstall_context_done(SysInstallContext *c) {
        assert(c);

        strv_free(c->definitions);

        free(c->node);

        free(c->kernel_filename);
        safe_close(c->kernel_fd);

        machine_credential_context_done(&c->credentials);

        sd_varlink_flush_close_unref(c->repart_link);

        sd_varlink_unref(c->link);
}

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
        if (r > 0)
                arg_varlink = true;

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

static int sysinstall_context_notify(
                SysInstallContext *context,
                ProgressPhase phase,
                const char *object,
                unsigned percent) {

        int r;

        assert(context);
        assert(phase >= 0);
        assert(phase < _PROGRESS_PHASE_MAX);

        log_notice("%s%s%s",
                   emoji_enabled() ? phase == PROGRESS_ENCRYPT_CREDENTIALS ?  glyph(GLYPH_LOCK_AND_KEY) : glyph(GLYPH_COMPUTER_DISK) : "",
                   emoji_enabled() ? " " : "",
                   progress_phase_log_to_string(phase));

        if (context->link) {
                r = sd_varlink_notifybo(
                                context->link,
                                JSON_BUILD_PAIR_ENUM("phase", progress_phase_to_string(phase)),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("object", object),
                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("progress", percent, UINT_MAX));
                if (r < 0)
                        log_debug_errno(r, "Failed to send varlink notify progress notification, ignoring: %m");

                r = sd_varlink_flush(context->link);
                if (r < 0)
                        log_debug_errno(r, "Failed to flush varlink notify progress notification, ignoring: %m");
        }

        return 0;
}

typedef struct RepartResult {
        int ret;
        SysInstallContext *context;
} RepartResult;

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
                { "minimalSizeBytes", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       voffsetof(p, min_size),     0 },
                { "currentSizeBytes", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       voffsetof(p, current_size), 0 },
                { "needFreeBytes",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       voffsetof(p, need_free),    0 },
                { "phase",            _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_const_string, voffsetof(p, phase),        0 },
                { "object",           _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_const_string, voffsetof(p, object),       0 },
                { "progress",         _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         voffsetof(p, progress),     0 },
                {}
        };

        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return result->ret = r;

        if (error_id) {
                const char *sysinstall_error_id = NULL;

                if (streq(error_id, "io.systemd.Repart.InsufficientFreeSpace")) {
                        sysinstall_error_id = "io.systemd.SysInstall.InsufficientFreeSpace";
                        result->ret = log_error_errno(SYNTHETIC_ERRNO(ENOSPC), "Not enough free space on disk, cannot install.");
                } else if (streq(error_id, "io.systemd.Repart.DiskTooSmall")) {
                        sysinstall_error_id = "io.systemd.SysInstall.DiskTooSmall";

                        result->ret = log_error_errno(SYNTHETIC_ERRNO(E2BIG), "Disk too small for installation, cannot install.");
                } else if (streq(error_id, "io.systemd.Repart.ConflictingDiskLabelPresent")) {
                        sysinstall_error_id = "io.systemd.SysInstall.ConflictingDiskLabelPresent";

                        result->ret = log_error_errno(
                                        SYNTHETIC_ERRNO(EHWPOISON),
                                        "A conflicting disk label is already present on the target disk, cannot install unless disk is erased.");
                }

                if (sysinstall_error_id && result->context->link) {
                        r = sd_varlink_errorbo(
                                        result->context->link,
                                        sysinstall_error_id,
                                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("currentSizeBytes", p.current_size, UINT64_MAX),
                                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("needFreeBytes", p.need_free, UINT64_MAX),
                                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("minimalSizeBytes", p.min_size, UINT64_MAX));

                        if (r < 0)
                                return result->ret = r;

                        return result->ret;
                }

                r = sd_varlink_error_to_errno(error_id, reply); /* If this is a system errno style error, output it with %m */
                if (r != -EBADR)
                        return result->ret = log_error_errno(r, "Failed to issue io.systemd.Repart.Run() varlink call: %m");

                return result->ret = log_error_errno(r, "Failed to issue io.systemd.Repart.Run() varlink call: %s", error_id);
        }

        if ((p.progress != UINT_MAX || p.object) && result->context->link)
                (void) sysinstall_context_notify(result->context, PROGRESS_INSTALL_PARTITIONS, p.object, p.progress);

        return result->ret = 0;
}

static int sysinstall_context_invoke_repart_run(SysInstallContext *context) {

        int r;

        assert(context);

        r = connect_to_repart(&context->repart_link);
        if (r < 0)
                return r;

        /* Seeding the partitions might be very slow, disable timeout */
        r = sd_varlink_set_relative_timeout(context->repart_link, UINT64_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to disable IPC timeout: %m");

        RepartResult result = {
                .context = context,
        };

        sd_varlink_set_userdata(context->repart_link, &result);

        r = sd_varlink_bind_reply(context->repart_link, handle_repart_reply);
        if (r < 0)
                return log_error_errno(r, "Failed to bind repart reply callback: %m");

        r = sd_varlink_observebo(
                        context->repart_link,
                        "io.systemd.Repart.Run",
                        SD_JSON_BUILD_PAIR_STRING("node", context->node),
                        SD_JSON_BUILD_PAIR_STRING("empty", context->erase ? "force" : "allow"),
                        SD_JSON_BUILD_PAIR_BOOLEAN("dryRun", false),
                        SD_JSON_BUILD_PAIR_CONDITION(!!context->definitions, "definitions", SD_JSON_BUILD_STRV(context->definitions)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("deferPartitionsEmpty", true),
                        SD_JSON_BUILD_PAIR_BOOLEAN("deferPartitionsFactoryReset", true));
        if (r < 0)
                return log_error_errno(r, "Failed to issue io.systemd.Repart.Run() varlink call: %m");

        for (;;) {
                r = sd_varlink_is_idle(context->repart_link);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if varlink connection is idle: %m");
                if (r > 0)
                        break;

                r = sd_varlink_process(context->repart_link);
                if (r < 0)
                        return log_error_errno(r, "Failed to process varlink connection: %m");
                if (r != 0)
                        continue;

                r = sd_varlink_wait(context->repart_link, USEC_INFINITY);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for varlink connection events: %m");
        }

        sd_varlink_set_userdata(context->repart_link, NULL);

        r = sd_varlink_bind_reply(context->repart_link, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to unbind repart reply callback: %m");

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

        bool yes;
        r = prompt_loop_yes_no(arg_summary ? "Please type 'yes' to confirm the choices above and begin the installation" :
                                             "Please type 'yes' to begin the installation",
                               /* def= */ false,
                               &yes);
        if (r < 0)
                return r;
        if (!yes)
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

static int sysinstall_context_show_summary(SysInstallContext *context) {
        int r;

        printf("\n"
               "%sSummary:%s\n", ansi_underline(), ansi_normal());

        _cleanup_(table_unrefp) Table *table = table_new_vertical();
        if (!table)
                return log_oom();

        r = table_add_many(
                        table,
                        TABLE_FIELD, "Selected Disk",
                        TABLE_STRING, context->node,
                        TABLE_FIELD, "Erase Disk",
                        TABLE_BOOLEAN, context->erase,
                        TABLE_SET_COLOR, context->erase ? ansi_highlight_red() : NULL,
                        TABLE_FIELD, "Register in Firmware",
                        TABLE_BOOLEAN, context->touch_variables);
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
                MachineCredential *c = machine_credential_find(&context->credentials, *id);
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
        FOREACH_ARRAY(cred, context->credentials.credentials, context->credentials.n_credentials) {
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
                const char *root_dir,
                int root_fd,
                const char *kernel_filename,
                int kernel_fd,
                char **encrypted_credentials) {
        int r;

        assert(link);
        assert(root_dir);
        assert(root_fd >= 0);
        assert(kernel_filename);
        assert(kernel_fd >= 0);

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

static int sysinstall_context_read_credentials(SysInstallContext *context) {
        int r;

        if (context->copy_locale) {
                r = read_credential_locale(&context->credentials);
                if (r < 0)
                        return r;
        }

        if (context->copy_keymap) {
                r = read_credential_keymap(&context->credentials);
                if (r < 0)
                        return r;
        }

        if (context->copy_timezone) {
                r = read_credential_timezone(&context->credentials);
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

static int encrypt_credentials(sd_varlink **link, MachineCredentialContext *credentials, char ***encrypted) {
        int r;

        assert(link);
        assert(encrypted);

        FOREACH_ARRAY(cred, credentials->credentials, credentials->n_credentials) {
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

static int settle_definitions(char **definitions, char ***ret_definitions) {

        _cleanup_strv_free_ char **d = NULL;
        int r;

        assert(ret_definitions);

        if (definitions) {
                d = strv_copy(definitions);
                if (!d)
                        return log_oom();

                *ret_definitions = TAKE_PTR(d);

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
                d = strv_copy(CONF_PATHS_STRV("repart.sysinstall.d"));
                if (!d)
                        return log_oom();

                *ret_definitions = TAKE_PTR(d);
        }

        return 0;
}

static int sysinstall_context_settle_definitions(SysInstallContext *context,
                                                 char **definitions) {

        return settle_definitions(definitions, &context->definitions);
}

static int sysinstall_context_settle_kernel_image(SysInstallContext *context,
                                                  const char *kernel_image) {

        _cleanup_free_ char *kernel_filename = NULL;
        _cleanup_close_ int kernel_fd = -EBADF;
        int r;

        assert(context->kernel_fd < 0);
        assert(!context->kernel_filename);

        if (kernel_image) {
                r = path_extract_filename(kernel_image, &kernel_filename);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from kernel path '%s': %m", kernel_image);
                if (r == O_DIRECTORY)
                        return log_error_errno(SYNTHETIC_ERRNO(EISDIR), "Kernel path '%s' refers to directory, must be regular file, refusing.", kernel_image);

                kernel_fd = xopenat_full(XAT_FDROOT, kernel_image, O_RDONLY|O_CLOEXEC, XO_REGULAR, MODE_INVALID, NULL);
                if (kernel_fd < 0)
                        return log_error_errno(kernel_fd, "Failed to open kernel image '%s': %m", kernel_image);

        } else {
                r = find_current_kernel(&kernel_filename, &kernel_fd);
                if (r < 0)
                        return r;
        }

        context->kernel_filename = TAKE_PTR(kernel_filename);
        context->kernel_fd = TAKE_FD(kernel_fd);

        return 0;
}

static int sysinstall_context_run(SysInstallContext *context) {

        int r;

        assert(context);

        (void) sysinstall_context_notify(context, PROGRESS_ENCRYPT_CREDENTIALS, NULL, UINT_MAX);

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *creds_link = NULL;
        _cleanup_strv_free_ char **encrypted_credentials = NULL;
        r = encrypt_credentials(&creds_link, &context->credentials, &encrypted_credentials);
        if (r < 0)
                return r;

        (void) sysinstall_context_notify(context, PROGRESS_INSTALL_PARTITIONS, NULL, UINT_MAX);

        /* Do the main part of the installation */

        r = sysinstall_context_invoke_repart_run(context);
        if (r < 0)
                return r;

        (void) sysinstall_context_notify(context, PROGRESS_MOUNT_PARTITIONS, NULL, UINT_MAX);

        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *root_dir = NULL;
        _cleanup_close_ int root_fd = -EBADF;
        r = mount_image_privately_interactively(
                        context->node,
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

        (void) sysinstall_context_notify(context, PROGRESS_INSTALL_KERNEL, NULL, UINT_MAX);

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *bootctl_link = NULL;
        r = invoke_bootctl_link(&bootctl_link, root_dir, root_fd, context->kernel_filename, context->kernel_fd, encrypted_credentials);
        if (r < 0)
                return r;

        (void) sysinstall_context_notify(context, PROGRESS_INSTALL_BOOTLOADER, NULL, UINT_MAX);

        r = invoke_bootctl_install(&bootctl_link, context->touch_variables, root_dir, root_fd);
        if (r < 0)
                return r;

        (void) sysinstall_context_notify(context, PROGRESS_UNMOUNT_PARTITIONS, NULL, UINT_MAX);

        root_fd = safe_close(root_fd);
        r = umount_recursive(root_dir, /* flags= */ 0);
        if (r < 0)
                log_warning_errno(r, "Failed to unmount target disk, proceeding anyway: %m");
        loop_device = loop_device_unref(loop_device);
        sync();

        return 0;
}

typedef struct ListCandidateDevicesContext {
        char **definitions;
        bool subscribe;

        sd_varlink *repart_link; /* A repart connection to get candidate devices */
        sd_varlink *dry_run_repart_link; /* A second repart connection to perform a dry run on each node */

        sd_varlink *link;
} ListCandidateDevicesContext;

static ListCandidateDevicesContext* list_candidate_devices_context_new(void) {
        ListCandidateDevicesContext *context = new(ListCandidateDevicesContext, 1);

        if (!context)
                return NULL;

        *context = (ListCandidateDevicesContext) {};

        return context;
}

static ListCandidateDevicesContext* list_candidate_devices_context_free(ListCandidateDevicesContext *context) {
        if (!context)
                return NULL;

        strv_free(context->definitions);

        context->repart_link = sd_varlink_flush_close_unref(context->repart_link);
        context->dry_run_repart_link = sd_varlink_flush_close_unref(context->dry_run_repart_link);
        context->link = sd_varlink_unref(context->link);

        return mfree(context);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(ListCandidateDevicesContext*, list_candidate_devices_context_free);

static int list_candidate_devices_context_settle_definitions(ListCandidateDevicesContext *context,
                                                             char **definitions) {

        return settle_definitions(definitions, &context->definitions);
}

static void vl_on_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        assert(server);
        assert(link);

        list_candidate_devices_context_free(sd_varlink_set_userdata(link, NULL));
}

typedef struct DevicesResponse {
        const char *node;
        char **symlinks;
        uint64_t diskseq;
        uint64_t size;
        const char *model;
        const char *vendor;
        const char *subsystem;
        const char *action;
} DevicesResponse;

static void devices_response_done(DevicesResponse *p) {
        assert(p);

        p->symlinks = strv_free(p->symlinks);
}

static int fetch_candidate_devices_reply(
                sd_varlink *repart_link,
                sd_json_variant *reply,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        int r;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ListCandidateDevicesContext *context = ASSERT_PTR(userdata);

        if (error_id) {
                if (streq(error_id, "io.systemd.Repart.NoCandidateDevices"))
                        return sd_varlink_error(context->link, "io.systemd.SysInstall.NoCandidateDevices", NULL);

                return sd_varlink_error(context->link, error_id, NULL);
        }

        static const sd_json_dispatch_field dispatch_table[] = {
                { "node",      SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(DevicesResponse, node),      0 },
                { "symlinks",  SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,         offsetof(DevicesResponse, symlinks),  0 },
                { "diskseq",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       offsetof(DevicesResponse, diskseq),   0 },
                { "sizeBytes", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       offsetof(DevicesResponse, size),      0 },
                { "model",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(DevicesResponse, model),     0 },
                { "vendor",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(DevicesResponse, vendor),    0 },
                { "subsystem", SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(DevicesResponse, subsystem), 0 },
                { "action",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(DevicesResponse, action),    0 },
                {}
        };

        _cleanup_(devices_response_done) DevicesResponse p = {
                .diskseq = UINT64_MAX,
                .size = UINT64_MAX,
        };
        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return r;

        if (context->subscribe) {
                /* The action needs to be ready, remove or add else we don't support the action */
                if (streq(p.action, "ready"))
                        return sd_varlink_notifybo(context->link, SD_JSON_BUILD_PAIR("action", JSON_BUILD_CONST_STRING("ready")));

                if (streq(p.action, "remove"))
                        return sd_varlink_notifybo(context->link,
                                        SD_JSON_BUILD_PAIR("action", JSON_BUILD_CONST_STRING("remove")),
                                        SD_JSON_BUILD_PAIR_STRING("node", p.node));

                if (!streq(p.action, "add")) {
                        log_debug("Skip unsupported action '%s' while fetching candidate devices.", p.action);
                        return 0;
                }
        }

        uint64_t min_size = UINT64_MAX, current_size = UINT64_MAX, need_free = UINT64_MAX;
        r = invoke_repart(
                        &context->dry_run_repart_link,
                        p.node,
                        /* erase= */ false,
                        /* dry_run= */ true,
                        context->definitions,
                        &min_size,
                        &current_size,
                        &need_free);

        DeviceFit fit;
        if (r < 0) {
                if (r == -ENOSPC)
                        fit = DEVICE_FIT_INSUFFICIENT_FREE_SPACE;
                else if (r == -E2BIG)
                        fit = DEVICE_FIT_DISK_TOO_SMALL;
                else if (r == -EHWPOISON)
                        fit = DEVICE_FIT_CONFLICTING_DISK_LABEL_PRESENT;
                else
                        return r;
        } else
                fit = DEVICE_FIT_ENOUGH_FREE_SPACE;

        r = sd_json_buildo(&v,
                        SD_JSON_BUILD_PAIR_STRING("node", p.node),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("symlinks", p.symlinks),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("diskseq", p.diskseq, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("sizeBytes", p.size, UINT64_MAX),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("model", p.model),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("vendor", p.vendor),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("subsystem", p.subsystem),
                        JSON_BUILD_PAIR_ENUM("fit", device_fit_to_string(fit)),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("currentSizeBytes", current_size, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("needFreeBytes", need_free, UINT64_MAX),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("minimalSizeBytes", min_size, UINT64_MAX),
                        SD_JSON_BUILD_PAIR_CONDITION(context->subscribe, "action", JSON_BUILD_CONST_STRING("add")));
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES))
                return sd_varlink_notify(context->link, v);

        return sd_varlink_reply(context->link, v);
}

typedef struct ListCandidateDevicesParameters {
        char **definitions;
        bool subscribe;
} ListCandidateDevicesParameters;

static void list_candidate_devices_parameters_done(ListCandidateDevicesParameters *p) {
        assert(p);

        p->definitions = strv_free(p->definitions);
}

static int vl_method_list_candidate_devices(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {
        int r;

        assert(link);

        sd_varlink_server *varlink_server = sd_varlink_get_server(link);
        sd_event *event = sd_varlink_server_get_event(varlink_server);
        Hashmap **polkit_registry = ASSERT_PTR(sd_varlink_server_get_userdata(varlink_server));

        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.sysinstall.ListCandidateDevices",
                        /* details= */ NULL,
                        polkit_registry);
        if (r <= 0)
                return r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "definitions", SD_JSON_VARIANT_ARRAY,   json_dispatch_strv_path,  offsetof(ListCandidateDevicesParameters, definitions), SD_JSON_STRICT },
                { "subscribe",   SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(ListCandidateDevicesParameters, subscribe),   0              },
                {}
        };

        _cleanup_(list_candidate_devices_parameters_done) ListCandidateDevicesParameters p = {};
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        _cleanup_(list_candidate_devices_context_freep) ListCandidateDevicesContext* context = list_candidate_devices_context_new();
        if (!context)
                return log_oom();

        context->subscribe = p.subscribe;
        r = list_candidate_devices_context_settle_definitions(context, p.definitions);
        if (r < 0)
                return r;

        context->link = sd_varlink_ref(link);

        r = connect_to_repart(&context->repart_link);
        if (r < 0)
                return r;

        r = sd_varlink_attach_event(context->repart_link, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(
                                r,
                                "Failed to attach io.systemd.Repart.ListCandidateDevices() varlink connection to event loop: %m");

        r = sd_varlink_bind_reply(context->repart_link, fetch_candidate_devices_reply);
        if (r < 0)
                return r;

        r = sd_varlink_observebo(
                        context->repart_link,
                        "io.systemd.Repart.ListCandidateDevices",
                        SD_JSON_BUILD_PAIR_BOOLEAN("subscribe", context->subscribe),
                        SD_JSON_BUILD_PAIR_BOOLEAN("ignoreRoot", true));

        if (r < 0)
                return log_error_errno(
                                r,
                                "Failed to issue io.systemd.Repart.ListCandidateDevices() varlink call: %m");

        r = sd_varlink_server_bind_disconnect(varlink_server, vl_on_disconnect);
        if (r < 0)
                return r;

        /* The context is freed in vl_on_disconnect() */
        sd_varlink_set_userdata(context->repart_link, context);
        sd_varlink_set_userdata(link, TAKE_PTR(context));

        return 0;
}

typedef struct RunParameters {
        char *node;
        char **definitions;
        bool erase;
        bool variables;
        char *kernel_image;
        bool copy_locale;
        bool copy_keymap;
        bool copy_timezone;
        sd_json_variant *credentials;
} RunParameters;

static void run_parameters_done(RunParameters *p) {
        assert(p);

        p->node = mfree(p->node);
        p->definitions = strv_free(p->definitions);
        p->kernel_image = mfree(p->kernel_image);
        p->credentials = sd_json_variant_unref(p->credentials);
}

typedef struct CredentialParameters {
        const char *id;
        struct iovec value;
} CredentialParameters;

static void credential_parameters_done(CredentialParameters *p) {
        assert(p);

        iovec_done_erase(&p->value);
}

static int credentials_from_json_array(MachineCredentialContext *credentials, sd_json_variant *v) {

        int r;
        sd_json_variant *credential;

        assert(credentials);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "id",    SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(CredentialParameters, id),    SD_JSON_MANDATORY },
                { "value", SD_JSON_VARIANT_STRING, json_dispatch_unbase64_iovec,  offsetof(CredentialParameters, value), SD_JSON_MANDATORY },
                {}
        };

        JSON_VARIANT_ARRAY_FOREACH(credential, v) {
                _cleanup_(credential_parameters_done) CredentialParameters p = {};

                r = sd_json_dispatch(credential, dispatch_table, /* flags= */ 0, &p);
                if (r < 0)
                        return r;

                r = machine_credential_add(credentials, p.id, p.value.iov_base, p.value.iov_len);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int vl_method_run(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "node",            SD_JSON_VARIANT_STRING,  json_dispatch_path,       offsetof(RunParameters, node),          SD_JSON_MANDATORY | SD_JSON_STRICT },
                { "definitions",     SD_JSON_VARIANT_ARRAY,   json_dispatch_strv_path,  offsetof(RunParameters, definitions),   SD_JSON_NULLABLE | SD_JSON_STRICT  },
                { "erase",           SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(RunParameters, erase),         SD_JSON_MANDATORY                  },
                { "variables",       SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(RunParameters, variables),     SD_JSON_NULLABLE                   },
                { "kernelImagePath", SD_JSON_VARIANT_STRING,  json_dispatch_path,       offsetof(RunParameters, kernel_image),  SD_JSON_NULLABLE | SD_JSON_STRICT  },
                { "copyLocale",      SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(RunParameters, copy_locale),   SD_JSON_NULLABLE                   },
                { "copyKeymap",      SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(RunParameters, copy_keymap),   SD_JSON_NULLABLE                   },
                { "copyTimezone",    SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(RunParameters, copy_timezone), SD_JSON_NULLABLE                   },
                { "credentials",     SD_JSON_VARIANT_ARRAY,   sd_json_dispatch_variant, offsetof(RunParameters, credentials),   SD_JSON_NULLABLE                   },
                {}
        };

        int r;

        assert(link);

        sd_varlink_server *varlink_server = sd_varlink_get_server(link);
        Hashmap **polkit_registry = ASSERT_PTR(sd_varlink_server_get_userdata(varlink_server));

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

        _cleanup_(sysinstall_context_done) SysInstallContext context = (SysInstallContext) {
                .copy_locale = p.copy_locale,
                .copy_keymap = p.copy_keymap,
                .copy_timezone = p.copy_timezone,
                .erase = p.erase,
                .touch_variables = p.variables,
                .node = TAKE_PTR(p.node),
                .kernel_fd = -EBADF,
        };

        r = sysinstall_context_settle_definitions(&context, p.definitions);
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                context.link = sd_varlink_ref(link);

        r = credentials_from_json_array(&context.credentials, p.credentials);
        if (r < 0)
                return r;

        r = sysinstall_context_read_credentials(&context);
        if (r < 0)
                return r;

        r = sysinstall_context_settle_kernel_image(&context, p.kernel_image);
        if (r < 0)
                return r;

        r = sysinstall_context_run(&context);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        _cleanup_hashmap_free_ Hashmap *polkit_registry = NULL;
        int r;

        /* Invocation as Varlink service */

        r = varlink_server_new(
                        &varlink_server,
                        0,
                        /* userdata= */ &polkit_registry);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_SysInstall);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.SysInstall.ListCandidateDevices", vl_method_list_candidate_devices,
                        "io.systemd.SysInstall.Run",                  vl_method_run);
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

        _cleanup_(sysinstall_context_done) SysInstallContext context = (SysInstallContext) {
                .copy_locale = arg_copy_locale,
                .copy_keymap = arg_copy_keymap,
                .copy_timezone = arg_copy_timezone,
                .credentials = TAKE_STRUCT(arg_credentials),
                .kernel_fd = -EBADF,
        };

        r = sysinstall_context_settle_definitions(&context, arg_definitions);
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

        r = sysinstall_context_read_credentials(&context);
        if (r < 0)
                return r;

        r = sysinstall_context_settle_kernel_image(&context, arg_kernel_image);
        if (r < 0)
                return r;

        /* Verify we have everything we need */
        assert(arg_node);
        assert(arg_erase >= 0);
        assert(arg_touch_variables >= 0);

        context.node = TAKE_PTR(arg_node);
        context.touch_variables = arg_touch_variables;
        context.erase = arg_erase;

        if (arg_summary) {
                r = sysinstall_context_show_summary(&context);
                if (r < 0)
                        return r;
        }

        r = prompt_confirm();
        if (r < 0)
                return r;

        putchar('\n');

        r = sysinstall_context_run(&context);
        if (r < 0)
                return r;

        log_notice("%s%sInstallation succeeded.",
                   emoji_enabled() ? glyph(GLYPH_SPARKLES) : "", emoji_enabled() ? " " : "");

        r = maybe_reboot();
        if (r < 0)
                return r;

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
