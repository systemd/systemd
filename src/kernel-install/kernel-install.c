/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdbool.h>

#include "build.h"
#include "boot-entry.h"
#include "chase.h"
#include "conf-files.h"
#include "dissect-image.h"
#include "env-file.h"
#include "env-util.h"
#include "exec-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "find-esp.h"
#include "id128-util.h"
#include "kernel-image.h"
#include "main-func.h"
#include "mkdir.h"
#include "mount-util.h"
#include "parse-argument.h"
#include "path-util.h"
#include "pretty-print.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "verbs.h"

static bool arg_verbose = false;
static char *arg_esp_path = NULL;
static char *arg_xbootldr_path = NULL;
static char *arg_root = NULL;
static char *arg_image = NULL;
ImagePolicy *arg_image_policy = NULL;
static int arg_make_entry_directory = -1; /* tristate */

STATIC_DESTRUCTOR_REGISTER(arg_esp_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_xbootldr_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);

typedef enum Action {
        ACTION_ADD,
        ACTION_REMOVE,
        ACTION_INSPECT,
        _ACTION_MAX,
        _ACTION_INVALID = -EINVAL,
} Action;

typedef enum Layout {
        LAYOUT_AUTO,
        LAYOUT_UKI,
        LAYOUT_BLS,
        LAYOUT_OTHER,
        _LAYOUT_MAX,
        _LAYOUT_INVALID = -EINVAL,
} Layout;

static const char * const layout_table[_LAYOUT_MAX] = {
        [LAYOUT_AUTO]  = "auto",
        [LAYOUT_UKI]   = "uki",
        [LAYOUT_BLS]   = "bls",
        [LAYOUT_OTHER] = "other",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(layout, Layout);

typedef struct Context {
        int rfd;
        LoopDevice *loop_device;
        char *unlink_dir;

        Action action;
        sd_id128_t machine_id;
        bool machine_id_is_random;
        KernelImageType kernel_image_type;
        Layout layout;
        char *layout_other;
        char *conf_root;
        char *boot_root;
        BootEntryTokenType entry_token_type;
        char *entry_token;
        char *entry_dir;
        char *version;
        char *kernel;
        char **initrds;
        char *initrd_generator;
        char *uki_generator;
        char *staging_area;
        char **plugins;
        char **argv;
        char **envp;
} Context;

static void context_done(Context *c) {
        assert(c);

        free(c->layout_other);
        free(c->conf_root);
        free(c->boot_root);
        free(c->entry_token);
        free(c->entry_dir);
        free(c->version);
        free(c->kernel);
        strv_free(c->initrds);
        free(c->initrd_generator);
        free(c->uki_generator);
        if (c->action == ACTION_INSPECT)
                free(c->staging_area);
        else
                rm_rf_physical_and_free(c->staging_area);
        strv_free(c->plugins);
        strv_free(c->argv);
        strv_free(c->envp);

        safe_close(c->rfd);
        umount_and_rmdir_and_free(c->unlink_dir);
        loop_device_unref(c->loop_device);
}

static int context_open_root(Context *c) {
        int r;

        assert(c);

        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                arg_image_policy,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_VALIDATE_OS |
                                DISSECT_IMAGE_RELAX_VAR_CHECK,
                                &c->unlink_dir,
                                &c->rfd,
                                &c->loop_device);
                if (r < 0)
                        return r;

                arg_root = strdup(c->unlink_dir);
                if (!arg_root)
                        return log_oom();

                return 0;
        }

        c->rfd = open(empty_to_root(arg_root), O_CLOEXEC | O_DIRECTORY | O_PATH);
        if (c->rfd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", empty_to_root(arg_root));

        return 0;
}

static const char *context_get_layout(Context *c) {
        assert(c);
        assert(c->layout >= 0);

        return c->layout_other ?: layout_to_string(c->layout);
}

static int context_set_layout(Context *c, const char *s, const char *source) {
        Layout t;

        assert(c);
        assert(source);

        if (c->layout >= 0 || !s)
                return 0;

        assert(!c->layout_other);

        t = layout_from_string(s);
        if (t >= 0)
                c->layout = t;
        else if (isempty(s))
                c->layout = LAYOUT_AUTO;
        else {
                c->layout_other = strdup(s);
                if (!c->layout_other)
                        return log_oom();

                c->layout = LAYOUT_OTHER;
        }

        log_debug("layout=%s set via %s", context_get_layout(c), source);
        return 1;
}

static int context_set_machine_id(Context *c, const char *s, const char *source) {
        int r;

        assert(c);
        assert(source);

        if (!sd_id128_is_null(c->machine_id) || !s)
                return 0;

        r = sd_id128_from_string(s, &c->machine_id);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse machine ID specified in %s, ignoring.", source);

        if (sd_id128_is_null(c->machine_id))
                return 0;

        log_debug("MACHINE_ID=%s set via %s.", SD_ID128_TO_STRING(c->machine_id), source);
        return 1;
}

static int context_set_string(const char *s, const char *source, const char *name, char **dest) {
        char *p;

        assert(source);
        assert(name);
        assert(dest);

        if (*dest || !s)
                return 0;

        p = strdup(s);
        if (!p)
                return log_oom();

        log_debug("%s (%s) set via %s.", name, p, source);

        *dest = p;
        return 1;
}

static int context_set_initrd_generator(Context *c, const char *s, const char *source) {
        assert(c);
        return context_set_string(s, source, "INITRD_GENERATOR", &c->initrd_generator);
}

static int context_set_uki_generator(Context *c, const char *s, const char *source) {
        assert(c);
        return context_set_string(s, source, "UKI_GENERATOR", &c->uki_generator);
}

static int context_set_version(Context *c, const char *s) {
        assert(c);

        if (!filename_is_valid(s))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid version specified: %s", s);

        return context_set_string(s, "command line", "kernel version", &c->version);
}

static int context_set_path(Context *c, const char *s, const char *source, const char *name, char **dest) {
        char *p;
        int r;

        assert(c);
        assert(source);
        assert(name);
        assert(dest);

        if (*dest || !s)
                return 0;

        r = chaseat(c->rfd, s, CHASE_AT_RESOLVE_IN_ROOT, &p, /* ret_fd = */ NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to chase path %s for %s specified in %s, ignoring: %m",
                                         s, name, source);

        log_debug("%s (%s) set via %s.", name, p, source);

        *dest = p;
        return 1;
}

static int context_set_boot_root(Context *c, const char *s, const char *source) {
        assert(c);
        return context_set_path(c, s, source, "BOOT_ROOT", &c->boot_root);
}

static int context_set_conf_root(Context *c, const char *s, const char *source) {
        assert(c);
        return context_set_path(c, s, source, "CONF_ROOT", &c->conf_root);
}

static int context_set_kernel(Context *c, const char *s) {
        assert(c);
        return context_set_path(c, s, "command line", "kernel image file", &c->kernel);
}

static int context_set_path_strv(Context *c, char* const* strv, const char *source, const char *name, char ***dest) {
        _cleanup_strv_free_ char **w = NULL;
        int r;

        assert(c);
        assert(source);
        assert(name);
        assert(dest);

        if (*dest || strv_isempty(strv))
                return 0;

        STRV_FOREACH(s, strv) {
                char *p;

                r = chaseat(c->rfd, *s, CHASE_AT_RESOLVE_IN_ROOT, &p, /* ret_fd = */ NULL);
                if (r < 0)
                        return log_warning_errno(r, "Failed to chase path %s for %s specified in %s, ignoring: %m",
                                                 *s, name, source);

                r = strv_consume(&w, p);
                if (r < 0)
                        return log_oom();
        }

        log_debug("%s set via %s", name, source);

        *dest = TAKE_PTR(w);
        return 1;
}

static int context_set_plugins(Context *c, const char *s, const char *source) {
        _cleanup_strv_free_ char **v = NULL;

        assert(c);

        if (c->plugins || !s)
                return 0;

        v = strv_split(s, NULL);
        if (!v)
                return log_oom();

        return context_set_path_strv(c, v, source, "plugins", &c->plugins);
}

static int context_set_initrds(Context *c, char* const* strv) {
        assert(c);
        return context_set_path_strv(c, strv, "command line", "initrds", &c->initrds);
}

static int context_load_environment(Context *c) {
        assert(c);

        (void) context_set_machine_id(c, getenv("MACHINE_ID"), "environment");
        (void) context_set_boot_root(c, getenv("BOOT_ROOT"), "environment");
        (void) context_set_conf_root(c, getenv("KERNEL_INSTALL_CONF_ROOT"), "environment");
        (void) context_set_plugins(c, getenv("KERNEL_INSTALL_PLUGINS"), "environment");
        return 0;
}

static int context_ensure_conf_root(Context *c) {
        int r;

        assert(c);

        if (c->conf_root)
                return 0;

        r = chaseat(c->rfd, "/etc/kernel", CHASE_AT_RESOLVE_IN_ROOT, &c->conf_root, /* ret_fd = */ NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to chase /etc/kernel, ignoring: %m");

        return 0;
}

static int context_load_install_conf_one(Context *c, const char *path) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char
                *conf = NULL, *machine_id = NULL, *boot_root = NULL, *layout = NULL,
                *initrd_generator = NULL, *uki_generator = NULL;
        int r;

        assert(c);
        assert(path);

        conf = path_join(path, "install.conf");
        if (!conf)
                return log_oom();

        r = chaseat(c->rfd, conf, CHASE_AT_RESOLVE_IN_ROOT, NULL, &fd);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to chase %s: %m", conf);

        log_debug("Loading %s…", conf);

        r = parse_env_file_fd(fd, conf,
                              "MACHINE_ID",       &machine_id,
                              "BOOT_ROOT",        &boot_root,
                              "layout",           &layout,
                              "initrd_generator", &initrd_generator,
                              "uki_generator",    &uki_generator);
        if (r < 0)
                return log_error_errno(r, "Failed to parse '%s': %m", conf);

        (void) context_set_machine_id(c, machine_id, conf);
        (void) context_set_boot_root(c, boot_root, conf);
        (void) context_set_layout(c, layout, conf);
        (void) context_set_initrd_generator(c, initrd_generator, conf);
        (void) context_set_uki_generator(c, uki_generator, conf);

        log_debug("Loaded %s.", conf);
        return 1;
}

static int context_load_install_conf(Context *c) {
        int r;

        assert(c);

        if (c->conf_root) {
                r = context_load_install_conf_one(c, c->conf_root);
                if (r != 0)
                        return r;
        }

        STRV_FOREACH(p, CONF_PATHS_STRV("kernel")) {
                r = context_load_install_conf_one(c, *p);
                if (r != 0)
                        return r;
        }

        return 0;
}

static int context_load_machine_info(Context *c) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *machine_id = NULL, *layout = NULL;
        static const char *path = "/etc/machine-info";
        int r;

        assert(c);

        /* If the user configured an explicit machine ID to use in /etc/machine-info to use for our purpose,
         * we'll use that instead (for compatibility). */

        if (!sd_id128_is_null(c->machine_id) && c->layout >= 0)
                return 0;

        r = chaseat(c->rfd, path, CHASE_AT_RESOLVE_IN_ROOT, NULL, &fd);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to chase %s: %m", path);

        log_debug("Loading %s…", path);

        r = parse_env_file_fd(fd, path,
                              "KERNEL_INSTALL_MACHINE_ID", &machine_id,
                              "KERNEL_INSTALL_LAYOUT", &layout);
        if (r < 0)
                return log_error_errno(r, "Failed to parse '%s': %m", path);

        (void) context_set_machine_id(c, machine_id, path);
        (void) context_set_layout(c, layout, path);
        return 0;
}

static int context_load_machine_id(Context *c) {
        int r;

        assert(c);

        r = id128_get_machine_at(c->rfd, &c->machine_id);
        if (r < 0) {
                if (ERRNO_IS_MACHINE_ID_UNSET(r))
                        return 0;
                return log_error_errno(r, "Failed to load machine ID from /etc/machine-id: %m");
        }

        log_debug("MACHINE_ID=%s set via /etc/machine-id.", SD_ID128_TO_STRING(c->machine_id));
        return 1; /* loaded */
}

static int context_ensure_machine_id(Context *c) {
        int r;

        assert(c);

        if (!sd_id128_is_null(c->machine_id))
                return 0;

        /* If /etc/machine-id is initialized we'll use it. */
        r = context_load_machine_id(c);
        if (r != 0)
                return r;

        /* Otherwise we'll use a freshly generated one. */
        r = sd_id128_randomize(&c->machine_id);
        if (r < 0)
                return log_error_errno(r, "Failed to generate random ID: %m");

        c->machine_id_is_random = true;
        log_debug("New machine ID '%s' generated.", SD_ID128_TO_STRING(c->machine_id));
        return 0;
}

static int context_acquire_xbootldr(Context *c) {
        int r;

        assert(c);
        assert(!c->boot_root);

        r = find_xbootldr_and_warn_at(
                        /* rfd = */ c->rfd,
                        /* path = */ arg_xbootldr_path,
                        /* unprivileged_mode= */ geteuid() != 0,
                        /* ret_path = */ &c->boot_root,
                        /* ret_uuid = */ NULL,
                        /* ret_devid = */ NULL);
        if (IN_SET(r, -ENOKEY, -EACCES)) {
                log_debug_errno(r, "Couldn't find an XBOOTLDR partition.");
                return 0;
        }
        if (r < 0)
                return r;

        log_debug("Using XBOOTLDR partition at %s as $BOOT_ROOT.", c->boot_root);
        return 1; /* found */
}

static int context_acquire_esp(Context *c) {
        int r;

        assert(c);
        assert(!c->boot_root);

        r = find_esp_and_warn_at(
                        /* rfd = */ c->rfd,
                        /* path = */ arg_esp_path,
                        /* unprivileged_mode= */ geteuid() != 0,
                        /* ret_path = */ &c->boot_root,
                        /* ret_part = */ NULL,
                        /* ret_pstart = */ NULL,
                        /* ret_psize = */ NULL,
                        /* ret_uuid = */ NULL,
                        /* ret_devid = */ NULL);
        if (IN_SET(r, -ENOKEY, -EACCES)) {
                log_debug_errno(r, "Couldn't find EFI system partition, ignoring.");
                return 0;
        }
        if (r < 0)
                return r;

        log_debug("Using EFI System Partition at %s as $BOOT_ROOT.", c->boot_root);
        return 1; /* found */
}

static int context_ensure_boot_root(Context *c) {
        int r;

        assert(c);

        /* If BOOT_ROOT is specified in environment or install.conf, then use it. */
        if (c->boot_root)
                return 0;

        /* Otherwise, use XBOOTLDR partition, if exist. */
        r = context_acquire_xbootldr(c);
        if (r != 0)
                return r;

        /* Otherwise, use ESP partition, if exist. */
        r = context_acquire_esp(c);
        if (r != 0)
                return r;

        /* If all else fails, use /boot. */
        r = chaseat(c->rfd, "/boot", CHASE_AT_RESOLVE_IN_ROOT, &c->boot_root, /* ret_fd = */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to chase '/boot': %m");

        log_debug("KERNEL_INSTALL_BOOT_ROOT autodetection yielded no candidates, using \"%s\".", c->boot_root);
        return 0;
}

static int context_ensure_entry_token(Context *c) {
        int r;

        assert(c);

        /* Now that we determined the machine ID to use, let's determine the "token" for the boot loader
         * entry to generate. We use that for naming the directory below $BOOT where we want to place the
         * kernel/initrd and related resources, as well for naming the .conf boot loader spec entry.
         * Typically this is just the machine ID, but it can be anything else, too, if we are told so. */

        r = boot_entry_token_ensure_at(
                        c->rfd,
                        c->conf_root,
                        c->machine_id,
                        c->machine_id_is_random,
                        &c->entry_token_type,
                        &c->entry_token);
        if (r < 0)
                return r;

        log_debug("Using entry token: %s", c->entry_token);
        return 0;
}

static int context_load_plugins(Context *c) {
        int r;

        assert(c);

        if (c->plugins)
                return 0;

        r = conf_files_list_strv_at(
                        &c->plugins,
                        ".install",
                        c->rfd,
                        CONF_FILES_EXECUTABLE | CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED,
                        (const char**) CONF_PATHS_STRV("kernel/install.d"));
        if (r < 0)
                return log_error_errno(r, "Failed to find plugins: %m");

        return 0;
}

static int context_init(Context *c) {
        int r;

        assert(c);

        r = context_open_root(c);
        if (r < 0)
                return r;

        r = context_load_environment(c);
        if (r < 0)
                return r;

        r = context_ensure_conf_root(c);
        if (r < 0)
                return r;

        r = context_load_install_conf(c);
        if (r < 0)
                return r;

        r = context_load_machine_info(c);
        if (r < 0)
                return r;

        r = context_ensure_machine_id(c);
        if (r < 0)
                return r;

        r = context_ensure_boot_root(c);
        if (r < 0)
                return r;

        r = context_ensure_entry_token(c);
        if (r < 0)
                return r;

        r = context_load_plugins(c);
        if (r < 0)
                return r;

        return 0;
}

static int context_inspect_kernel(Context *c) {
        assert(c);

        if (!c->kernel)
                return 0;

        return inspect_kernel(c->rfd, c->kernel, &c->kernel_image_type, NULL, NULL, NULL);
}

static int context_ensure_layout(Context *c) {
        _cleanup_free_ char *path = NULL, *srel = NULL;
        int r;

        assert(c);
        assert(c->boot_root);
        assert(c->entry_token);

        if (c->layout >= 0 && c->layout != LAYOUT_AUTO)
                return 0;

        /* No layout configured by the administrator. Let's try to figure it out automatically from metadata
         * already contained in $BOOT_ROOT. */

        if (c->kernel_image_type == KERNEL_IMAGE_TYPE_UKI) {
                c->layout = LAYOUT_UKI;
                log_debug("Kernel image type is %s, using layout=%s.",
                          kernel_image_type_to_string(c->kernel_image_type), layout_to_string(c->layout));
                return 0;
        }

        path = path_join(c->boot_root, "loader/entries.srel");
        if (!path)
                return log_oom();

        r = read_one_line_file_at(c->rfd, path, &srel);
        if (r >= 0) {
                if (streq(srel, "type1"))
                        /* The loader/entries.srel file clearly indicates that the installed boot loader
                         * implements the proper standard upstream boot loader spec for Type #1 entries.
                         * Let's default to that, then. */
                        c->layout = LAYOUT_BLS;
                else
                        /* The loader/entries.srel file indicates some other spec is implemented and owns the
                         * /loader/entries/ directory. Since we have no idea what that means, let's stay away
                         * from it by default. */
                        c->layout = LAYOUT_OTHER;

                log_debug("%s with '%s' found, using layout=%s.", path, srel, layout_to_string(c->layout));
                return 0;

        } else if (r != -ENOENT)
                return log_error_errno(r, "Failed to read %s: %m", path);

        free(path);
        path = path_join(c->boot_root, c->entry_token);
        if (!path)
                return log_oom();

        r = is_dir_full(c->rfd, path, /* follow = */ false);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to check if '%s' is a directory: %m", path);
        if (r > 0) {
                /* If the metadata in $BOOT_ROOT doesn't tell us anything, then check if the entry token
                 * directory already exists. If so, let's assume it's the standard boot loader spec, too. */
                c->layout = LAYOUT_BLS;
                log_debug("%s exists, using layout=%s.", path, layout_to_string(c->layout));
                return 0;
        }

        /* There's no metadata in $BOOT_ROOT, and apparently no entry token directory installed? Then we
         * really don't know anything. */
        c->layout = LAYOUT_OTHER;
        log_debug("Entry-token directory not found, using layout=%s.", layout_to_string(c->layout));
        return 0;
}

static int context_setup_staging_area(Context *c) {
        static const char *template = "/tmp/kernel-install.staging.XXXXXX";
        int r;

        assert(c);

        if (c->staging_area)
                return 0;

        if (c->action == ACTION_INSPECT) {
                c->staging_area = strdup(template);
                if (!c->staging_area)
                        return log_oom();
        } else {
                r = mkdtemp_malloc(template, &c->staging_area);
                if (r < 0)
                        return log_error_errno(r, "Failed to create staging area: %m");
        }

        return 0;
}

static int context_build_entry_dir(Context *c) {
        assert(c);
        assert(c->boot_root);
        assert(c->entry_token);
        assert(c->version || c->action == ACTION_INSPECT);

        if (c->entry_dir)
                return 0;

        c->entry_dir = path_join(c->boot_root, c->entry_token, c->version ?: "$KERNEL_VERSION");
        if (!c->entry_dir)
                return log_oom();

        log_debug("Using ENTRY_DIR=%s", c->entry_dir);
        return 0;
}

static bool context_should_make_entry_dir(Context *c) {
        assert(c);

        /* Compatibility with earlier versions that used the presence of $BOOT_ROOT/$ENTRY_TOKEN to signal to
         * 00-entry-directory to create $ENTRY_DIR to serve as the indication to use or to not use the BLS */

        if (arg_make_entry_directory < 0)
                return c->layout == LAYOUT_BLS;

        return arg_make_entry_directory;
}

static int context_make_entry_dir(Context *c) {
        _cleanup_close_ int fd = -EBADF;

        assert(c);
        assert(c->entry_dir);

        if (c->action != ACTION_ADD)
                return 0;

        if (!context_should_make_entry_dir(c))
                return 0;

        log_debug("mkdir -p %s", c->entry_dir);
        fd = chase_and_openat(c->rfd, c->entry_dir, CHASE_AT_RESOLVE_IN_ROOT | CHASE_MKDIR_0755, O_CLOEXEC | O_CREAT | O_DIRECTORY | O_PATH, NULL);
        if (fd < 0)
                return log_error_errno(fd, "Failed to make directory '%s': %m", c->entry_dir);

        return 0;
}

static int context_remove_entry_dir(Context *c) {
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -EBADF;
        struct stat st;
        int r;

        assert(c);
        assert(c->entry_dir);

        if (c->action != ACTION_REMOVE)
                return 0;

        if (!context_should_make_entry_dir(c))
                return 0;

        log_debug("rm -rf %s", c->entry_dir);
        fd = chase_and_openat(c->rfd, c->entry_dir, CHASE_AT_RESOLVE_IN_ROOT, O_CLOEXEC | O_DIRECTORY, &p);
        if (fd < 0) {
                if (IN_SET(fd, -ENOTDIR, -ENOENT))
                        return 0;
                return log_debug_errno(fd, "Failed to chase and open %s, ignoring: %m", c->entry_dir);
        }

        if (fstat(fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat %s: %m", p);

        r = rm_rf_children(TAKE_FD(fd), REMOVE_PHYSICAL|REMOVE_MISSING_OK|REMOVE_CHMOD, &st);
        if (r < 0)
                log_debug_errno(r, "Failed to remove children of %s, ignoring: %m", p);

        if (unlinkat(c->rfd, p, AT_REMOVEDIR) < 0)
                log_debug_errno(errno, "Failed to remove %s, ignoring: %m", p);

        return 0;
}

static int strv_extend_path(char ***a, const char *path) {
        char *p;

        assert(a);
        assert(path);

        p = path_join(arg_root, path);
        if (!p)
                return -ENOMEM;

        return strv_consume(a, p);
}

static int context_build_arguments(Context *c) {
        _cleanup_strv_free_ char **a = NULL;
        const char *verb;
        int r;

        assert(c);
        assert(c->entry_dir);

        if (c->argv)
                return 0;

        switch (c->action) {
        case ACTION_ADD:
                assert(c->version);
                assert(c->kernel);
                verb = "add";
                break;

        case ACTION_REMOVE:
                assert(c->version);
                assert(!c->kernel);
                assert(!c->initrds);
                verb = "remove";
                break;

        case ACTION_INSPECT:
                assert(!c->version);
                assert(!c->initrds);
                verb = "<add|remove>";
                break;

        default:
                assert_not_reached();
        }

        a = strv_new("dummy-arg", /* to make strv_free() works for this variable. */
                     verb,
                     c->version ?: "$KERNEL_VERSION");
        if (!a)
                return log_oom();

        r = strv_extend_path(&a, c->entry_dir);
        if (r < 0)
                return log_oom();

        if (c->action == ACTION_ADD) {
                r = strv_extend_path(&a, c->kernel);
                if (r < 0)
                        return log_oom();

                STRV_FOREACH(i, c->initrds) {
                        r = strv_extend_path(&a, *i);
                        if (r < 0)
                                return log_oom();
                }

        } else if (c->action == ACTION_INSPECT) {
                if (c->kernel)
                        r = strv_extend_path(&a, c->kernel);
                else
                        r = strv_extend(&a, "[$KERNEL_IMAGE]");
                if (r < 0)
                        return log_oom();

                r = strv_extend(&a, "[$INITRD...]");
                if (r < 0)
                        return log_oom();
        }

        c->argv = TAKE_PTR(a);
        return 0;
}

static int context_build_environment(Context *c) {
        _cleanup_free_ char *boot_root_abs = NULL;
        _cleanup_strv_free_ char **e = NULL;
        int r;

        assert(c);

        if (c->envp)
                return 0;

        boot_root_abs = path_join(arg_root, c->boot_root);
        if (!boot_root_abs)
                return log_oom();

        r = strv_env_assign_many(&e,
                                 "LC_COLLATE",                      "C",
                                 "KERNEL_INSTALL_VERBOSE",          one_zero(arg_verbose),
                                 "KERNEL_INSTALL_IMAGE_TYPE",       kernel_image_type_to_string(c->kernel_image_type),
                                 "KERNEL_INSTALL_MACHINE_ID",       SD_ID128_TO_STRING(c->machine_id),
                                 "KERNEL_INSTALL_ENTRY_TOKEN",      c->entry_token,
                                 "KERNEL_INSTALL_ROOT",             strempty(arg_root),
                                 "KERNEL_INSTALL_BOOT_ROOT",        boot_root_abs,
                                 "KERNEL_INSTALL_LAYOUT",           context_get_layout(c),
                                 "KERNEL_INSTALL_INITRD_GENERATOR", strempty(c->initrd_generator),
                                 "KERNEL_INSTALL_UKI_GENERATOR",    strempty(c->uki_generator),
                                 "KERNEL_INSTALL_STAGING_AREA",     c->staging_area);
        if (r < 0)
                return log_error_errno(r, "Failed to build environment variables for plugins: %m");

        c->envp = TAKE_PTR(e);
        return 0;
}

static int context_prepare_execution(Context *c) {
        int r;

        assert(c);

        r = context_inspect_kernel(c);
        if (r < 0)
                return r;

        r = context_ensure_layout(c);
        if (r < 0)
                return r;

        r = context_setup_staging_area(c);
        if (r < 0)
                return r;

        r = context_build_entry_dir(c);
        if (r < 0)
                return r;

        r = context_build_arguments(c);
        if (r < 0)
                return r;

        r = context_build_environment(c);
        if (r < 0)
                return r;

        return 0;
}

static int context_execute(Context *c) {
        int r;

        assert(c);

        r = context_make_entry_dir(c);
        if (r < 0)
                return r;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *joined = NULL;

                joined = strv_join_full(c->plugins, "", "\n  ", /* escape_separator = */ false);
                log_debug("Plugins: %s", strna(joined));

                free(joined);

                joined = strv_join_full(c->envp, "", "\n  ", /* escape_separator = */ false);
                log_debug("Environment: %s", strna(joined));

                free(joined);

                joined = strv_join_full(strv_skip(c->argv, 1), " ", arg_root, /* escape_separator = */ false);
                log_debug("Plugin arguments: %s", strna(joined));
        }

        r = execute_strv(
                        /* name = */ NULL,
                        c->plugins,
                        arg_root,
                        USEC_INFINITY,
                        /* callbacks = */ NULL,
                        /* callback_args = */ NULL,
                        c->argv,
                        c->envp,
                        EXEC_DIR_SKIP_REMAINING);
        if (r < 0)
                return r;

        r = context_remove_entry_dir(c);
        if (r < 0)
                return r;

        return 0;
}

static int verb_add(int argc, char *argv[], void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(argc >= 3);
        assert(argv);

        c->action = ACTION_ADD;

        r = context_set_version(c, argv[1]);
        if (r < 0)
                return r;

        r = context_set_kernel(c, argv[2]);
        if (r < 0)
                return r;

        r = context_set_initrds(c, strv_skip(argv, 3));
        if (r < 0)
                return r;

        r = context_prepare_execution(c);
        if (r < 0)
                return r;

        return context_execute(c);
}

static int run_as_installkernel(int argc, char *argv[], Context *c) {
        /* kernel's install.sh invokes us as
         *   /sbin/installkernel <version> <vmlinuz> <map> <installation-dir>
         * We ignore the last two arguments. */
        if (optind + 2 > argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "'installkernel' command requires at least two arguments.");

        return verb_add(3, STRV_MAKE("add", argv[optind], argv[optind+1]), c);
}

static int verb_remove(int argc, char *argv[], void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(argc == 2);
        assert(argv);

        c->action = ACTION_REMOVE;

        r = context_set_version(c, argv[1]);
        if (r < 0)
                return r;

        r = context_prepare_execution(c);
        if (r < 0)
                return r;

        return context_execute(c);
}

static int verb_inspect(int argc, char *argv[], void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        _cleanup_free_ char *prefix = NULL, *joined = NULL;
        int r;

        c->action = ACTION_INSPECT;

        if (argc >= 2) {
                r = context_set_kernel(c, argv[1]);
                if (r < 0)
                        return r;
        }

        r = context_prepare_execution(c);
        if (r < 0)
                return r;

        prefix = strjoin("  ", strempty(arg_root));
        if (!prefix)
                return log_oom();

        puts("Plugins:");
        strv_print_full(c->plugins, prefix);
        puts("");

        puts("Environment:");
        strv_print_full(c->envp, "  ");
        puts("");

        puts("Plugin arguments:");
        joined = strv_join(strv_skip(c->argv, 1), " ");
        printf("  %s\n", strna(joined));

        return 0;
}

static bool bypass(void) {
        int r;

        r = getenv_bool("KERNEL_INSTALL_BYPASS");
        if (r <= 0) {
                if (r != -ENXIO)
                        log_debug_errno(r, "Failed to parse $KERNEL_INSTALL_BYPASS, assuming no.");
                return false;
        }

        log_debug("$KERNEL_INSTALL_BYPASS is enabled, skipping execution.");
        return true;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("kernel-install", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND ...\n\n"
               "%2$sAdd and remove kernel and initrd images to and from /boot%3$s\n"
               "\nUsage:\n"
               "  %1$s [OPTIONS...] add KERNEL-VERSION KERNEL-IMAGE [INITRD-FILE...]\n"
               "  %1$s [OPTIONS...] remove KERNEL-VERSION\n"
               "  %1$s [OPTIONS...] inspect [KERNEL-IMAGE]\n"
               "\nOptions:\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "  -v --verbose           Increase verbosity\n"
               "     --esp-path=PATH     Path to the EFI System Partition (ESP)\n"
               "     --boot-path=PATH    Path to the $BOOT partition\n"
               "     --root=PATH         Operate on an alternate filesystem root\n"
               "     --image=PATH        Operate on disk image as filesystem root\n"
               "     --image-policy=POLICY\n"
               "                         Specify disk image dissection policy\n"
               "     --make-entry-directory=yes|no|auto\n"
               "                         Create $BOOT/ENTRY-TOKEN/ directory\n"
               "     --entry-token=machine-id|os-id|os-image-id|auto|literal:…\n"
               "                         Entry token to use for this installation\n"
               "\nSee the %4$s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[], Context *c) {
        enum {
                ARG_VERSION = 0x100,
                ARG_ESP_PATH,
                ARG_BOOT_PATH,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_IMAGE_POLICY,
                ARG_MAKE_ENTRY_DIRECTORY,
                ARG_ENTRY_TOKEN,
        };
        static const struct option options[] = {
                { "help",                 no_argument,       NULL, 'h'                      },
                { "version",              no_argument,       NULL, ARG_VERSION              },
                { "verbose",              no_argument,       NULL, 'v'                      },
                { "esp-path",             required_argument, NULL, ARG_ESP_PATH             },
                { "boot-path",            required_argument, NULL, ARG_BOOT_PATH            },
                { "root",                 required_argument, NULL, ARG_ROOT                 },
                { "image",                required_argument, NULL, ARG_IMAGE                },
                { "image-policy",         required_argument, NULL, ARG_IMAGE_POLICY         },
                { "make-entry-directory", required_argument, NULL, ARG_MAKE_ENTRY_DIRECTORY },
                { "entry-token",          required_argument, NULL, ARG_ENTRY_TOKEN          },
                {}
        };
        int t, r;

        assert(argc >= 0);
        assert(argv);
        assert(c);

        while ((t = getopt_long(argc, argv, "hv", options, NULL)) >= 0)
                switch (t) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'v':
                        log_set_max_level(LOG_DEBUG);
                        arg_verbose = true;
                        break;

                case ARG_ESP_PATH:
                        r = parse_path_argument(optarg, /* suppress_root = */ false, &arg_esp_path);
                        if (r < 0)
                                return log_oom();
                        break;

                case ARG_BOOT_PATH:
                        r = parse_path_argument(optarg, /* suppress_root = */ false, &arg_xbootldr_path);
                        if (r < 0)
                                return log_oom();
                        break;

                case ARG_ROOT:
                        r = parse_path_argument(optarg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE_POLICY:
                        r = parse_image_policy_argument(optarg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                case ARG_MAKE_ENTRY_DIRECTORY:
                        if (streq(optarg, "auto"))
                                arg_make_entry_directory = -1;
                        else {
                                r = parse_boolean_argument("--make-entry-directory=", optarg, NULL);
                                if (r < 0)
                                        return r;

                                arg_make_entry_directory = r;
                        }
                        break;

                case ARG_ENTRY_TOKEN:
                        r = parse_boot_entry_token_type(optarg, &c->entry_token_type, &c->entry_token);
                        if (r < 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_root && arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        return 1;
}

static int run(int argc, char* argv[]) {
        static const Verb verbs[] = {
                { "add",         3,        VERB_ANY, 0,            verb_add            },
                { "remove",      2,        2,        0,            verb_remove         },
                { "inspect",     1,        2,        VERB_DEFAULT, verb_inspect        },
                {}
        };
        _cleanup_(context_done) Context c = {
                .rfd = -EBADF,
                .action = _ACTION_INVALID,
                .kernel_image_type = KERNEL_IMAGE_TYPE_UNKNOWN,
                .layout = _LAYOUT_INVALID,
                .entry_token_type = BOOT_ENTRY_TOKEN_AUTO,
        };
        int r;

        log_setup();

        if (bypass())
                return 0;

        r = parse_argv(argc, argv, &c);
        if (r <= 0)
                return r;

        r = context_init(&c);
        if (r < 0)
                return r;

        if (invoked_as(argv, "installkernel"))
                return run_as_installkernel(argc, argv, &c);

        return dispatch_verb(argc, argv, verbs, &c);
}

DEFINE_MAIN_FUNCTION(run);
