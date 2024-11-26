/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdbool.h>
#include <sys/utsname.h>

#include "boot-entry.h"
#include "build.h"
#include "chase.h"
#include "conf-files.h"
#include "dirent-util.h"
#include "env-file.h"
#include "env-util.h"
#include "exec-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "find-esp.h"
#include "format-table.h"
#include "fs-util.h"
#include "id128-util.h"
#include "image-policy.h"
#include "kernel-config.h"
#include "kernel-image.h"
#include "main-func.h"
#include "mkdir.h"
#include "mount-util.h"
#include "parse-argument.h"
#include "path-util.h"
#include "pretty-print.h"
#include "recurse-dir.h"
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
static int arg_make_entry_directory = -1; /* tristate */
static PagerFlags arg_pager_flags = 0;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static char *arg_root = NULL;
static char *arg_image = NULL;
static ImagePolicy *arg_image_policy = NULL;
static bool arg_legend = true;

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

#define CONTEXT_NULL (Context) { .rfd = -EBADF }

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
}

static int context_copy(const Context *source, Context *ret) {
        int r;

        assert(source);
        assert(ret);
        assert(source->rfd >= 0 || source->rfd == AT_FDCWD);

        _cleanup_(context_done) Context copy = (Context) {
                .rfd = AT_FDCWD,
                .action = source->action,
                .machine_id = source->machine_id,
                .machine_id_is_random = source->machine_id_is_random,
                .kernel_image_type = source->kernel_image_type,
                .layout = source->layout,
                .entry_token_type = source->entry_token_type,
        };

        if (source->rfd >= 0) {
                copy.rfd = fd_reopen(source->rfd, O_CLOEXEC|O_DIRECTORY|O_PATH);
                if (copy.rfd < 0)
                        return copy.rfd;
        }

        r = strdup_to(&copy.layout_other, source->layout_other);
        if (r < 0)
                return r;
        r = strdup_to(&copy.conf_root, source->conf_root);
        if (r < 0)
                return r;
        r = strdup_to(&copy.boot_root, source->boot_root);
        if (r < 0)
                return r;
        r = strdup_to(&copy.entry_token, source->entry_token);
        if (r < 0)
                return r;
        r = strdup_to(&copy.entry_dir, source->entry_dir);
        if (r < 0)
                return r;
        r = strdup_to(&copy.version, source->version);
        if (r < 0)
                return r;
        r = strdup_to(&copy.kernel, source->kernel);
        if (r < 0)
                return r;
        r = strv_copy_unless_empty(source->initrds, &copy.initrds);
        if (r < 0)
                return r;
        r = strdup_to(&copy.initrd_generator, source->initrd_generator);
        if (r < 0)
                return r;
        r = strdup_to(&copy.uki_generator, source->uki_generator);
        if (r < 0)
                return r;
        r = strdup_to(&copy.staging_area, source->staging_area);
        if (r < 0)
                return r;
        r = strv_copy_unless_empty(source->plugins, &copy.plugins);
        if (r < 0)
                return r;
        r = strv_copy_unless_empty(source->argv, &copy.argv);
        if (r < 0)
                return r;
        r = strv_copy_unless_empty(source->envp, &copy.envp);
        if (r < 0)
                return r;

        *ret = copy;
        copy = CONTEXT_NULL;

        return 0;
}

static int context_open_root(Context *c) {
        int r;

        assert(c);
        assert(c->rfd < 0);

        if (isempty(arg_root))
                return 0;

        r = path_is_root(arg_root);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if '%s' is the root directory: %m", arg_root);
        if (r > 0)
                return 0;

        c->rfd = open(empty_to_root(arg_root), O_CLOEXEC | O_DIRECTORY | O_PATH);
        if (c->rfd < 0)
                return log_error_errno(errno, "Failed to open root directory '%s': %m", empty_to_root(arg_root));

        return 0;
}

static const char* context_get_layout(const Context *c) {
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
                return log_warning_errno(r, "Failed to parse machine ID specified via %s, ignoring.", source);

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

        if (s && !filename_is_valid(s))
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

        if (c->rfd >= 0) {
                r = chaseat(c->rfd, s, CHASE_AT_RESOLVE_IN_ROOT, &p, /* ret_fd = */ NULL);
                if (r < 0)
                        return log_warning_errno(r, "Failed to chase path %s for %s specified via %s, ignoring: %m",
                                                 s, name, source);
        } else {
                r = path_make_absolute_cwd(s, &p);
                if (r < 0)
                        return log_warning_errno(r, "Failed to make path '%s' for %s specified via %s absolute, ignoring: %m",
                                                 s, name, source);
        }

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

        if (*dest)
                return 0;

        STRV_FOREACH(s, strv) {
                char *p;

                if (c->rfd >= 0) {
                        r = chaseat(c->rfd, *s, CHASE_AT_RESOLVE_IN_ROOT, &p, /* ret_fd = */ NULL);
                        if (r < 0)
                                return log_warning_errno(r, "Failed to chase path %s for %s specified via %s: %m",
                                                         *s, name, source);
                } else {
                        r = path_make_absolute_cwd(*s, &p);
                        if (r < 0)
                                return log_warning_errno(r, "Failed to make path '%s' for %s specified via %s absolute, ignoring: %m",
                                                         *s, name, source);
                }
                r = strv_consume(&w, p);
                if (r < 0)
                        return log_oom();
        }

        if (strv_isempty(w))
                return 0;

        log_debug("%s set via %s", name, source);

        *dest = TAKE_PTR(w);
        return 1;
}

static int context_set_plugins(Context *c, const char *s, const char *source) {
        _cleanup_strv_free_ char **v = NULL;
        int r;

        assert(c);

        if (c->plugins || !s)
                return 0;

        r = strv_split_full(&v, s, NULL, EXTRACT_UNQUOTE);
        if (r < 0)
                return log_error_errno(r, "Failed to parse plugin paths from %s: %m", source);

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

static int context_load_install_conf(Context *c) {
        _cleanup_free_ char *machine_id = NULL, *boot_root = NULL, *layout = NULL,
                            *initrd_generator = NULL, *uki_generator = NULL;
        int r;

        assert(c);

        r = load_kernel_install_conf(arg_root,
                                     c->conf_root,
                                     &machine_id,
                                     &boot_root,
                                     &layout,
                                     &initrd_generator,
                                     &uki_generator);
        if (r <= 0)
                return r;

        (void) context_set_machine_id(c, machine_id, "config");
        (void) context_set_boot_root(c, boot_root, "config");
        (void) context_set_layout(c, layout, "config");
        (void) context_set_initrd_generator(c, initrd_generator, "config");
        (void) context_set_uki_generator(c, uki_generator, "config");

        log_debug("Loaded config.");
        return 0;
}

static int context_load_machine_info(Context *c) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *machine_id = NULL, *layout = NULL;
        static const char *path = "/etc/machine-info";
        int r;

        assert(c);

        /* If the user configured an explicit machine ID in /etc/machine-info to use for our purpose, we'll
         * use that instead (for compatibility). */

        if (!sd_id128_is_null(c->machine_id) && c->layout >= 0)
                return 0;

        /* For testing. To make not read host's /etc/machine-info. */
        r = getenv_bool("KERNEL_INSTALL_READ_MACHINE_INFO");
        if (r < 0 && r != -ENXIO)
                log_warning_errno(r, "Failed to read $KERNEL_INSTALL_READ_MACHINE_INFO, assuming yes: %m");
        if (r == 0) {
                log_debug("Skipping reading of /etc/machine-info.");
                return 0;
        }

        r = chase_and_fopenat_unlocked(c->rfd, path, CHASE_AT_RESOLVE_IN_ROOT, "re", NULL, &f);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to chase %s: %m", path);

        log_debug("Loading %s…", path);

        r = parse_env_file(f, path,
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
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r))
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to load machine ID from /etc/machine-id: %m");

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
                        /* unprivileged_mode= */ -1,
                        /* ret_path = */ &c->boot_root,
                        /* ret_uuid = */ NULL,
                        /* ret_devid = */ NULL);
        if (r == -ENOKEY) {
                log_debug_errno(r, "Couldn't find an XBOOTLDR partition.");
                return 0;
        }
        if (r == -EACCES && geteuid() != 0)
                return log_error_errno(r, "Failed to determine XBOOTLDR partition: %m");
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
                        /* unprivileged_mode= */ -1,
                        /* ret_path = */ &c->boot_root,
                        /* ret_part = */ NULL,
                        /* ret_pstart = */ NULL,
                        /* ret_psize = */ NULL,
                        /* ret_uuid = */ NULL,
                        /* ret_devid = */ NULL);
        if (r == -ENOKEY) {
                log_debug_errno(r, "Couldn't find EFI system partition, ignoring.");
                return 0;
        }
        if (r == -EACCES && geteuid() != 0)
                return log_error_errno(r, "Failed to determine EFI system partition: %m");
        if (r < 0)
                return r;

        log_debug("Using EFI System Partition at %s as $BOOT_ROOT.", c->boot_root);
        return 1; /* found */
}

static int context_ensure_boot_root(Context *c) {
        int r;

        assert(c);

        /* If BOOT_ROOT is specified via environment or install.conf, then use it. */
        if (c->boot_root)
                return 0;

        /* Otherwise, use XBOOTLDR partition, if mounted. */
        r = context_acquire_xbootldr(c);
        if (r != 0)
                return r;

        /* Otherwise, use EFI system partition, if mounted. */
        r = context_acquire_esp(c);
        if (r != 0)
                return r;

        /* If all else fails, use /boot. */
        if (c->rfd >= 0) {
                r = chaseat(c->rfd, "/boot", CHASE_AT_RESOLVE_IN_ROOT, &c->boot_root, /* ret_fd = */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to chase '/boot': %m");
        } else {
                c->boot_root = strdup("/boot");
                if (!c->boot_root)
                        return log_oom();
        }

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
                        STRV_MAKE_CONST("/etc/kernel/install.d", "/usr/lib/kernel/install.d"));
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

        _cleanup_free_ char *srel_path = path_join(c->boot_root, "loader/entries.srel");
        if (!srel_path)
                return log_oom();

        _cleanup_free_ char *srel = NULL;
        r = read_one_line_file_at(c->rfd, srel_path, &srel);
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

                log_debug("%s with '%s' found, using layout=%s.", srel_path, srel, layout_to_string(c->layout));
                return 0;
        } else if (r != -ENOENT)
                return log_error_errno(r, "Failed to read %s: %m", srel_path);

        _cleanup_free_ char *entry_token_path = path_join(c->boot_root, c->entry_token);
        if (!entry_token_path)
                return log_oom();

        r = is_dir_at(c->rfd, entry_token_path, /* follow = */ false);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to check if '%s' is a directory: %m", entry_token_path);
        if (r > 0) {
                /* If the metadata in $BOOT_ROOT doesn't tell us anything, then check if the entry token
                 * directory already exists. If so, let's assume it's the standard boot loader spec, too. */
                c->layout = LAYOUT_BLS;
                log_debug("%s exists, using layout=%s.", entry_token_path, layout_to_string(c->layout));
                return 0;
        }

        /* There's no metadata in $BOOT_ROOT, and apparently no entry token directory installed? Then we
         * really don't know anything. */
        c->layout = LAYOUT_OTHER;
        log_debug("Entry-token directory not found, using layout=%s.", layout_to_string(c->layout));
        return 0;
}

static int context_set_up_staging_area(Context *c) {
        static const char *template = "/tmp/kernel-install.staging.XXXXXX";
        int r;

        assert(c);

        if (c->staging_area)
                return 0;

        if (c->action == ACTION_INSPECT) {
                /* This is only used for display. The directory will not be created. */
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

        c->entry_dir = path_join(c->boot_root, c->entry_token, c->version ?: "KERNEL_VERSION");
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
        fd = chase_and_openat(c->rfd, c->entry_dir, CHASE_AT_RESOLVE_IN_ROOT | CHASE_MKDIR_0755,
                              O_CLOEXEC | O_CREAT | O_DIRECTORY | O_PATH, NULL);
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
                verb = "add|remove";
                break;

        default:
                assert_not_reached();
        }

        a = strv_new("dummy-arg", /* to make strv_free() works for this variable. */
                     verb,
                     c->version ?: "KERNEL_VERSION",
                     c->entry_dir);
        if (!a)
                return log_oom();

        if (c->action == ACTION_ADD) {
                r = strv_extend(&a, c->kernel);
                if (r < 0)
                        return log_oom();

                r = strv_extend_strv(&a, c->initrds, /* filter_duplicates = */ false);
                if (r < 0)
                        return log_oom();

        } else if (c->action == ACTION_INSPECT) {
                r = strv_extend_many(
                                &a,
                                c->kernel ?: "[KERNEL_IMAGE]",
                                "[INITRD...]");
                if (r < 0)
                        return log_oom();
        }

        c->argv = TAKE_PTR(a);
        return 0;
}

static int context_build_environment(Context *c) {
        _cleanup_strv_free_ char **e = NULL;
        int r;

        assert(c);

        if (c->envp)
                return 0;

        r = strv_env_assign_many(&e,
                                 "LC_COLLATE",                      SYSTEMD_DEFAULT_LOCALE,
                                 "KERNEL_INSTALL_VERBOSE",          one_zero(arg_verbose),
                                 "KERNEL_INSTALL_IMAGE_TYPE",       kernel_image_type_to_string(c->kernel_image_type),
                                 "KERNEL_INSTALL_MACHINE_ID",       SD_ID128_TO_STRING(c->machine_id),
                                 "KERNEL_INSTALL_ENTRY_TOKEN",      c->entry_token,
                                 "KERNEL_INSTALL_BOOT_ROOT",        c->boot_root,
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

        r = context_set_up_staging_area(c);
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
        int r, ret;

        assert(c);

        r = context_make_entry_dir(c);
        if (r < 0)
                return r;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *x = strv_join_full(c->plugins, "", "\n  ", /* escape_separator = */ false);
                log_debug("Using plugins: %s", strna(x));

                _cleanup_free_ char *y = strv_join_full(c->envp, "", "\n  ", /* escape_separator = */ false);
                log_debug("Plugin environment: %s", strna(y));

                _cleanup_free_ char *z = strv_join(strv_skip(c->argv, 1), " ");
                log_debug("Plugin arguments: %s", strna(z));
        }

        ret = execute_strv(
                        /* name = */ NULL,
                        c->plugins,
                        /* root = */ NULL,
                        USEC_INFINITY,
                        /* callbacks = */ NULL,
                        /* callback_args = */ NULL,
                        c->argv,
                        c->envp,
                        EXEC_DIR_SKIP_REMAINING);

        r = context_remove_entry_dir(c);
        if (r < 0)
                return r;

        /* This returns 0 on success, positive exit code on plugin failure, negative errno on other failures. */
        return ret;
}

static bool bypass(void) {
        int r;

        r = getenv_bool("KERNEL_INSTALL_BYPASS");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $KERNEL_INSTALL_BYPASS, assuming no.");
        if (r <= 0)
                return false;

        log_debug("$KERNEL_INSTALL_BYPASS is enabled, skipping execution.");
        return true;
}

static int do_add(
                Context *c,
                const char *version,
                const char *kernel,
                char **initrds) {

        int r;

        assert(c);
        assert(version);
        assert(kernel);

        r = context_set_version(c, version);
        if (r < 0)
                return r;

        r = context_set_kernel(c, kernel);
        if (r < 0)
                return r;

        r = context_set_initrds(c, initrds);
        if (r < 0)
                return r;

        r = context_prepare_execution(c);
        if (r < 0)
                return r;

        return context_execute(c);
}

static int kernel_from_version(const char *version, char **ret_kernel) {
        _cleanup_free_ char *vmlinuz = NULL;
        int r;

        assert(version);

        vmlinuz = path_join("/usr/lib/modules/", version, "/vmlinuz");
        if (!vmlinuz)
                return log_oom();

        r = access_nofollow(vmlinuz, F_OK);
        if (r == -ENOENT)
                return log_error_errno(r, "Kernel image not installed to '%s', requiring manual kernel image path specification.", vmlinuz);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if kernel image is installed to '%s': %m", vmlinuz);

        *ret_kernel = TAKE_PTR(vmlinuz);
        return 0;
}

static int verb_add(int argc, char *argv[], void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        _cleanup_free_ char *vmlinuz = NULL;
        const char *version, *kernel;
        char **initrds;
        struct utsname un;
        int r;

        assert(argv);

        if (arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "'add' does not support --root= or --image=.");

        if (bypass())
                return 0;

        c->action = ACTION_ADD;

        /* We use the same order of arguments that "inspect" introduced, i.e. if only on argument is
         * specified we take it as the kernel path, not the version, i.e. it's the first argument that is
         * optional, not the 2nd. */
        version = argc > 2 ? empty_or_dash_to_null(argv[1]) : NULL;
        kernel = argc > 2 ? empty_or_dash_to_null(argv[2]) :
                (argc > 1 ? empty_or_dash_to_null(argv[1]) : NULL);
        initrds = strv_skip(argv, 3);

        if (!version) {
                assert_se(uname(&un) >= 0);
                version = un.release;
        }

        if (!kernel) {
                r = kernel_from_version(version, &vmlinuz);
                if (r < 0)
                        return r;

                kernel = vmlinuz;
        }

        return do_add(c, version, kernel, initrds);
}

static int verb_add_all(int argc, char *argv[], void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        _cleanup_close_ int fd = -EBADF;
        size_t n = 0;
        int ret = 0, r;

        assert(argv);

        if (arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "'add-all' does not support --root= or --image=.");

        if (bypass())
                return 0;

        c->action = ACTION_ADD;

        fd = chase_and_openat(c->rfd, "/usr/lib/modules", CHASE_AT_RESOLVE_IN_ROOT, O_DIRECTORY|O_RDONLY|O_CLOEXEC, NULL);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open %s/usr/lib/modules/: %m", strempty(arg_root));

        _cleanup_free_ DirectoryEntries *de = NULL;
        r = readdir_all(fd, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT, &de);
        if (r < 0)
                return log_error_errno(r, "Failed to numerate /usr/lib/modules/ contents: %m");

        FOREACH_ARRAY(d, de->entries, de->n_entries) {
                r = dirent_ensure_type(fd, *d);
                if (r < 0) {
                        if (r != -ENOENT) /* don't log if just gone by now */
                                log_debug_errno(r, "Failed to check if '%s/usr/lib/modules/%s' is a directory, ignoring: %m", strempty(arg_root), (*d)->d_name);
                        continue;
                }

                if ((*d)->d_type != DT_DIR)
                        continue;

                _cleanup_free_ char *fn = path_join((*d)->d_name, "vmlinuz");
                if (!fn)
                        return log_oom();

                if (faccessat(fd, fn, F_OK, AT_SYMLINK_NOFOLLOW) < 0) {
                        if (errno != ENOENT)
                                log_debug_errno(errno, "Failed to check if '%s/usr/lib/modules/%s/vmlinuz' exists, ignoring: %m", strempty(arg_root), (*d)->d_name);

                        log_notice("Not adding version '%s', because kernel image not found.", (*d)->d_name);
                        continue;
                }

                _cleanup_(context_done) Context copy = CONTEXT_NULL;

                r = context_copy(c, &copy);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy execution context: %m");

                /* do_add() will look up the path in the correct root directory so we don't need to prefix it
                 * with arg_root here. */
                _cleanup_free_ char *full = path_join("/usr/lib/modules/", fn);
                if (!full)
                        return log_oom();

                r = do_add(&copy,
                           /* version= */ (*d)->d_name,
                           /* kernel= */ full,
                           /* initrds= */ NULL);
                if (r == 0)
                        n++;
                else if (ret == 0)
                        ret = r;
        }

        if (n > 0)
                log_debug("Installed %zu kernel(s).", n);
        else if (ret == 0)
                ret = log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No kernels to install found.");

        return ret;
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

        assert(argc >= 2);
        assert(argv);

        if (arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "'remove' does not support --root= or --image=.");

        if (argc > 2)
                log_debug("Too many arguments specified. 'kernel-install remove' takes only kernel version. "
                          "Ignoring residual arguments.");

        if (bypass())
                return 0;

        c->action = ACTION_REMOVE;

        /* Note, we do not automatically derive the kernel version to remove from uname() here (unlike we do
         * it for the "add" verb), since we don't want to make it too easy to uninstall your running
         * kernel, as a safety precaution */

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
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_free_ char *vmlinuz = NULL;
        const char *version, *kernel;
        char **initrds;
        struct utsname un;
        int r;

        c->action = ACTION_INSPECT;

        /* When only a single parameter is specified 'inspect' it's the kernel image path, and not the kernel
         * version. i.e. it's the first argument that is optional, not the 2nd. That's a bit unfortunate, but
         * we keep the behaviour for compatibility. If users want to specify only the version (and have the
         * kernel image path derived automatically), then they may specify an empty string or "dash" as
         * kernel image path. */
        version = argc > 2 ? empty_or_dash_to_null(argv[1]) : NULL;
        kernel = argc > 2 ? empty_or_dash_to_null(argv[2]) :
                (argc > 1 ? empty_or_dash_to_null(argv[1]) : NULL);
        initrds = strv_skip(argv, 3);

        if (!version && !arg_root) {
                assert_se(uname(&un) >= 0);
                version = un.release;
        }

        if (!kernel && version) {
                r = kernel_from_version(version, &vmlinuz);
                if (r < 0)
                        return r;

                kernel = vmlinuz;
        }

        r = context_set_version(c, version);
        if (r < 0)
                return r;

        r = context_set_kernel(c, kernel);
        if (r < 0)
                return r;

        r = context_set_initrds(c, initrds);
        if (r < 0)
                return r;

        r = context_prepare_execution(c);
        if (r < 0)
                return r;

        t = table_new_vertical();
        if (!t)
                return log_oom();

        r = table_add_many(t,
                           TABLE_FIELD, "Machine ID",
                           TABLE_ID128, c->machine_id,
                           TABLE_FIELD, "Kernel Image Type",
                           TABLE_STRING, kernel_image_type_to_string(c->kernel_image_type),
                           TABLE_FIELD, "Layout",
                           TABLE_STRING, context_get_layout(c),
                           TABLE_FIELD, "Boot Root",
                           TABLE_STRING, c->boot_root,
                           TABLE_FIELD, "Entry Token Type",
                           TABLE_STRING, boot_entry_token_type_to_string(c->entry_token_type),
                           TABLE_FIELD, "Entry Token",
                           TABLE_STRING, c->entry_token,
                           TABLE_FIELD, "Entry Directory",
                           TABLE_STRING, c->entry_dir,
                           TABLE_FIELD, "Kernel Version",
                           TABLE_STRING, c->version,
                           TABLE_FIELD, "Kernel",
                           TABLE_STRING, c->kernel,
                           TABLE_FIELD, "Initrds",
                           TABLE_STRV, c->initrds,
                           TABLE_FIELD, "Initrd Generator",
                           TABLE_STRING, c->initrd_generator,
                           TABLE_FIELD, "UKI Generator",
                           TABLE_STRING, c->uki_generator,
                           TABLE_FIELD, "Plugins",
                           TABLE_STRV, c->plugins,
                           TABLE_FIELD, "Plugin Environment",
                           TABLE_STRV, c->envp);
        if (r < 0)
                return table_log_add_error(r);

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                r = table_add_many(t,
                                   TABLE_FIELD, "Plugin Arguments",
                                   TABLE_STRV, strv_skip(c->argv, 1));
                if (r < 0)
                        return table_log_add_error(r);
        }

        table_set_ersatz_string(t, TABLE_ERSATZ_UNSET);

        for (size_t row = 1; row < table_get_rows(t); row++) {
                _cleanup_free_ char *name = NULL;

                name = strdup(table_get_at(t, row, 0));
                if (!name)
                        return log_oom();

                r = table_set_json_field_name(t, row - 1, delete_chars(name, " "));
                if (r < 0)
                        return log_error_errno(r, "Failed to set JSON field name: %m");
        }

        return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, /* show_header= */ false);
}

static int verb_list(int argc, char *argv[], void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        _cleanup_close_ int fd = -EBADF;
        int r;

        fd = chase_and_openat(c->rfd, "/usr/lib/modules", CHASE_AT_RESOLVE_IN_ROOT, O_DIRECTORY|O_RDONLY|O_CLOEXEC, NULL);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open %s/usr/lib/modules/: %m", strempty(arg_root));

        _cleanup_free_ DirectoryEntries *de = NULL;
        r = readdir_all(fd, RECURSE_DIR_SORT|RECURSE_DIR_IGNORE_DOT, &de);
        if (r < 0)
                return log_error_errno(r, "Failed to numerate /usr/lib/modules/ contents: %m");

        _cleanup_(table_unrefp) Table *table = NULL;
        table = table_new("version", "has kernel", "path");
        if (!table)
                return log_oom();

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);
        table_set_align_percent(table, table_get_cell(table, 0, 1), 100);

        FOREACH_ARRAY(d, de->entries, de->n_entries) {
                _cleanup_free_ char *j = path_join("/usr/lib/modules/", (*d)->d_name);
                if (!j)
                        return log_oom();

                r = dirent_ensure_type(fd, *d);
                if (r < 0) {
                        if (r != -ENOENT) /* don't log if just gone by now */
                                log_debug_errno(r, "Failed to check if '%s/%s' is a directory, ignoring: %m", strempty(arg_root), j);
                        continue;
                }

                if ((*d)->d_type != DT_DIR)
                        continue;

                _cleanup_free_ char *fn = path_join((*d)->d_name, "vmlinuz");
                if (!fn)
                        return log_oom();

                bool exists;
                if (faccessat(fd, fn, F_OK, AT_SYMLINK_NOFOLLOW) < 0) {
                        if (errno != ENOENT)
                                log_debug_errno(errno, "Failed to check if '%s/usr/lib/modules/%s/vmlinuz' exists, ignoring: %m", strempty(arg_root), (*d)->d_name);

                        exists = false;
                } else
                        exists = true;

                r = table_add_many(table,
                                   TABLE_STRING, (*d)->d_name,
                                   TABLE_BOOLEAN_CHECKMARK, exists,
                                   TABLE_SET_COLOR, ansi_highlight_green_red(exists),
                                   TABLE_PATH, j);
                if (r < 0)
                        return table_log_add_error(r);
        }

        return table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("kernel-install", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND ...\n\n"
               "%5$sAdd and remove kernel and initrd images to and from the boot partition.%6$s\n"
               "\n%3$sUsage:%4$s\n"
               "  kernel-install [OPTIONS...] add [[[KERNEL-VERSION] KERNEL-IMAGE] [INITRD ...]]\n"
               "  kernel-install [OPTIONS...] add-all\n"
               "  kernel-install [OPTIONS...] remove KERNEL-VERSION\n"
               "  kernel-install [OPTIONS...] inspect [[[KERNEL-VERSION] KERNEL-IMAGE]\n"
               "                                      [INITRD ...]]\n"
               "  kernel-install [OPTIONS...] list\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help                    Show this help\n"
               "     --version                 Show package version\n"
               "  -v --verbose                 Increase verbosity\n"
               "     --esp-path=PATH           Path to the EFI System Partition (ESP)\n"
               "     --boot-path=PATH          Path to the $BOOT partition\n"
               "     --make-entry-directory=yes|no|auto\n"
               "                               Create $BOOT/ENTRY-TOKEN/ directory\n"
               "     --entry-token=machine-id|os-id|os-image-id|auto|literal:…\n"
               "                               Entry token to use for this installation\n"
               "     --no-pager                Do not pipe inspect output into a pager\n"
               "     --json=pretty|short|off   Generate JSON output\n"
               "     --no-legend               Do not show the headers and footers\n"
               "     --root=PATH               Operate on an alternate filesystem root\n"
               "     --image=PATH              Operate on disk image as filesystem root\n"
               "     --image-policy=POLICY     Specify disk image dissection policy\n"
               "\n"
               "This program may also be invoked as 'installkernel':\n"
               "  installkernel  [OPTIONS...] VERSION VMLINUZ [MAP] [INSTALLATION-DIR]\n"
               "(The optional arguments are passed by kernel build system, but ignored.)\n"
               "\n"
               "See the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[], Context *c) {
        enum {
                ARG_VERSION = 0x100,
                ARG_NO_LEGEND,
                ARG_ESP_PATH,
                ARG_BOOT_PATH,
                ARG_MAKE_ENTRY_DIRECTORY,
                ARG_ENTRY_TOKEN,
                ARG_NO_PAGER,
                ARG_JSON,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_IMAGE_POLICY,
        };
        static const struct option options[] = {
                { "help",                 no_argument,       NULL, 'h'                      },
                { "version",              no_argument,       NULL, ARG_VERSION              },
                { "verbose",              no_argument,       NULL, 'v'                      },
                { "esp-path",             required_argument, NULL, ARG_ESP_PATH             },
                { "boot-path",            required_argument, NULL, ARG_BOOT_PATH            },
                { "make-entry-directory", required_argument, NULL, ARG_MAKE_ENTRY_DIRECTORY },
                { "entry-token",          required_argument, NULL, ARG_ENTRY_TOKEN          },
                { "no-pager",             no_argument,       NULL, ARG_NO_PAGER             },
                { "json",                 required_argument, NULL, ARG_JSON                 },
                { "root",                 required_argument, NULL, ARG_ROOT                 },
                { "image",                required_argument, NULL, ARG_IMAGE                },
                { "image-policy",         required_argument, NULL, ARG_IMAGE_POLICY         },
                { "no-legend",            no_argument,       NULL, ARG_NO_LEGEND            },
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

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

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

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r < 0)
                                return r;
                        break;

                case ARG_ROOT:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_root);
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

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_image && arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        return 1;
}

static int run(int argc, char* argv[]) {
        static const Verb verbs[] = {
                { "add",         1,        VERB_ANY, 0,            verb_add            },
                { "add-all",     1,        1,        0,            verb_add_all        },
                { "remove",      2,        VERB_ANY, 0,            verb_remove         },
                { "inspect",     1,        VERB_ANY, VERB_DEFAULT, verb_inspect        },
                { "list",        1,        1,        0,            verb_list           },
                {}
        };
        _cleanup_(context_done) Context c = {
                .rfd = AT_FDCWD,
                .action = _ACTION_INVALID,
                .kernel_image_type = KERNEL_IMAGE_TYPE_UNKNOWN,
                .layout = _LAYOUT_INVALID,
                .entry_token_type = BOOT_ENTRY_TOKEN_AUTO,
        };
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        int r;

        log_setup();

        r = parse_argv(argc, argv, &c);
        if (r <= 0)
                return r;

        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                arg_image_policy,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_VALIDATE_OS |
                                DISSECT_IMAGE_ALLOW_USERSPACE_VERITY,
                                &mounted_dir,
                                /* ret_dir_fd= */ NULL,
                                &loop_device);
                if (r < 0)
                        return r;

                arg_root = strdup(mounted_dir);
                if (!arg_root)
                        return log_oom();
        }

        r = context_init(&c);
        if (r < 0)
                return r;

        if (invoked_as(argv, "installkernel"))
                return run_as_installkernel(argc, argv, &c);

        return dispatch_verb(argc, argv, verbs, &c);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
