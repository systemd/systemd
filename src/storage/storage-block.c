/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>

#include "sd-device.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "blockdev-list.h"
#include "build.h"
#include "bus-polkit.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "hashmap.h"
#include "help-util.h"
#include "json-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "path-util.h"
#include "storage-util.h"
#include "strv.h"
#include "varlink-io.systemd.StorageProvider.h"
#include "varlink-util.h"

static int block_device_pick_name(
                const BlockDevice *d,
                const char **ret_name,
                char ***ret_aliases) {

        int r;

        assert(d);
        assert(d->node);
        assert(ret_name);
        assert(ret_aliases);

        static const char *const prefixes[] = {
                /* The list of preferred prefixes, in order of preference. Note: for security reasons we only
                 * use identifiers that do not depend on the *contents* of the device, i.e. we restrict
                 * ourselves to IDs whose fields are either chosen by whoever created the kernel device or are
                 * hardware properties, but not names generated from superblock metainformation or similar. */
                "/dev/mapper",
                "/dev/disk/by-loop-ref",
                "/dev/disk/by-id",
                "/dev/disk/by-path",
        };

        const char* found[ELEMENTSOF(prefixes)] = {};
        _cleanup_strv_free_ char **aliases = NULL;
        size_t best = SIZE_MAX;
        STRV_FOREACH(sl, d->symlinks) {
                bool matched = false;
                for (size_t i = 0; i < ELEMENTSOF(prefixes); i++) {
                        if (!path_startswith(*sl, prefixes[i]))
                                continue;

                        if (found[i]) {
                                /* Two symlinks with the same prefix? Then keep the lower one. */
                                if (path_compare(*sl, found[i]) > 0)
                                        continue;

                                r = strv_extend(&aliases, found[i]);
                                if (r < 0)
                                        return r;
                        }

                        found[i] = *sl;
                        if (i < best)
                                best = i;
                        matched = true;
                }

                if (!matched) {
                        r = strv_extend(&aliases, *sl);
                        if (r < 0)
                                return r;
                }
        }

        if (best == SIZE_MAX) /* No preferred prefix found, use the kernel device name */
                *ret_name = d->node;
        else {
                /* We found a preferred prefix, add the kernel device name to the aliases then. */
                r = strv_extend(&aliases, d->node);
                if (r < 0)
                        return r;

                /* If there are any less preferred prefixes also add them to the aliases array */
                for (size_t i = best + 1; i < ELEMENTSOF(prefixes); i++) {
                        if (!found[i])
                                continue;

                        r = strv_extend(&aliases, found[i]);
                        if (r < 0)
                                return r;
                }

                *ret_name = found[best];
        }

        strv_sort(aliases);
        *ret_aliases = TAKE_PTR(aliases);

        return 0;
}

static bool block_device_match(const BlockDevice *d, const char *match) {
        assert(d);
        assert(d->node);

        if (!match)
                return true;

        if (fnmatch(match, d->node, FNM_NOESCAPE) == 0)
                return true;

        STRV_FOREACH(sl, d->symlinks)
                if (fnmatch(match, *sl, FNM_NOESCAPE) == 0)
                        return true;

        return false;
}

static int vl_method_list_volumes(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        int r;

        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        struct {
                const char *match_name;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "matchName", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, match_name), 0 },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        BlockDevice *l = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(l, n, block_device_array_free);

        r = blockdev_list(
                        BLOCKDEV_LIST_SHOW_SYMLINKS|
                        BLOCKDEV_LIST_IGNORE_ROOT|
                        BLOCKDEV_LIST_IGNORE_EMPTY|
                        BLOCKDEV_LIST_METADATA,
                        &l,
                        &n);
        if (r < 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.StorageProvider.NoSuchVolume");
        if (r < 0)
                return r;

        FOREACH_ARRAY(d, l, n) {
                const char *name = NULL;
                _cleanup_strv_free_ char **aliases = NULL;

                if (!block_device_match(d, p.match_name))
                        continue;

                r = block_device_pick_name(d, &name, &aliases);
                if (r < 0)
                        return r;

                r = sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("name", name),
                                JSON_BUILD_PAIR_STRV_NON_EMPTY("aliases", aliases),
                                SD_JSON_BUILD_PAIR_STRING("type", "blk"),
                                SD_JSON_BUILD_PAIR_CONDITION(d->read_only >= 0, "readOnly", SD_JSON_BUILD_BOOLEAN(d->read_only)),
                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("sizeBytes", d->size, UINT64_MAX));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int vl_method_list_templates(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        /* This storage provider does not support templates */
        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        return sd_varlink_error(link, "io.systemd.StorageProvider.NoSuchTemplate", NULL);
}

static int device_open_disk_auto_rw(sd_device *d, int *read_only) {
        assert(d);
        assert(read_only);

        int fd = sd_device_open(d, *read_only > 0 ? O_RDONLY : O_RDWR);
        if (fd < 0) {
                if (!ERRNO_IS_NEG_FS_WRITE_REFUSED(fd) || *read_only >= 0)
                        return log_device_debug_errno(d, fd, "Failed to open device in %s mode: %m", *read_only > 0 ? "read-only" : "read-write");

                /* Try again in read-only mode */
                fd = sd_device_open(d, O_RDONLY);
                if (fd < 0)
                        return log_device_debug_errno(d, fd, "Failed to open device in read-only mode, too: %m");

                *read_only = true;
        } else
                *read_only = *read_only > 0;

        return fd;
}

static int vl_method_acquire(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        Hashmap **polkit_registry = ASSERT_PTR(userdata);
        int r;

        assert(link);

        struct {
                const char *name;
                CreateMode create_mode;
                const char *template;
                int read_only;
                VolumeType request_as;
                uint64_t create_size;
        } p = {
                .create_mode = CREATE_ANY,
                .read_only = -1,
                .request_as = _VOLUME_TYPE_INVALID,
                .create_size = UINT64_MAX, /* never actually used here, just validated; we don't allow creation of block devices here */
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",            SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, name),        SD_JSON_MANDATORY },
                { "createMode",      SD_JSON_VARIANT_STRING,        json_dispatch_create_mode,     voffsetof(p, create_mode), 0                 },
                { "template",        SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, template),    0                 },
                { "readOnly",        SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,     voffsetof(p, read_only),   0                 },
                { "requestAs",       SD_JSON_VARIANT_STRING,        json_dispatch_volume_type,     voffsetof(p, request_as),  0                 },
                { "createSizeBytes", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       voffsetof(p, create_size), 0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!storage_volume_name_is_valid(p.name))
                return sd_varlink_error_invalid_parameter_name(link, "name");
        if (!path_startswith(p.name, "/dev") || !path_is_normalized(p.name))
                return sd_varlink_error(link, "io.systemd.StorageProvider.NoSuchVolume", NULL);

        if (!IN_SET(p.create_mode, CREATE_ANY, CREATE_OPEN))
                return sd_varlink_error(link, "io.systemd.StorageProvider.CreateNotSupported", NULL);

        /* off_t is signed, hence refuse overly long requests */
        if (p.create_size != UINT64_MAX && p.create_size > INT64_MAX)
                return sd_varlink_error_invalid_parameter_name(link, "createSizeBytes");

        if (!isempty(p.template)) {
                if (!storage_template_name_is_valid(p.template))
                        return sd_varlink_error_invalid_parameter_name(link, "template");

                return sd_varlink_error(link, "io.systemd.StorageProvider.NoSuchTemplate", NULL);
        }

        if (p.request_as >= 0 && p.request_as != VOLUME_BLK)
                return sd_varlink_error(link, "io.systemd.StorageProvider.TypeNotSupported", NULL);

        const char *details[] = {
                "name", p.name,
                NULL
        };

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.storage.block.acquire",
                        details,
                        polkit_registry);
        if (r <= 0)
                return r;

        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        r = sd_device_new_from_devname(&d, p.name);
        if (ERRNO_IS_NEG_DEVICE_ABSENT(r))
                return sd_varlink_error(link, "io.systemd.StorageProvider.NoSuchVolume", NULL);
        if (r < 0)
                return r;

        if (!device_in_subsystem(d, "block"))
                return sd_varlink_error(link, "io.systemd.StorageProvider.NoSuchVolume", NULL);

        /* The error returns are sometimes a bit inconclusive (i.e. read-only media might appear as
         * inaccessible due to a permission issue), hence let's do an explicit check first, to give good
         * answers */
        if (p.read_only <= 0) {
                r = device_get_sysattr_bool(d, "ro");
                if (r < 0)
                        log_device_debug_errno(d, r, "Failed to acquire read-only flag of device '%s', ignoring: %m", p.name);
                else if (r > 0) {
                        if (p.read_only == 0)
                                return sd_varlink_error(link, "io.systemd.StorageProvider.ReadOnlyVolume", NULL);

                        p.read_only = true;
                }
        }

        _cleanup_close_ int fd = device_open_disk_auto_rw(d, &p.read_only);
        if (ERRNO_IS_NEG_FS_WRITE_REFUSED(fd))
                return sd_varlink_error(link, "io.systemd.StorageProvider.ReadOnlyVolume", NULL);
        if (fd < 0)
                return fd;

        assert(p.read_only >= 0); /* flag is now definitely initialized to either true or false, not negative anymore */

        int idx = sd_varlink_push_fd(link, fd);
        if (idx < 0)
                return idx;

        TAKE_FD(fd);

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_INTEGER("fileDescriptorIndex", idx),
                        SD_JSON_BUILD_PAIR_STRING("type", "blk"),
                        SD_JSON_BUILD_PAIR_BOOLEAN("readOnly", p.read_only));
}

static int vl_server(void) {
        int r;

        _cleanup_(hashmap_freep) Hashmap *polkit_registry = NULL;
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_HANDLE_SIGINT|
                        SD_VARLINK_SERVER_HANDLE_SIGTERM|
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT|
                        SD_VARLINK_SERVER_INHERIT_USERDATA,
                        &polkit_registry);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_StorageProvider);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.StorageProvider.Acquire", vl_method_acquire,
                        "io.systemd.StorageProvider.ListVolumes", vl_method_list_volumes,
                        "io.systemd.StorageProvider.ListTemplates", vl_method_list_templates);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int help(void) {
        int r;

        help_cmdline("[OPTIONS...]");
        help_abstract("Simple block device backed storage provider");

        _cleanup_(table_unrefp) Table *options = NULL;
        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        help_section("Options:");

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("systemd-storage-block", "8");
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };
        FOREACH_OPTION(c, &opts, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();
                }

        if (option_parser_get_n_args(&opts) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        return 1;
}

static int run(int argc, char* argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return vl_server();
}

DEFINE_MAIN_FUNCTION(run);
