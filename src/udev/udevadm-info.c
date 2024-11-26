/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "device-enumerator-private.h"
#include "device-private.h"
#include "device-util.h"
#include "devnum-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "glyph-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "sort-util.h"
#include "static-destruct.h"
#include "string-table.h"
#include "string-util.h"
#include "terminal-util.h"
#include "udev-util.h"
#include "udevadm.h"
#include "udevadm-util.h"

typedef enum ActionType {
        ACTION_QUERY,
        ACTION_ATTRIBUTE_WALK,
        ACTION_DEVICE_ID_FILE,
        ACTION_TREE,
        ACTION_EXPORT,
} ActionType;

typedef enum QueryType {
        QUERY_NAME,
        QUERY_PATH,
        QUERY_SYMLINK,
        QUERY_PROPERTY,
        QUERY_ALL,
} QueryType;

static char **arg_properties = NULL;
static bool arg_root = false;
static bool arg_export = false;
static bool arg_value = false;
static const char *arg_export_prefix = NULL;
static usec_t arg_wait_for_initialization_timeout = 0;
PagerFlags arg_pager_flags = 0;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;

/* Put a limit on --tree descent level to not exhaust our stack */
#define TREE_DEPTH_MAX 64

static bool skip_attribute(const char *name) {
        assert(name);

        /* Those are either displayed separately or should not be shown at all. */
        return STR_IN_SET(name,
                          "uevent",
                          "dev",
                          "modalias",
                          "resource",
                          "driver",
                          "subsystem",
                          "module");
}

typedef struct SysAttr {
        const char *name;
        const char *value;
} SysAttr;

STATIC_DESTRUCTOR_REGISTER(arg_properties, strv_freep);

static int sysattr_compare(const SysAttr *a, const SysAttr *b) {
        assert(a);
        assert(b);

        return strcmp(a->name, b->name);
}

static int print_all_attributes(sd_device *device, bool is_parent) {
        _cleanup_free_ SysAttr *sysattrs = NULL;
        const char *value;
        size_t n_items = 0;
        int r;

        assert(device);

        if (is_parent)
                puts("");

        value = NULL;
        (void) sd_device_get_devpath(device, &value);
        printf("  looking at %sdevice '%s':\n", is_parent ? "parent " : "", strempty(value));

        value = NULL;
        (void) sd_device_get_sysname(device, &value);
        printf("    %s==\"%s\"\n", is_parent ? "KERNELS" : "KERNEL", strempty(value));

        value = NULL;
        (void) sd_device_get_subsystem(device, &value);
        printf("    %s==\"%s\"\n", is_parent ? "SUBSYSTEMS" : "SUBSYSTEM", strempty(value));

        value = NULL;
        (void) sd_device_get_driver(device, &value);
        printf("    %s==\"%s\"\n", is_parent ? "DRIVERS" : "DRIVER", strempty(value));

        FOREACH_DEVICE_SYSATTR(device, name) {
                size_t len;

                if (skip_attribute(name))
                        continue;

                r = sd_device_get_sysattr_value(device, name, &value);
                if (r >= 0) {
                        /* skip any values that look like a path */
                        if (value[0] == '/')
                                continue;

                        /* skip nonprintable attributes */
                        len = strlen(value);
                        while (len > 0 && isprint((unsigned char) value[len-1]))
                                len--;
                        if (len > 0)
                                continue;

                } else if (ERRNO_IS_PRIVILEGE(r))
                        value = "(not readable)";
                else
                        continue;

                if (!GREEDY_REALLOC(sysattrs, n_items + 1))
                        return log_oom();

                sysattrs[n_items] = (SysAttr) {
                        .name = name,
                        .value = value,
                };
                n_items++;
        }

        typesafe_qsort(sysattrs, n_items, sysattr_compare);

        FOREACH_ARRAY(i, sysattrs, n_items)
                printf("    %s{%s}==\"%s\"\n", is_parent ? "ATTRS" : "ATTR", i->name, i->value);

        return 0;
}

static int print_device_chain(sd_device *device) {
        sd_device *child, *parent;
        int r;

        assert(device);

        printf("\n"
               "Udevadm info starts with the device specified by the devpath and then\n"
               "walks up the chain of parent devices. It prints for every device\n"
               "found, all possible attributes in the udev rules key format.\n"
               "A rule to match, can be composed by the attributes of the device\n"
               "and the attributes from one single parent device.\n"
               "\n");

        r = print_all_attributes(device, /* is_parent = */ false);
        if (r < 0)
                return r;

        for (child = device; sd_device_get_parent(child, &parent) >= 0; child = parent) {
                r = print_all_attributes(parent, /* is_parent = */ true);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int print_all_attributes_in_json(sd_device *device, bool is_parent) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;
        _cleanup_free_ SysAttr *sysattrs = NULL;
        const char *value;
        size_t n_items = 0;
        int r;

        assert(device);

        value = NULL;
        (void) sd_device_get_devpath(device, &value);
        r = sd_json_variant_set_field_string(&v, "DEVPATH", value);
        if (r < 0)
                return r;

        value = NULL;
        (void) sd_device_get_sysname(device, &value);
        r = sd_json_variant_set_field_string(&v, is_parent ? "KERNELS" : "KERNEL", value);
        if (r < 0)
                return r;

        value = NULL;
        (void) sd_device_get_subsystem(device, &value);
        r = sd_json_variant_set_field_string(&v, is_parent ? "SUBSYSTEMS" : "SUBSYSTEM", value);
        if (r < 0)
                return r;

        value = NULL;
        (void) sd_device_get_driver(device, &value);
        r = sd_json_variant_set_field_string(&v, is_parent ? "DRIVERS" : "DRIVER", value);
        if (r < 0)
                return r;

        FOREACH_DEVICE_SYSATTR(device, name) {
                size_t len;

                if (skip_attribute(name))
                        continue;

                r = sd_device_get_sysattr_value(device, name, &value);
                if (r >= 0) {
                        /* skip any values that look like a path */
                        if (value[0] == '/')
                                continue;

                        /* skip nonprintable attributes */
                        len = strlen(value);
                        while (len > 0 && isprint((unsigned char) value[len-1]))
                                len--;
                        if (len > 0)
                                continue;

                } else if (ERRNO_IS_PRIVILEGE(r))
                        value = "(not readable)";
                else
                        continue;

                if (!GREEDY_REALLOC(sysattrs, n_items + 1))
                        return log_oom();

                sysattrs[n_items] = (SysAttr) {
                        .name = name,
                        .value = value,
                };
                n_items++;
        }

        typesafe_qsort(sysattrs, n_items, sysattr_compare);

        FOREACH_ARRAY(i, sysattrs, n_items) {
                r = sd_json_variant_set_field_string(&w, i->name, i->value);
                if (r < 0)
                        return r;
        }

        r = sd_json_variant_set_field(&v, is_parent ? "ATTRS" : "ATTR", w);
        if (r < 0)
                return r;

        return sd_json_variant_dump(v, arg_json_format_flags, stdout, NULL);
}

static int print_device_chain_in_json(sd_device *device) {
        sd_device *child, *parent;
        int r;

        assert(device);

        arg_json_format_flags |=SD_JSON_FORMAT_SEQ;

        r = print_all_attributes_in_json(device, /* is_parent = */ false);
        if (r < 0)
                return r;

        for (child = device; sd_device_get_parent(child, &parent) >= 0; child = parent) {
                r = print_all_attributes_in_json(parent, /* is_parent = */ true);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int print_record(sd_device *device, const char *prefix) {
        const char *str, *subsys;
        dev_t devnum;
        uint64_t q;
        int i, ifi;

        assert(device);

        prefix = strempty(prefix);

        /* We don't show syspath here, because it's identical to devpath (modulo the "/sys" prefix).
         *
         * We don't show action/seqnum here because that only makes sense for records synthesized from
         * uevents, not for those synthesized from database entries.
         *
         * We don't show sysattrs here, because they can be expensive and potentially issue expensive driver
         * IO.
         *
         * Coloring: let's be conservative with coloring. Let's use it to group related fields. Right now:
         *
         *     • white for fields that give the device a name
         *     • green for fields that categorize the device into subsystem/devtype and similar
         *     • cyan for fields about associated device nodes/symlinks/network interfaces and such
         *     • magenta for block device diskseq
         *     • yellow for driver info
         *     • no color for regular properties */

        assert_se(sd_device_get_devpath(device, &str) >= 0);
        printf("%sP: %s%s%s\n", prefix, ansi_highlight_white(), str, ansi_normal());

        if (sd_device_get_sysname(device, &str) >= 0)
                printf("%sM: %s%s%s\n", prefix, ansi_highlight_white(), str, ansi_normal());

        if (sd_device_get_sysnum(device, &str) >= 0)
                printf("%sR: %s%s%s\n", prefix, ansi_highlight_white(), str, ansi_normal());

        if (sd_device_get_device_id(device, &str) >= 0)
                printf("%sJ: %s%s%s\n", prefix, ansi_highlight_white(), str, ansi_normal());

        if (sd_device_get_subsystem(device, &subsys) >= 0)
                printf("%sU: %s%s%s\n", prefix, ansi_highlight_green(), subsys, ansi_normal());

        if (sd_device_get_driver_subsystem(device, &str) >= 0)
                printf("%sB: %s%s%s\n", prefix, ansi_highlight_green(), str, ansi_normal());

        if (sd_device_get_devtype(device, &str) >= 0)
                printf("%sT: %s%s%s\n", prefix, ansi_highlight_green(), str, ansi_normal());

        if (sd_device_get_devnum(device, &devnum) >= 0)
                printf("%sD: %s%c %u:%u%s\n",
                       prefix,
                       ansi_highlight_cyan(),
                       streq_ptr(subsys, "block") ? 'b' : 'c', major(devnum), minor(devnum),
                       ansi_normal());

        if (sd_device_get_ifindex(device, &ifi) >= 0)
                printf("%sI: %s%i%s\n", prefix, ansi_highlight_cyan(), ifi, ansi_normal());

        if (sd_device_get_devname(device, &str) >= 0) {
                const char *val;

                assert_se(val = path_startswith(str, "/dev/"));
                printf("%sN: %s%s%s\n", prefix, ansi_highlight_cyan(), val, ansi_normal());

                if (device_get_devlink_priority(device, &i) >= 0)
                        printf("%sL: %s%i%s\n", prefix, ansi_highlight_cyan(), i, ansi_normal());

                FOREACH_DEVICE_DEVLINK(device, link) {
                        assert_se(val = path_startswith(link, "/dev/"));
                        printf("%sS: %s%s%s\n", prefix, ansi_highlight_cyan(), val, ansi_normal());
                }
        }

        if (sd_device_get_diskseq(device, &q) >= 0)
                printf("%sQ: %s%" PRIu64 "%s\n", prefix, ansi_highlight_magenta(), q, ansi_normal());

        if (sd_device_get_driver(device, &str) >= 0)
                printf("%sV: %s%s%s\n", prefix, ansi_highlight_yellow4(), str, ansi_normal());

        FOREACH_DEVICE_PROPERTY(device, key, val)
                printf("%sE: %s=%s\n", prefix, key, val);

        if (isempty(prefix))
                puts("");
        return 0;
}

static int record_to_json(sd_device *device, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        const char *str;
        int r;

        assert(device);
        assert(ret);

        /* We don't show any shorthand fields here as done in print_record() except for SYSNAME, SYSNUM,
         * DRIVER_SUBSYSTEM, and DEVICE_ID, as all the other ones have a matching property which will already
         * be included. */

        if (sd_device_get_sysname(device, &str) >= 0) {
                r = sd_json_variant_set_field_string(&v, "SYSNAME", str);
                if (r < 0)
                        return r;
        }

        if (sd_device_get_sysnum(device, &str) >= 0) {
                r = sd_json_variant_set_field_string(&v, "SYSNUM", str);
                if (r < 0)
                        return r;
        }

        if (sd_device_get_driver_subsystem(device, &str) >= 0) {
                r = sd_json_variant_set_field_string(&v, "DRIVER_SUBSYSTEM", str);
                if (r < 0)
                        return r;
        }

        if (sd_device_get_device_id(device, &str) >= 0) {
                r = sd_json_variant_set_field_string(&v, "DEVICE_ID", str);
                if (r < 0)
                        return r;
        }

        FOREACH_DEVICE_PROPERTY(device, key, val) {
                r = sd_json_variant_set_field_string(&v, key, val);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int stat_device(const char *name, bool export, const char *prefix) {
        struct stat statbuf;

        assert(name);

        if (stat(name, &statbuf) != 0)
                return -errno;

        if (export) {
                if (!prefix)
                        prefix = "INFO_";
                printf("%sMAJOR=%u\n"
                       "%sMINOR=%u\n",
                       prefix, major(statbuf.st_dev),
                       prefix, minor(statbuf.st_dev));
        } else
                printf("%u:%u\n", major(statbuf.st_dev), minor(statbuf.st_dev));
        return 0;
}

static int export_devices(sd_device_enumerator *e) {
        sd_device *d;
        int r;

        assert(e);

        r = device_enumerator_scan_devices(e);
        if (r < 0)
                return log_error_errno(r, "Failed to scan devices: %m");

        pager_open(arg_pager_flags);

        FOREACH_DEVICE_AND_SUBSYSTEM(e, d)
                if (sd_json_format_enabled(arg_json_format_flags)) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                        r = record_to_json(d, &v);
                        if (r < 0)
                                return r;

                        (void) sd_json_variant_dump(v, arg_json_format_flags, stdout, NULL);
                } else
                        (void) print_record(d, NULL);

        return 0;
}

static void cleanup_dir(DIR *dir, mode_t mask, int depth) {
        assert(dir);

        if (depth <= 0)
                return;

        FOREACH_DIRENT_ALL(dent, dir, break) {
                struct stat stats;

                if (dot_or_dot_dot(dent->d_name))
                        continue;
                if (fstatat(dirfd(dir), dent->d_name, &stats, AT_SYMLINK_NOFOLLOW) < 0)
                        continue;
                if ((stats.st_mode & mask) != 0)
                        continue;
                if (S_ISDIR(stats.st_mode)) {
                        _cleanup_closedir_ DIR *subdir = NULL;

                        subdir = xopendirat(dirfd(dir), dent->d_name, O_NOFOLLOW);
                        if (!subdir)
                                log_debug_errno(errno, "Failed to open subdirectory '%s', ignoring: %m", dent->d_name);
                        else
                                cleanup_dir(subdir, mask, depth-1);

                        (void) unlinkat(dirfd(dir), dent->d_name, AT_REMOVEDIR);
                } else
                        (void) unlinkat(dirfd(dir), dent->d_name, 0);
        }
}

/*
 * Assume that dir is a directory with file names matching udev data base
 * entries for devices in /run/udev/data (such as "b8:16"), and removes
 * all files except those that haven't been deleted in /run/udev/data
 * (i.e. they were skipped during db cleanup because of the db_persist flag).
 */
static void cleanup_dir_after_db_cleanup(DIR *dir, DIR *datadir) {
        assert(dir);
        assert(datadir);

        FOREACH_DIRENT_ALL(dent, dir, break) {
                if (dot_or_dot_dot(dent->d_name))
                        continue;

                if (faccessat(dirfd(datadir), dent->d_name, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                        /* The corresponding udev database file still exists.
                         * Assuming the persistent flag is set for the database. */
                        continue;

                (void) unlinkat(dirfd(dir), dent->d_name, 0);
        }
}

static void cleanup_dirs_after_db_cleanup(DIR *dir, DIR *datadir) {
        assert(dir);
        assert(datadir);

        FOREACH_DIRENT_ALL(dent, dir, break) {
                struct stat stats;

                if (dot_or_dot_dot(dent->d_name))
                        continue;
                if (fstatat(dirfd(dir), dent->d_name, &stats, AT_SYMLINK_NOFOLLOW) < 0)
                        continue;
                if (S_ISDIR(stats.st_mode)) {
                        _cleanup_closedir_ DIR *subdir = NULL;

                        subdir = xopendirat(dirfd(dir), dent->d_name, O_NOFOLLOW);
                        if (!subdir)
                                log_debug_errno(errno, "Failed to open subdirectory '%s', ignoring: %m", dent->d_name);
                        else
                                cleanup_dir_after_db_cleanup(subdir, datadir);

                        (void) unlinkat(dirfd(dir), dent->d_name, AT_REMOVEDIR);
                } else
                        (void) unlinkat(dirfd(dir), dent->d_name, 0);
        }
}

static void cleanup_db(void) {
        _cleanup_closedir_ DIR *dir1 = NULL, *dir2 = NULL, *dir3 = NULL, *dir4 = NULL;

        dir1 = opendir("/run/udev/data");
        if (dir1)
                cleanup_dir(dir1, S_ISVTX, 1);

        dir2 = opendir("/run/udev/links");
        if (dir2)
                cleanup_dirs_after_db_cleanup(dir2, dir1);

        dir3 = opendir("/run/udev/tags");
        if (dir3)
                cleanup_dirs_after_db_cleanup(dir3, dir1);

        dir4 = opendir("/run/udev/static_node-tags");
        if (dir4)
                cleanup_dir(dir4, 0, 2);

        /* Do not remove /run/udev/watch. It will be handled by udevd well on restart.
         * And should not be removed by external program when udevd is running. */
}

static int query_device(QueryType query, sd_device* device) {
        int r;

        assert(device);

        switch (query) {
        case QUERY_NAME: {
                const char *node;

                r = sd_device_get_devname(device, &node);
                if (r < 0)
                        return log_error_errno(r, "No device node found: %m");

                if (!arg_root)
                        assert_se(node = path_startswith(node, "/dev/"));
                printf("%s\n", node);
                return 0;
        }

        case QUERY_SYMLINK: {
                const char *prefix = "";

                FOREACH_DEVICE_DEVLINK(device, devlink) {
                        if (!arg_root)
                                assert_se(devlink = path_startswith(devlink, "/dev/"));
                        printf("%s%s", prefix, devlink);
                        prefix = " ";
                }
                puts("");
                return 0;
        }

        case QUERY_PATH: {
                const char *devpath;

                r = sd_device_get_devpath(device, &devpath);
                if (r < 0)
                        return log_error_errno(r, "Failed to get device path: %m");

                printf("%s\n", devpath);
                return 0;
        }

        case QUERY_PROPERTY:
                FOREACH_DEVICE_PROPERTY(device, key, value) {
                        if (arg_properties && !strv_contains(arg_properties, key))
                                continue;

                        if (arg_export)
                                printf("%s%s='%s'\n", strempty(arg_export_prefix), key, value);
                        else if (arg_value)
                                printf("%s\n", value);
                        else
                                printf("%s=%s\n", key, value);
                }

                return 0;

        case QUERY_ALL:
                if (sd_json_format_enabled(arg_json_format_flags))  {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                        r = record_to_json(device, &v);
                        if (r < 0)
                                return r;

                        (void) sd_json_variant_dump(v, arg_json_format_flags, stdout, NULL);
                } else
                        return print_record(device, NULL);

                return 0;

        default:
                assert_not_reached();
        }
}

static int help(void) {
        printf("%s info [OPTIONS] [DEVPATH|FILE]\n\n"
               "Query sysfs or the udev database.\n\n"
               "  -h --help                   Print this message\n"
               "  -V --version                Print version of the program\n"
               "  -q --query=TYPE             Query device information:\n"
               "       name                     Name of device node\n"
               "       symlink                  Pointing to node\n"
               "       path                     sysfs device path\n"
               "       property                 The device properties\n"
               "       all                      All values\n"
               "     --property=NAME          Show only properties by this name\n"
               "     --value                  When showing properties, print only their values\n"
               "  -p --path=SYSPATH           sysfs device path used for query or attribute walk\n"
               "  -n --name=NAME              Node or symlink name used for query or attribute walk\n"
               "  -r --root                   Prepend dev directory to path names\n"
               "  -a --attribute-walk         Print all key matches walking along the chain\n"
               "                              of parent devices\n"
               "  -t --tree                   Show tree of devices\n"
               "  -d --device-id-of-file=FILE Print major:minor of device containing this file\n"
               "  -x --export                 Export key/value pairs\n"
               "  -P --export-prefix          Export the key name with a prefix\n"
               "  -e --export-db              Export the content of the udev database\n"
               "  -c --cleanup-db             Clean up the udev database\n"
               "  -w --wait-for-initialization[=SECONDS]\n"
               "                              Wait for device to be initialized\n"
               "     --no-pager               Do not pipe output into a pager\n"
               "     --json=pretty|short|off  Generate JSON output\n"
               "     --subsystem-match=SUBSYSTEM\n"
               "                              Query devices matching a subsystem\n"
               "     --subsystem-nomatch=SUBSYSTEM\n"
               "                              Query devices not matching a subsystem\n"
               "     --attr-match=FILE[=VALUE]\n"
               "                              Query devices that match an attribute\n"
               "     --attr-nomatch=FILE[=VALUE]\n"
               "                              Query devices that do not match an attribute\n"
               "     --property-match=KEY=VALUE\n"
               "                              Query devices with matching properties\n"
               "     --tag-match=TAG          Query devices with a matching tag\n"
               "     --sysname-match=NAME     Query devices with this /sys path\n"
               "     --name-match=NAME        Query devices with this /dev name\n"
               "     --parent-match=NAME      Query devices with this parent device\n"
               "     --initialized-match      Query devices that are already initialized\n"
               "     --initialized-nomatch    Query devices that are not initialized yet\n",
               program_invocation_short_name);

        return 0;
}

static int draw_tree(
                sd_device *parent,
                sd_device *const array[], size_t n,
                const char *prefix,
                unsigned level);

static int output_tree_device(
                sd_device *device,
                const char *str,
                const char *prefix,
                bool more,
                sd_device *const array[], size_t n,
                unsigned level) {

        _cleanup_free_ char *subprefix = NULL, *subsubprefix = NULL;

        assert(device);
        assert(str);

        prefix = strempty(prefix);

        printf("%s%s%s\n", prefix, special_glyph(more ? SPECIAL_GLYPH_TREE_BRANCH : SPECIAL_GLYPH_TREE_RIGHT), str);

        subprefix = strjoin(prefix, special_glyph(more ? SPECIAL_GLYPH_TREE_VERTICAL : SPECIAL_GLYPH_TREE_SPACE));
        if (!subprefix)
                return log_oom();

        subsubprefix = strjoin(subprefix, special_glyph(SPECIAL_GLYPH_VERTICAL_DOTTED), " ");
        if (!subsubprefix)
                return log_oom();

        (void) print_record(device, subsubprefix);

        return draw_tree(device, array, n, subprefix, level + 1);
}

static int draw_tree(
                sd_device *parent,
                sd_device *const array[], size_t n,
                const char *prefix,
                unsigned level) {

        const char *parent_path;
        size_t i = 0;
        int r;

        if (n == 0)
                return 0;

        assert(array);

        if (parent) {
                r = sd_device_get_devpath(parent, &parent_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to get sysfs path of parent device: %m");
        } else
                parent_path = NULL;

        if (level > TREE_DEPTH_MAX) {
                log_warning("Eliding tree below '%s', too deep.", strna(parent_path));
                return 0;
        }

        while (i < n) {
                sd_device *device = array[i];
                const char *device_path, *str;
                bool more = false;
                size_t j;

                r = sd_device_get_devpath(device, &device_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to get sysfs path of enumerated device: %m");

                /* Scan through the subsequent devices looking children of the device we are looking at. */
                for (j = i + 1; j < n; j++) {
                        sd_device *next = array[j];
                        const char *next_path;

                        r = sd_device_get_devpath(next, &next_path);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get sysfs of child device: %m");

                        if (!path_startswith(next_path, device_path)) {
                                more = !parent_path || path_startswith(next_path, parent_path);
                                break;
                        }
                }

                /* Determine the string to display for this node. If we are at the top of the tree, the full
                 * device path so far, otherwise just the part suffixing the parent's device path. */
                str = parent ? ASSERT_PTR(path_startswith(device_path, parent_path)) : device_path;

                r = output_tree_device(device, str, prefix, more, array + i + 1, j - i - 1, level);
                if (r < 0)
                        return r;

                i = j;
        }

        return 0;
}

static int print_tree(sd_device* below) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        const char *below_path;
        sd_device **array;
        size_t n = 0;
        int r;

        if (below) {
                r = sd_device_get_devpath(below, &below_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to get sysfs path of device: %m");

        } else
                below_path = NULL;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate device enumerator: %m");

        if (below) {
                r = sd_device_enumerator_add_match_parent(e, below);
                if (r < 0)
                        return log_error_errno(r, "Failed to install parent enumerator match: %m");
        }

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return log_error_errno(r, "Failed to enable enumeration of uninitialized devices: %m");

        r = device_enumerator_scan_devices_and_subsystems(e);
        if (r < 0)
                return log_error_errno(r, "Failed to scan for devices and subsystems: %m");

        if (below) {
                /* This must be called after device_enumerator_scan_devices_and_subsystems(). */
                r = device_enumerator_add_parent_devices(e, below);
                if (r < 0)
                        return log_error_errno(r, "Failed to add parent devices: %m");
        }

        assert_se(array = device_enumerator_get_devices(e, &n));

        if (n == 0) {
                log_info("No items.");
                return 0;
        }

        r = draw_tree(NULL, array, n, NULL, 0);
        if (r < 0)
                return r;

        printf("\n%zu items shown.\n", n);
        return 0;
}

static int ensure_device_enumerator(sd_device_enumerator **e) {
        int r;

        assert(e);

        if (*e)
                return 0;

        r = sd_device_enumerator_new(e);
        if (r < 0)
                return log_error_errno(r, "Failed to create device enumerator: %m");

        r = sd_device_enumerator_allow_uninitialized(*e);
        if (r < 0)
                return log_error_errno(r, "Failed to allow uninitialized devices: %m");

        return 0;
}

static int parse_key_value_argument(const char *s, char **key, char **value) {
        _cleanup_free_ char *k = NULL, *v = NULL;
        int r;

        assert(s);
        assert(key);
        assert(value);

        r = extract_many_words(&s, "=", EXTRACT_DONT_COALESCE_SEPARATORS, &k, &v);
        if (r < 0)
                return log_error_errno(r, "Failed to parse key/value pair %s: %m", s);
        if (r < 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing '=' in key/value pair %s.", s);

        if (!filename_is_valid(k))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s is not a valid key name", k);

        free_and_replace(*key, k);
        free_and_replace(*value, v);
        return 0;
}

int info_main(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_strv_free_ char **devices = NULL;
        _cleanup_free_ char *name = NULL;
        int c, r, ret;

        enum {
                ARG_PROPERTY = 0x100,
                ARG_VALUE,
                ARG_NO_PAGER,
                ARG_JSON,
                ARG_SUBSYSTEM_MATCH,
                ARG_SUBSYSTEM_NOMATCH,
                ARG_ATTR_MATCH,
                ARG_ATTR_NOMATCH,
                ARG_PROPERTY_MATCH,
                ARG_TAG_MATCH,
                ARG_SYSNAME_MATCH,
                ARG_NAME_MATCH,
                ARG_PARENT_MATCH,
                ARG_INITIALIZED_MATCH,
                ARG_INITIALIZED_NOMATCH,
        };

        static const struct option options[] = {
                { "attribute-walk",          no_argument,       NULL, 'a'                     },
                { "tree",                    no_argument,       NULL, 't'                     },
                { "cleanup-db",              no_argument,       NULL, 'c'                     },
                { "device-id-of-file",       required_argument, NULL, 'd'                     },
                { "export",                  no_argument,       NULL, 'x'                     },
                { "export-db",               no_argument,       NULL, 'e'                     },
                { "export-prefix",           required_argument, NULL, 'P'                     },
                { "help",                    no_argument,       NULL, 'h'                     },
                { "name",                    required_argument, NULL, 'n'                     },
                { "path",                    required_argument, NULL, 'p'                     },
                { "property",                required_argument, NULL, ARG_PROPERTY            },
                { "query",                   required_argument, NULL, 'q'                     },
                { "root",                    no_argument,       NULL, 'r'                     },
                { "value",                   no_argument,       NULL, ARG_VALUE               },
                { "version",                 no_argument,       NULL, 'V'                     },
                { "wait-for-initialization", optional_argument, NULL, 'w'                     },
                { "no-pager",                no_argument,       NULL, ARG_NO_PAGER            },
                { "json",                    required_argument, NULL, ARG_JSON                },
                { "subsystem-match",         required_argument, NULL, ARG_SUBSYSTEM_MATCH     },
                { "subsystem-nomatch",       required_argument, NULL, ARG_SUBSYSTEM_NOMATCH   },
                { "attr-match",              required_argument, NULL, ARG_ATTR_MATCH          },
                { "attr-nomatch",            required_argument, NULL, ARG_ATTR_NOMATCH        },
                { "property-match",          required_argument, NULL, ARG_PROPERTY_MATCH      },
                { "tag-match",               required_argument, NULL, ARG_TAG_MATCH           },
                { "sysname-match",           required_argument, NULL, ARG_SYSNAME_MATCH       },
                { "name-match",              required_argument, NULL, ARG_NAME_MATCH          },
                { "parent-match",            required_argument, NULL, ARG_PARENT_MATCH        },
                { "initialized-match",       no_argument,       NULL, ARG_INITIALIZED_MATCH   },
                { "initialized-nomatch",     no_argument,       NULL, ARG_INITIALIZED_NOMATCH },
                {}
        };

        ActionType action = ACTION_QUERY;
        QueryType query = QUERY_ALL;

        while ((c = getopt_long(argc, argv, "atced:n:p:q:rxP:w::Vh", options, NULL)) >= 0)
                switch (c) {
                case ARG_PROPERTY:
                        /* Make sure that if the empty property list was specified, we won't show any
                           properties. */
                        if (isempty(optarg) && !arg_properties) {
                                arg_properties = new0(char*, 1);
                                if (!arg_properties)
                                        return log_oom();
                        } else {
                                r = strv_split_and_extend(&arg_properties, optarg, ",", true);
                                if (r < 0)
                                        return log_oom();
                        }
                        break;
                case ARG_VALUE:
                        arg_value = true;
                        break;
                case 'n':
                case 'p': {
                        const char *prefix = c == 'n' ? "/dev/" : "/sys/";
                        char *path;

                        path = path_join(path_startswith(optarg, prefix) ? NULL : prefix, optarg);
                        if (!path)
                                return log_oom();

                        r = strv_consume(&devices, path);
                        if (r < 0)
                                return log_oom();
                        break;
                }

                case 'q':
                        action = ACTION_QUERY;
                        if (streq(optarg, "property") || streq(optarg, "env"))
                                query = QUERY_PROPERTY;
                        else if (streq(optarg, "name"))
                                query = QUERY_NAME;
                        else if (streq(optarg, "symlink"))
                                query = QUERY_SYMLINK;
                        else if (streq(optarg, "path"))
                                query = QUERY_PATH;
                        else if (streq(optarg, "all"))
                                query = QUERY_ALL;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "unknown query type");
                        break;
                case 'r':
                        arg_root = true;
                        break;
                case 'd':
                        action = ACTION_DEVICE_ID_FILE;
                        r = free_and_strdup(&name, optarg);
                        if (r < 0)
                                return log_oom();
                        break;
                case 'a':
                        action = ACTION_ATTRIBUTE_WALK;
                        break;
                case 't':
                        action = ACTION_TREE;
                        break;
                case 'e':
                        action = ACTION_EXPORT;
                        break;
                case 'c':
                        cleanup_db();
                        return 0;
                case 'x':
                        arg_export = true;
                        break;
                case 'P':
                        arg_export = true;
                        arg_export_prefix = optarg;
                        break;
                case 'w':
                        if (optarg) {
                                r = parse_sec(optarg, &arg_wait_for_initialization_timeout);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse timeout value: %m");
                        } else
                                arg_wait_for_initialization_timeout = USEC_INFINITY;
                        break;
                case 'V':
                        return print_version();
                case 'h':
                        return help();
                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                case ARG_SUBSYSTEM_MATCH:
                case ARG_SUBSYSTEM_NOMATCH:
                        r = ensure_device_enumerator(&e);
                        if (r < 0)
                                return r;

                        r = sd_device_enumerator_add_match_subsystem(e, optarg, c == ARG_SUBSYSTEM_MATCH);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add%s subsystem match '%s': %m",
                                                       c == ARG_SUBSYSTEM_MATCH ? "" : " negative", optarg);

                        break;

                case ARG_ATTR_MATCH:
                case ARG_ATTR_NOMATCH: {
                        _cleanup_free_ char *k = NULL, *v = NULL;

                        r = ensure_device_enumerator(&e);
                        if (r < 0)
                                return r;

                        r = parse_key_value_argument(optarg, &k, &v);
                        if (r < 0)
                                return r;

                        r = sd_device_enumerator_add_match_sysattr(e, k, v, c == ARG_ATTR_MATCH);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add%s sysattr match '%s=%s': %m",
                                                       c == ARG_ATTR_MATCH ? "" : " negative", k, v);
                        break;
                }

                case ARG_PROPERTY_MATCH: {
                        _cleanup_free_ char *k = NULL, *v = NULL;

                        r = ensure_device_enumerator(&e);
                        if (r < 0)
                                return r;

                        r = parse_key_value_argument(optarg, &k, &v);
                        if (r < 0)
                                return r;

                        r = sd_device_enumerator_add_match_property_required(e, k, v);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add property match '%s=%s': %m", k, v);
                        break;
                }

                case ARG_TAG_MATCH:
                        r = ensure_device_enumerator(&e);
                        if (r < 0)
                                return r;

                        r = sd_device_enumerator_add_match_tag(e, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add tag match '%s': %m", optarg);
                        break;

                case ARG_SYSNAME_MATCH:
                        r = ensure_device_enumerator(&e);
                        if (r < 0)
                                return r;

                        r = sd_device_enumerator_add_match_sysname(e, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add sysname match '%s': %m", optarg);
                        break;

                case ARG_NAME_MATCH:
                case ARG_PARENT_MATCH: {
                        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

                        r = find_device(optarg, c == ARG_NAME_MATCH ? "/dev" : "/sys", &dev);
                        if (r < 0)
                                return log_error_errno(r, "Failed to open the device '%s': %m", optarg);

                        r = ensure_device_enumerator(&e);
                        if (r < 0)
                                return r;

                        r = device_enumerator_add_match_parent_incremental(e, dev);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add parent match '%s': %m", optarg);
                        break;
                }

                case ARG_INITIALIZED_MATCH:
                case ARG_INITIALIZED_NOMATCH:
                        r = ensure_device_enumerator(&e);
                        if (r < 0)
                                return r;

                        r = device_enumerator_add_match_is_initialized(e, c == ARG_INITIALIZED_MATCH ? MATCH_INITIALIZED_YES : MATCH_INITIALIZED_NO);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set initialized filter: %m");
                        break;

                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached();
                }

        if (action == ACTION_DEVICE_ID_FILE) {
                if (argv[optind])
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Positional arguments are not allowed with -d/--device-id-of-file.");
                assert(name);
                return stat_device(name, arg_export, arg_export_prefix);
        }

        if (action == ACTION_EXPORT) {
                r = ensure_device_enumerator(&e);
                if (r < 0)
                        return r;

                return export_devices(e);
        }

        r = strv_extend_strv(&devices, argv + optind, false);
        if (r < 0)
                return log_error_errno(r, "Failed to build argument list: %m");

        if (action != ACTION_TREE && strv_isempty(devices))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "A device name or path is required");
        if (IN_SET(action, ACTION_ATTRIBUTE_WALK, ACTION_TREE) && strv_length(devices) > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Only one device may be specified with -a/--attribute-walk and -t/--tree");

        if (arg_export && arg_value)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "-x/--export or -P/--export-prefix cannot be used with --value");

        pager_open(arg_pager_flags);

        if (strv_isempty(devices)) {
                assert(action == ACTION_TREE);
                return print_tree(NULL);
        }

        ret = 0;
        STRV_FOREACH(p, devices) {
                _cleanup_(sd_device_unrefp) sd_device *device = NULL;

                r = find_device(*p, NULL, &device);
                if (r < 0) {
                        if (r == -EINVAL)
                                log_error_errno(r, "Bad argument \"%s\", expected an absolute path in /dev/ or /sys/ or a unit name: %m", *p);
                        else
                                log_error_errno(r, "Unknown device \"%s\": %m",  *p);

                        if (ret == 0)
                                ret = r;
                        continue;
                }

                if (arg_wait_for_initialization_timeout > 0) {
                        sd_device *d;

                        r = device_wait_for_initialization(
                                        device,
                                        NULL,
                                        arg_wait_for_initialization_timeout,
                                        &d);
                        if (r < 0)
                                return r;

                        sd_device_unref(device);
                        device = d;
                }

                if (action == ACTION_QUERY)
                        r = query_device(query, device);
                else if (action == ACTION_ATTRIBUTE_WALK) {
                        if (sd_json_format_enabled(arg_json_format_flags))
                                r = print_device_chain_in_json(device);
                        else
                                r = print_device_chain(device);
                } else if (action == ACTION_TREE)
                        r = print_tree(device);
                else
                        assert_not_reached();
                if (r < 0)
                        return r;
        }

        return ret;
}
