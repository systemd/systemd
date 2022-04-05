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

#include "alloc-util.h"
#include "device-enumerator-private.h"
#include "device-private.h"
#include "device-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "glyph-util.h"
#include "pager.h"
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
        const char *name, *value;
        size_t n_items = 0;
        int r;

        assert(device);

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

        for (size_t i = 0; i < n_items; i++)
                printf("    %s{%s}==\"%s\"\n", is_parent ? "ATTRS" : "ATTR", sysattrs[i].name, sysattrs[i].value);

        puts("");

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

        r = print_all_attributes(device, false);
        if (r < 0)
                return r;

        for (child = device; sd_device_get_parent(child, &parent) >= 0; child = parent) {
                r = print_all_attributes(parent, true);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int print_record(sd_device *device, const char *prefix) {
        const char *str, *val, *subsys;
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

        if (sd_device_get_subsystem(device, &subsys) >= 0)
                printf("%sU: %s%s%s\n", prefix, ansi_highlight_green(), subsys, ansi_normal());

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
                assert_se(val = path_startswith(str, "/dev/"));
                printf("%sN: %s%s%s\n", prefix, ansi_highlight_cyan(), val, ansi_normal());

                if (device_get_devlink_priority(device, &i) >= 0)
                        printf("%sL: %s%i%s\n", prefix, ansi_highlight_cyan(), i, ansi_normal());

                FOREACH_DEVICE_DEVLINK(device, str) {
                        assert_se(val = path_startswith(str, "/dev/"));
                        printf("%sS: %s%s%s\n", prefix, ansi_highlight_cyan(), val, ansi_normal());
                }
        }

        if (sd_device_get_diskseq(device, &q) >= 0)
                printf("%sQ: %s%" PRIu64 "%s\n", prefix, ansi_highlight_magenta(), q, ansi_normal());

        if (sd_device_get_driver(device, &str) >= 0)
                printf("%sV: %s%s%s\n", prefix, ansi_highlight_yellow4(), str, ansi_normal());

        FOREACH_DEVICE_PROPERTY(device, str, val)
                printf("%sE: %s=%s\n", prefix, str, val);

        if (isempty(prefix))
                puts("");
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

static int export_devices(void) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *d;
        int r;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return log_oom();

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return log_error_errno(r, "Failed to set allowing uninitialized flag: %m");

        r = device_enumerator_scan_devices(e);
        if (r < 0)
                return log_error_errno(r, "Failed to scan devices: %m");

        FOREACH_DEVICE_AND_SUBSYSTEM(e, d)
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
                        _cleanup_closedir_ DIR *dir2 = NULL;

                        dir2 = fdopendir(openat(dirfd(dir), dent->d_name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC));
                        if (dir2)
                                cleanup_dir(dir2, mask, depth-1);

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
                         * Assuming the parsistent flag is set for the database. */
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
                        _cleanup_closedir_ DIR *dir2 = NULL;

                        dir2 = fdopendir(openat(dirfd(dir), dent->d_name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC));
                        if (dir2)
                                cleanup_dir_after_db_cleanup(dir2, datadir);

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
                const char *devlink, *prefix = "";

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

        case QUERY_PROPERTY: {
                const char *key, *value;

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
        }

        case QUERY_ALL:
                return print_record(device, NULL);

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
               "                              Wait for device to be initialized\n",
               program_invocation_short_name);

        return 0;
}

static int device_traverse_upwards(
                sd_device *below,
                sd_device *focus,
                sd_device **ret) {

        const char *below_path, *focus_path;
        int r;

        assert(focus);
        assert(ret);

        /* Goes from the 'focus' device iteratively upwards through the parents chain until the the next
         * parent is not below the 'below' device anymore. */

        r = sd_device_get_devpath(focus, &focus_path);
        if (r < 0)
                return r;

        if (below) {
                r = sd_device_get_devpath(below, &below_path);
                if (r < 0)
                        return r;

                if (isempty(path_startswith(focus_path, below_path))) {
                        /* If the start device isn't a child of the 'below' path, then we are done already. */
                        *ret = NULL;
                        return 0;
                }
        } else
                below_path = NULL;

        for (;;) {
                const char *w_path;
                sd_device *w;

                r = sd_device_get_parent(focus, &w);
                if (r == -ENOENT) /* Nothing further up? */
                        break;
                if (r < 0)
                        return r;

                r = sd_device_get_devpath(w, &w_path);
                if (r < 0)
                        return r;

                if (below && isempty(path_startswith(w_path, below_path)))
                        break;

                focus = w;
        }

        *ret = focus;
        return 1;
}

static int print_tree(sd_device* below, const char *prefix, unsigned level);

static int output_tree_device(
                sd_device *d,
                const char *str,
                const char *devpath,
                const char *prefix,
                bool more,
                unsigned level) {

        _cleanup_free_ char *subprefix = NULL, *subsubprefix = NULL;


        assert(d);
        assert(str);
        assert(devpath);

        prefix = strempty(prefix);

        printf("%s%s%s\n", prefix, special_glyph(more ? SPECIAL_GLYPH_TREE_BRANCH : SPECIAL_GLYPH_TREE_RIGHT), str);

        subprefix = strjoin(strempty(prefix), special_glyph(more ? SPECIAL_GLYPH_TREE_VERTICAL : SPECIAL_GLYPH_TREE_SPACE));
        if (!subprefix)
                return log_oom();

        subsubprefix = strjoin(subprefix, special_glyph(SPECIAL_GLYPH_VERTICAL_DOTTED), " ");
        if (!subsubprefix)
                return log_oom();

        (void) print_record(d, subsubprefix);
        print_tree(d, subprefix, level + 1);

        return 0;
}

static int print_tree(sd_device* below, const char *prefix, unsigned level) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_free_ char *previous_path = NULL, *previous_string = NULL;
        _cleanup_(sd_device_unrefp) sd_device *previous_device = NULL;
        const char *below_path;
        sd_device *child;
        int r;

        if (below) {
                r = sd_device_get_devpath(below, &below_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to get sysfs path of device: %m");

                /* log_notice("looking at %s", below_path); */
        } else {
                pager_open(0);
                below_path = NULL;
        }

        if (level >= TREE_DEPTH_MAX) {
                assert(below_path);
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Device recursion too deep at device '%s', refusing.", below_path);
        }

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

        FOREACH_DEVICE(e, child) {
                const char *child_path, *str;

                /* So here's the thing: in the sysfs tree there are certain devices that are not linked from
                 * /sys/class/ or /sys/devices/ (and which will thus not be enumerated). These devices exist
                 * mostly for grouping stuff. We want to show them here, since this kind of grouping is after
                 * all exactly what we want to display in our tree output. To find them we'll simply go
                 * upwards towards the root of the tree from the enumerated child devices towards the closest
                 * device that is still below the root of the subtree we are looking at. Of course this means
                 * we'll oftentimes discover the same devices multiple times here (i.e. multiple
                 * grandchildren resulting in the same child to be discovered), hence we do some simple
                 * filtering of duplicates below. Because the tree is ordered nicely we just need to compare
                 * the child with the previous one to find such duplicate. */

                r = device_traverse_upwards(below, child, &child);
                if (IN_SET(r, 0, -ENODEV)) /* Outside of 'below'? Or vanished by now? */
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to find topmost parent of child device: %m");

                r = sd_device_get_devpath(child, &child_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to get sysfs path of child device: %m");

                /* Determine string to display */
                str = below ? ASSERT_PTR(path_startswith(child_path, below_path)) : child_path;

                /* Now we figured out all details, and can output information about the entry. Except we
                 * can't. We first need to figure out whether we want to output further entries. If we do we
                 * need to draw "branch" glyph, otherwise a "right" glyph. Hence we won't display the entry
                 * right away, but simply store information about it, and display it in the next
                 * cycle. Conversely if we already have stored information about a previous device, now it's
                 * the time to output it. */

                if (previous_device) {
                        if (path_equal(previous_path, child_path)) /* Duplicate child, due to the upwards traversion, see above */
                                continue;

                        /* Output the previous item (This one will get a "branch" glyph) */
                        r = output_tree_device(previous_device, previous_string, previous_path, prefix, /* more= */ true, level);
                        if (r < 0)
                                return r;
                }

                /* Remember this entry, so that we can output it on the next iteration */
                r = free_and_strdup_warn(&previous_string, str);
                if (r < 0)
                        return r;

                r = free_and_strdup_warn(&previous_path, child_path);
                if (r < 0)
                        return r;

                sd_device_unref(previous_device);
                previous_device = sd_device_ref(child);
        }

        if (previous_device) {
                /* And now output the final item (This one will get a "right" glyph) */
                r = output_tree_device(previous_device, previous_string, previous_path, prefix, /* more= */ false, level);
                if (r < 0)
                        return r;
        }

        return 0;
}

int info_main(int argc, char *argv[], void *userdata) {
        _cleanup_strv_free_ char **devices = NULL;
        _cleanup_free_ char *name = NULL;
        int c, r, ret;

        enum {
                ARG_PROPERTY = 0x100,
                ARG_VALUE,
        };

        static const struct option options[] = {
                { "attribute-walk",          no_argument,       NULL, 'a'          },
                { "tree",                    no_argument,       NULL, 't'          },
                { "cleanup-db",              no_argument,       NULL, 'c'          },
                { "device-id-of-file",       required_argument, NULL, 'd'          },
                { "export",                  no_argument,       NULL, 'x'          },
                { "export-db",               no_argument,       NULL, 'e'          },
                { "export-prefix",           required_argument, NULL, 'P'          },
                { "help",                    no_argument,       NULL, 'h'          },
                { "name",                    required_argument, NULL, 'n'          },
                { "path",                    required_argument, NULL, 'p'          },
                { "property",                required_argument, NULL, ARG_PROPERTY },
                { "query",                   required_argument, NULL, 'q'          },
                { "root",                    no_argument,       NULL, 'r'          },
                { "value",                   no_argument,       NULL, ARG_VALUE    },
                { "version",                 no_argument,       NULL, 'V'          },
                { "wait-for-initialization", optional_argument, NULL, 'w'          },
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
                        return export_devices();
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

        if (strv_isempty(devices)) {
                assert(action == ACTION_TREE);
                return print_tree(NULL, NULL, 0);
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
                                        usec_add(now(CLOCK_MONOTONIC), arg_wait_for_initialization_timeout),
                                        &d);
                        if (r < 0)
                                return r;

                        sd_device_unref(device);
                        device = d;
                }

                if (action == ACTION_QUERY)
                        r = query_device(query, device);
                else if (action == ACTION_ATTRIBUTE_WALK)
                        r = print_device_chain(device);
                else if (action == ACTION_TREE)
                        r = print_tree(device, NULL, 0);
                else
                        assert_not_reached();
                if (r < 0)
                        return r;
        }

        return ret;
}
