/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "alloc-util.h"
#include "ansi-color.h"
#include "device-private.h"
#include "device-util.h"
#include "devnum-util.h"
#include "format-util.h"
#include "hashmap.h"
#include "json-util.h"
#include "string-util.h"
#include "strv.h"
#include "udev-builtin.h"
#include "udev-dump.h"
#include "udev-event.h"
#include "user-util.h"

static void event_cache_written_value(Hashmap **values, const char *attr, const char *value) {
        assert(values);

        _unused_ _cleanup_free_ void *key = NULL;
        free(hashmap_remove2(*values, attr, &key));

        if (hashmap_put_strdup_full(values, &path_hash_ops_free_free, attr, value) < 0)
                log_oom_debug();
}

void event_cache_written_sysattr(UdevEvent *event, const char *attr, const char *value) {
        event_cache_written_value(&event->written_sysattrs, attr, value);
}

void event_cache_written_sysctl(UdevEvent *event, const char *attr, const char *value) {
        event_cache_written_value(&event->written_sysctls, attr, value);
}

static int dump_event_json(UdevEvent *event, sd_json_format_flags_t flags, FILE *f) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        const char *str;
        int r;

        if (sd_device_get_devpath(dev, &str) >= 0) {
                r = sd_json_variant_set_field_string(&v, "path", str);
                if (r < 0)
                        return r;
        }

        if (sd_device_get_sysname(dev, &str) >= 0) {
                r = sd_json_variant_set_field_string(&v, "name", str);
                if (r < 0)
                        return r;
        }

        unsigned sysnum;
        if (device_get_sysnum_unsigned(dev, &sysnum) >= 0) {
                r = sd_json_variant_set_field_unsigned(&v, "number", sysnum);
                if (r < 0)
                        return r;
        }

        if (sd_device_get_device_id(dev, &str) >= 0) {
                r = sd_json_variant_set_field_string(&v, "id", str);
                if (r < 0)
                        return r;
        }

        const char *subsys = NULL;
        if (sd_device_get_subsystem(dev, &subsys) >= 0) {
                r = sd_json_variant_set_field_string(&v, "subsystem", subsys);
                if (r < 0)
                        return r;
        }

        if (sd_device_get_driver_subsystem(dev, &str) >= 0) {
                r = sd_json_variant_set_field_string(&v, "driverSubsystem", str);
                if (r < 0)
                        return r;
        }

        if (sd_device_get_devtype(dev, &str) >= 0) {
                r = sd_json_variant_set_field_string(&v, "type", str);
                if (r < 0)
                        return r;
        }

        if (sd_device_get_driver(dev, &str) >= 0) {
                r = sd_json_variant_set_field_string(&v, "driver", str);
                if (r < 0)
                        return r;
        }

        if (sd_device_get_devname(dev, &str) >= 0) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *node = NULL;

                r = sd_json_variant_set_field_string(&node, "path", str);
                if (r < 0)
                        return r;

                r = sd_json_variant_set_field_string(&node, "type", streq_ptr(subsys, "block") ? "block" : "char");
                if (r < 0)
                        return r;

                dev_t devnum;
                if (sd_device_get_devnum(dev, &devnum) >= 0) {
                        r = sd_json_variant_set_fieldb(&node, "rdev", JSON_BUILD_DEVNUM(devnum));
                        if (r < 0)
                                return r;
                }

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *owner = NULL;

                uid_t uid = event->uid;
                if (!uid_is_valid(uid))
                        (void) device_get_devnode_uid(dev, &uid);
                if (uid_is_valid(uid)) {
                        _cleanup_free_ char *user = uid_to_name(uid);
                        if (!user)
                                return -ENOMEM;

                        r = sd_json_variant_set_field_unsigned(&owner, "uid", uid);
                        if (r < 0)
                                return r;

                        r = sd_json_variant_set_field_string(&owner, "userName", user);
                        if (r < 0)
                                return r;
                }

                gid_t gid = event->gid;
                if (!gid_is_valid(gid))
                        (void) device_get_devnode_gid(dev, &gid);
                if (gid_is_valid(gid)) {
                        _cleanup_free_ char *group = gid_to_name(gid);
                        if (!group)
                                return -ENOMEM;

                        r = sd_json_variant_set_field_unsigned(&owner, "gid", gid);
                        if (r < 0)
                                return r;

                        r = sd_json_variant_set_field_string(&owner, "groupName", group);
                        if (r < 0)
                                return r;
                }

                r = json_variant_set_field_non_null(&node, "owner", owner);
                if (r < 0)
                        return r;

                mode_t mode = event->mode;
                if (mode == MODE_INVALID)
                        (void) device_get_devnode_mode(dev, &mode);
                if (mode != MODE_INVALID) {
                        char mode_str[STRLEN("0755")+1];
                        xsprintf(mode_str, "%04o", mode & ~S_IFMT);

                        r = sd_json_variant_set_field_string(&node, "mode", mode_str);
                        if (r < 0)
                                return r;
                }

                _cleanup_strv_free_ char **links = NULL;
                FOREACH_DEVICE_DEVLINK(dev, devlink) {
                        r = strv_extend(&links, devlink);
                        if (r < 0)
                                return r;
                }

                if (!strv_isempty(links)) {
                        int prio = 0;
                        (void) device_get_devlink_priority(dev, &prio);

                        r = sd_json_variant_set_field_integer(&node, "symlinkPriority", prio);
                        if (r < 0)
                                return r;

                        r = sd_json_variant_set_field_strv(&node, "symlinks", strv_sort(links));
                        if (r < 0)
                                return r;
                }

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *labels = NULL;
                const char *name, *label;
                ORDERED_HASHMAP_FOREACH_KEY(label, name, event->seclabel_list) {
                        r = sd_json_variant_append_arraybo(
                                        &labels,
                                        SD_JSON_BUILD_PAIR_STRING("name", name),
                                        SD_JSON_BUILD_PAIR_STRING("label", label));
                                if (r < 0)
                                        return r;
                }

                r = json_variant_set_field_non_null(&node, "securityLabels", labels);
                if (r < 0)
                        return r;

                r = sd_json_variant_set_field_boolean(&node, "inotifyWatch", event->inotify_watch);
                if (r < 0)
                        return r;

                r = json_variant_set_field_non_null(&v, "node", node);
                if (r < 0)
                        return r;
        }

        int ifindex;
        if (sd_device_get_ifindex(dev, &ifindex) >= 0) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *netif = NULL;

                r = sd_json_variant_set_field_integer(&netif, "index", ifindex);
                if (r < 0)
                        return r;

                if (!isempty(event->name)) {
                        r = sd_json_variant_set_field_string(&netif, "name", event->name);
                        if (r < 0)
                                return r;
                }

                if (!strv_isempty(event->altnames)) {
                        r = sd_json_variant_set_field_strv(&netif, "alternativeNames", strv_sort(event->altnames));
                        if (r < 0)
                                return r;
                }

                r = json_variant_set_field_non_null(&v, "networkInterface", netif);
                if (r < 0)
                        return r;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *sysattrs = NULL;
        const char *key, *value;
        HASHMAP_FOREACH_KEY(value, key, event->written_sysattrs) {
                r = sd_json_variant_append_arraybo(
                                &sysattrs,
                                SD_JSON_BUILD_PAIR_STRING("path", key),
                                SD_JSON_BUILD_PAIR_STRING("value", value));
                if (r < 0)
                        return r;
        }

        r = json_variant_set_field_non_null(&v, "sysfsAttributes", sysattrs);
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *sysctls = NULL;
        HASHMAP_FOREACH_KEY(value, key, event->written_sysctls) {
                r = sd_json_variant_append_arraybo(
                                &sysctls,
                                SD_JSON_BUILD_PAIR_STRING("path", key),
                                SD_JSON_BUILD_PAIR_STRING("value", value));
                if (r < 0)
                        return r;
        }

        r = json_variant_set_field_non_null(&v, "sysctl", sysctls);
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **tags = NULL;
        FOREACH_DEVICE_TAG(dev, tag) {
                r = strv_extend(&tags, tag);
                if (r < 0)
                        return r;
        }

        if (!strv_isempty(tags)) {
                r = sd_json_variant_set_field_strv(&v, "tags", strv_sort(tags));
                if (r < 0)
                        return r;
        }

        tags = strv_free(tags);

        FOREACH_DEVICE_CURRENT_TAG(dev, tag) {
                r = strv_extend(&tags, tag);
                if (r < 0)
                        return r;
        }

        if (!strv_isempty(tags)) {
                r = sd_json_variant_set_field_strv(&v, "currentTags", strv_sort(tags));
                if (r < 0)
                        return r;
        }

        char **properties;
        if (device_get_properties_strv(dev, &properties) >= 0 && !strv_isempty(properties)) {
                r = sd_json_variant_set_field_strv(&v, "properties", strv_sort(properties));
                if (r < 0)
                        return r;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *commands = NULL;
        void *val;
        const char *command;
        ORDERED_HASHMAP_FOREACH_KEY(val, command, event->run_list) {
                r = sd_json_variant_append_arraybo(
                                &commands,
                                SD_JSON_BUILD_PAIR_STRING("type", PTR_TO_UDEV_BUILTIN_CMD(val) >= 0 ? "builtin" : "program"),
                                SD_JSON_BUILD_PAIR_STRING("command", command));
                if (r < 0)
                        return r;
        }

        r = json_variant_set_field_non_null(&v, "queuedCommands", commands);
        if (r < 0)
                return r;

        return sd_json_variant_dump(v, flags, f, /* prefix= */ NULL);
}

int dump_event(UdevEvent *event, sd_json_format_flags_t flags, FILE *f) {
        if (sd_json_format_enabled(flags))
                return dump_event_json(event, flags, f);

        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        const char *subsys = NULL, *str;

        if (!f)
                f = stdout;

        if (sd_device_get_devpath(dev, &str) >= 0)
                fprintf(f, "%sDevice path:%s\n  %s\n", ansi_highlight(), ansi_normal(), str);

        if (sd_device_get_sysname(dev, &str) >= 0)
                fprintf(f, "%sDevice name:%s\n  %s\n", ansi_highlight(), ansi_normal(), str);

        if (sd_device_get_sysnum(dev, &str) >= 0)
                fprintf(f, "%sDevice number:%s\n  %s\n", ansi_highlight(), ansi_normal(), str);

        if (sd_device_get_device_id(dev, &str) >= 0)
                fprintf(f, "%sDevice ID:%s\n  %s\n", ansi_highlight(), ansi_normal(), str);

        if (sd_device_get_subsystem(dev, &subsys) >= 0) {
                const char *driver_subsys = NULL;
                (void) sd_device_get_driver_subsystem(dev, &driver_subsys);
                fprintf(f, "%sSubsystem:%s\n  %s%s%s%s\n", ansi_highlight(), ansi_normal(), subsys,
                        driver_subsys ? " (" : "",
                        strempty(driver_subsys),
                        driver_subsys ? ")" : "");
        }

        if (sd_device_get_devtype(dev, &str) >= 0)
                fprintf(f, "%sDevice type:%s\n  %s\n", ansi_highlight(), ansi_normal(), str);

        if (sd_device_get_driver(dev, &str) >= 0)
                fprintf(f, "%sDevice driver:%s\n  %s\n", ansi_highlight(), ansi_normal(), str);

        if (sd_device_get_devname(dev, &str) >= 0) {
                dev_t devnum;
                if (sd_device_get_devnum(dev, &devnum) >= 0)
                        fprintf(f, "%sDevice node:%s\n  %s (%s "DEVNUM_FORMAT_STR")\n", ansi_highlight(), ansi_normal(), str,
                                streq_ptr(subsys, "block") ? "block" : "char",
                                DEVNUM_FORMAT_VAL(devnum));

                uid_t uid = event->uid;
                if (!uid_is_valid(uid))
                        (void) device_get_devnode_uid(dev, &uid);
                if (uid_is_valid(uid)) {
                        _cleanup_free_ char *user = uid_to_name(uid);
                        fprintf(f, "%sDevice node owner user:%s\n  %s (uid="UID_FMT")\n", ansi_highlight(), ansi_normal(), strna(user), uid);
                }

                gid_t gid = event->gid;
                if (!gid_is_valid(gid))
                        (void) device_get_devnode_gid(dev, &gid);
                if (gid_is_valid(gid)) {
                        _cleanup_free_ char *group = gid_to_name(gid);
                        fprintf(f, "%sDevice node owner group:%s\n  %s (gid="GID_FMT")\n", ansi_highlight(), ansi_normal(), strna(group), gid);
                }

                mode_t mode = event->mode;
                if (mode == MODE_INVALID)
                        (void) device_get_devnode_mode(dev, &mode);
                if (mode != MODE_INVALID)
                        fprintf(f, "%sDevice node permission:%s\n  %04o\n", ansi_highlight(), ansi_normal(), mode);

                if (sd_device_get_devlink_first(dev)) {
                        int prio = 0;
                        (void) device_get_devlink_priority(dev, &prio);
                        fprintf(f, "%sDevice node symlinks:%s (priority=%i)\n", ansi_highlight(), ansi_normal(), prio);
                        FOREACH_DEVICE_DEVLINK(dev, devlink)
                                fprintf(f, "  %s\n", devlink);
                }

                if (!ordered_hashmap_isempty(event->seclabel_list)) {
                        const char *name, *label;
                        fprintf(f, "%sDevice node security label:%s\n", ansi_highlight(), ansi_normal());
                        ORDERED_HASHMAP_FOREACH_KEY(label, name, event->seclabel_list)
                                fprintf(f, "  %s : %s\n", name, label);
                }

                fprintf(f, "%sInotify watch:%s\n  %s\n", ansi_highlight(), ansi_normal(), enabled_disabled(event->inotify_watch));
        }

        int ifindex;
        if (sd_device_get_ifindex(dev, &ifindex) >= 0) {
                fprintf(f, "%sNetwork interface index:%s\n  %i\n", ansi_highlight(), ansi_normal(), ifindex);

                if (!isempty(event->name))
                        fprintf(f, "%sNetwork interface name:%s\n  %s\n", ansi_highlight(), ansi_normal(), event->name);

                if (!strv_isempty(event->altnames)) {
                        bool space = true;
                        fprintf(f, "%sAlternative interface names:%s", ansi_highlight(), ansi_normal());
                        fputstrv(f, strv_sort(event->altnames), "\n  ", &space);
                        fputs("\n", f);
                }
        }

        if (!hashmap_isempty(event->written_sysattrs)) {
                const char *key, *value;

                fprintf(f, "%sWritten sysfs attributes:%s\n", ansi_highlight(), ansi_normal());
                HASHMAP_FOREACH_KEY(value, key, event->written_sysattrs)
                        fprintf(f, "  %s : %s\n", key, value);
        }

        if (!hashmap_isempty(event->written_sysctls)) {
                const char *key, *value;

                fprintf(f, "%sWritten sysctl entries:%s\n", ansi_highlight(), ansi_normal());
                HASHMAP_FOREACH_KEY(value, key, event->written_sysctls)
                        fprintf(f, "  %s : %s\n", key, value);
        }

        if (sd_device_get_tag_first(dev)) {
                fprintf(f, "%sTags:%s\n", ansi_highlight(), ansi_normal());
                FOREACH_DEVICE_TAG(dev, tag)
                        fprintf(f, "  %s\n", tag);
        }

        if (sd_device_get_current_tag_first(dev)) {
                fprintf(f, "%sCurrent Tags:%s\n", ansi_highlight(), ansi_normal());
                FOREACH_DEVICE_CURRENT_TAG(dev, tag)
                        fprintf(f, "  %s\n", tag);
        }

        char **properties;
        if (device_get_properties_strv(dev, &properties) >= 0 && !strv_isempty(properties)) {
                bool space = true;
                fprintf(f, "%sProperties:%s", ansi_highlight(), ansi_normal());
                fputstrv(f, strv_sort(properties), "\n  ", &space);
                fputs("\n", f);
        }

        if (!ordered_hashmap_isempty(event->run_list)) {
                void *val;
                const char *command;
                fprintf(f, "%sQueued commands:%s\n", ansi_highlight(), ansi_normal());
                ORDERED_HASHMAP_FOREACH_KEY(val, command, event->run_list) {
                        UdevBuiltinCommand builtin_cmd = PTR_TO_UDEV_BUILTIN_CMD(val);

                        if (builtin_cmd >= 0)
                                fprintf(f, "  RUN{builtin} : %s\n", command);
                        else
                                fprintf(f, "  RUN{program} : %s\n", command);
                }
        }

        return 0;
}
