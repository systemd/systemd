/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "ansi-color.h"
#include "device-private.h"
#include "device-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "json-util.h"
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
        int r;

        if (!hashmap_isempty(event->written_sysattrs)) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
                const char *key, *value;

                HASHMAP_FOREACH_KEY(value, key, event->written_sysattrs) {
                        r = sd_json_variant_append_arraybo(
                                        &w,
                                        SD_JSON_BUILD_PAIR_STRING("path", key),
                                        SD_JSON_BUILD_PAIR_STRING("value", value));
                        if (r < 0)
                                return r;
                }

                r = json_variant_set_field_non_null(&v, "sysfsAttributes", w);
                if (r < 0)
                        return r;
        }

        if (!hashmap_isempty(event->written_sysctls)) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
                const char *key, *value;

                HASHMAP_FOREACH_KEY(value, key, event->written_sysctls) {
                        r = sd_json_variant_append_arraybo(
                                        &w,
                                        SD_JSON_BUILD_PAIR_STRING("path", key),
                                        SD_JSON_BUILD_PAIR_STRING("value", value));
                        if (r < 0)
                                return r;
                }

                r = json_variant_set_field_non_null(&v, "sysctl", w);
                if (r < 0)
                        return r;
        }

        _cleanup_strv_free_ char **props = NULL;
        FOREACH_DEVICE_PROPERTY(dev, key, value) {
                r = strv_extendf(&props, "%s=%s", key, value);
                if (r < 0)
                        return r;
        }

        r = sd_json_variant_set_field_strv(&v, "properties", strv_sort(props));
        if (r < 0)
                return r;

        if (sd_device_get_tag_first(dev)) {
                _cleanup_strv_free_ char **tags = NULL;
                FOREACH_DEVICE_TAG(dev, tag) {
                        r = strv_extend(&tags, tag);
                        if (r < 0)
                                return r;
                }

                r = sd_json_variant_set_field_strv(&v, "tags", strv_sort(tags));
                if (r < 0)
                        return r;
        }

        if (sd_device_get_devnum(dev, NULL) >= 0) {

                if (sd_device_get_devlink_first(dev)) {
                        _cleanup_strv_free_ char **links = NULL;
                        int prio = 0;
                        (void) device_get_devlink_priority(dev, &prio);

                        FOREACH_DEVICE_DEVLINK(dev, devlink) {
                                r = strv_extend(&links, devlink);
                                if (r < 0)
                                        return r;
                        }

                        r = sd_json_variant_set_field_strv(&v, "symlinks", strv_sort(links));
                        if (r < 0)
                                return r;
                }

                r = sd_json_variant_merge_objectbo(
                                &v,
                                SD_JSON_BUILD_PAIR_BOOLEAN("inotifyWatch", event->inotify_watch));
                if (r < 0)
                        return r;

                uid_t uid = event->uid;
                if (!uid_is_valid(uid))
                        (void) device_get_devnode_uid(dev, &uid);
                if (uid_is_valid(uid)) {
                        _cleanup_free_ char *user = uid_to_name(uid);
                        if (!user)
                                return -ENOMEM;

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
                        r = sd_json_buildo(
                                        &w,
                                        SD_JSON_BUILD_PAIR_UNSIGNED("uid", uid),
                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("name", user));
                        if (r < 0)
                                return r;

                        r = json_variant_set_field_non_null(&v, "owner", w);
                        if (r < 0)
                                return r;
                }

                gid_t gid = event->gid;
                if (!gid_is_valid(uid))
                        (void) device_get_devnode_gid(dev, &gid);
                if (gid_is_valid(gid)) {
                        _cleanup_free_ char *group = gid_to_name(gid);
                        if (!group)
                                return -ENOMEM;

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
                        r = sd_json_buildo(
                                        &w,
                                        SD_JSON_BUILD_PAIR_UNSIGNED("gid", gid),
                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("name", group));
                        if (r < 0)
                                return r;

                        r = json_variant_set_field_non_null(&v, "group", w);
                        if (r < 0)
                                return r;
                }

                mode_t mode = event->mode;
                if (mode == MODE_INVALID)
                        (void) device_get_devnode_mode(dev, &mode);
                if (mode != MODE_INVALID) {
                        r = sd_json_variant_merge_objectbo(
                                        &v,
                                        SD_JSON_BUILD_PAIR_UNSIGNED("mode", mode));
                        if (r < 0)
                                return r;
                }

                if (!ordered_hashmap_isempty(event->seclabel_list)) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
                        const char *name, *label;

                        ORDERED_HASHMAP_FOREACH_KEY(label, name, event->seclabel_list) {
                                r = sd_json_variant_append_arraybo(
                                                &w,
                                                SD_JSON_BUILD_PAIR_STRING("name", name),
                                                SD_JSON_BUILD_PAIR_STRING("label", label));
                                if (r < 0)
                                        return r;
                        }

                        r = json_variant_set_field_non_null(&v, "securityLabels", w);
                        if (r < 0)
                                return r;
                }
        }

        if (sd_device_get_ifindex(dev, NULL) >= 0) {
                r = sd_json_variant_merge_objectbo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("interfaceName", event->name),
                                JSON_BUILD_PAIR_STRV_NON_EMPTY("alternativeInterfaceNames", strv_sort(event->altnames)));
                if (r < 0)
                        return r;
        }

        if (!ordered_hashmap_isempty(event->run_list)) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
                void *val;
                const char *command;

                ORDERED_HASHMAP_FOREACH_KEY(val, command, event->run_list) {
                        r = sd_json_variant_append_arraybo(
                                        &w,
                                        SD_JSON_BUILD_PAIR_STRING("type", PTR_TO_UDEV_BUILTIN_CMD(val) >= 0 ? "builtin" : "program"),
                                        SD_JSON_BUILD_PAIR_STRING("command", command));
                        if (r < 0)
                                return r;
                }

                r = json_variant_set_field_non_null(&v, "queuedCommands", w);
                if (r < 0)
                        return r;
        }

        return sd_json_variant_dump(v, flags, f, /* prefix = */ NULL);
}

int dump_event(UdevEvent *event, sd_json_format_flags_t flags, FILE *f) {
        if (sd_json_format_enabled(flags))
                return dump_event_json(event, flags, f);

        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);

        if (!f)
                f = stdout;

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

        fprintf(f, "%sProperties:%s\n", ansi_highlight(), ansi_normal());
        FOREACH_DEVICE_PROPERTY(dev, key, value)
                fprintf(f, "  %s=%s\n", key, value);

        if (sd_device_get_tag_first(dev)) {
                fprintf(f, "%sTags:%s\n", ansi_highlight(), ansi_normal());
                FOREACH_DEVICE_TAG(dev, tag)
                        fprintf(f, "  %s\n", tag);
        }

        if (sd_device_get_devnum(dev, NULL) >= 0) {

                if (sd_device_get_devlink_first(dev)) {
                        int prio = 0;
                        (void) device_get_devlink_priority(dev, &prio);
                        fprintf(f, "%sDevice node symlinks:%s (priority=%i)\n", ansi_highlight(), ansi_normal(), prio);
                        FOREACH_DEVICE_DEVLINK(dev, devlink)
                                fprintf(f, "  %s\n", devlink);
                }

                fprintf(f, "%sInotify watch:%s\n  %s\n", ansi_highlight(), ansi_normal(), enabled_disabled(event->inotify_watch));

                uid_t uid = event->uid;
                if (!uid_is_valid(uid))
                        (void) device_get_devnode_uid(dev, &uid);
                if (uid_is_valid(uid)) {
                        _cleanup_free_ char *user = uid_to_name(uid);
                        fprintf(f, "%sDevice node owner:%s\n  %s (uid="UID_FMT")\n", ansi_highlight(), ansi_normal(), strna(user), uid);
                }

                gid_t gid = event->gid;
                if (!gid_is_valid(uid))
                        (void) device_get_devnode_gid(dev, &gid);
                if (gid_is_valid(gid)) {
                        _cleanup_free_ char *group = gid_to_name(gid);
                        fprintf(f, "%sDevice node group:%s\n  %s (gid="GID_FMT")\n", ansi_highlight(), ansi_normal(), strna(group), gid);
                }

                mode_t mode = event->mode;
                if (mode == MODE_INVALID)
                        (void) device_get_devnode_mode(dev, &mode);
                if (mode != MODE_INVALID)
                        fprintf(f, "%sDevice node permission:%s\n  %04o\n", ansi_highlight(), ansi_normal(), mode);

                if (!ordered_hashmap_isempty(event->seclabel_list)) {
                        const char *name, *label;
                        fprintf(f, "%sDevice node security label:%s\n", ansi_highlight(), ansi_normal());
                        ORDERED_HASHMAP_FOREACH_KEY(label, name, event->seclabel_list)
                                fprintf(f, "  %s : %s\n", name, label);
                }
        }

        if (sd_device_get_ifindex(dev, NULL) >= 0) {
                if (!isempty(event->name))
                        fprintf(f, "%sNetwork interface name:%s\n  %s\n", ansi_highlight(), ansi_normal(), event->name);

                if (!strv_isempty(event->altnames)) {
                        bool space = true;
                        fprintf(f, "%sAlternative interface names:%s", ansi_highlight(), ansi_normal());
                        fputstrv(f, event->altnames, "\n  ", &space);
                        fputs("\n", f);
                }
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
