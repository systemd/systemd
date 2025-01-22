/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "ansi-color.h"
#include "device-private.h"
#include "device-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "udev-builtin.h"
#include "udev-dump.h"
#include "udev-event.h"
#include "user-util.h"

void dump_event(UdevEvent *event, FILE *f) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);

        if (!f)
                f = stdout;

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

                        if (builtin_cmd != _UDEV_BUILTIN_INVALID)
                                fprintf(f, "  RUN{builtin} : %s\n", command);
                        else
                                fprintf(f, "  RUN{program} : %s\n", command);
                }
        }
}
