/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fs-util.h"
#include "json.h"
#include "userns-util.h"
#include "user-util.h"
#include "format-util.h"

int userns_open_registry_fd(void) {
        int fd;

        fd = open_mkdirp_at(AT_FDCWD, "/run/systemd/userdbd/registry", O_CLOEXEC|O_NOFOLLOW, 0755);
        if (fd < 0)
                return log_debug_errno(fd, "Failed to open registry dir: %m");

        return fd;
}

UserNamespaceInfo *userns_info_free(UserNamespaceInfo *userns) {
        if (!userns)
                return NULL;

        free(userns->name);

        return mfree(userns);
}

static int userns_load_json(int dir_fd, const char *fn, UserNamespaceInfo **ret) {

        static const JsonDispatch dispatch_table[] = {
                { "name",   JSON_VARIANT_STRING,   json_dispatch_string,   offsetof(UserNamespaceInfo, name),         JSON_MANDATORY },
                { "userns", JSON_VARIANT_UNSIGNED, json_dispatch_uint64,   offsetof(UserNamespaceInfo, userns_inode), JSON_MANDATORY },
                { "start",  JSON_VARIANT_UNSIGNED, json_dispatch_uid_gid,  offsetof(UserNamespaceInfo, start),        0              },
                { "size",   JSON_VARIANT_UNSIGNED, json_dispatch_uint32,   offsetof(UserNamespaceInfo, size),         0              },
                { "target", JSON_VARIANT_UNSIGNED, json_dispatch_uid_gid,  offsetof(UserNamespaceInfo, target),       0              },
                {}
        };

        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_close_ int registry_fd = -EBADF;
        int r;

        if (dir_fd < 0) {
                registry_fd = userns_open_registry_fd();
                if (registry_fd < 0)
                        return registry_fd;

                dir_fd = registry_fd;
        }

        r = json_parse_file_at(NULL, dir_fd, fn, 0, &v, NULL, NULL);
        if (r < 0)
                return r;

        userns_info = new(UserNamespaceInfo, 1);
        if (!userns_info)
                return -ENOMEM;

        *userns_info = (UserNamespaceInfo) {
                .start = UID_INVALID,
                .target = UID_INVALID,
        };

        r = json_dispatch(v, dispatch_table, 0, userns_info);
        if (r < 0)
                return r;

        if (userns_info->userns_inode == 0)
                return -EBADMSG;
        if (userns_info->start == 0)
                return -EBADMSG;
        if (userns_info->size == 0) {
                if (uid_is_valid(userns_info->start) || uid_is_valid(userns_info->target))
                        return -EBADMSG;
        } else {
                if (!uid_is_valid(userns_info->start) || !uid_is_valid(userns_info->target))
                        return -EBADMSG;

                if (userns_info->size > UINT32_MAX - userns_info->start ||
                    userns_info->size > UINT32_MAX - userns_info->target)
                        return -EBADMSG;
        }

        if (ret)
                *ret = TAKE_PTR(userns_info);
        return 0;
}

int userns_load_json_by_start_uid(int dir_fd, uid_t start, UserNamespaceInfo **ret) {
        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        _cleanup_free_ char *fn = NULL;
        int r;

        if (!uid_is_valid(start))
                return -ENOENT;

        if (asprintf(&fn, "u" UID_FMT ".userns", start) < 0)
                return -ENOMEM;

        r = userns_load_json(dir_fd, fn, &userns_info);
        if (r < 0)
                return r;

        if (userns_info->start != start)
                return -EBADMSG;

        if (ret)
                *ret = TAKE_PTR(userns_info);

        return 0;
}

int userns_load_json_by_userns_inode(int dir_fd, uint64_t inode, UserNamespaceInfo **ret) {
        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        _cleanup_free_ char *fn = NULL;
        int r;

        if (inode == 0)
                return -ENOENT;

        if (asprintf(&fn, "n%" PRIu64 ".userns", inode) < 0)
                return -ENOMEM;

        r = userns_load_json(dir_fd, fn, &userns_info);
        if (r < 0)
                return r;

        if (userns_info->userns_inode != inode)
                return -EBADMSG;

        if (ret)
                *ret = TAKE_PTR(userns_info);

        return 0;
}
