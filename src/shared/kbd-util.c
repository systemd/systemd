/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "kbd-util.h"
#include "log.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

struct recurse_dir_userdata {
        const char *keymap_name;
        Set *keymaps;
};

static int keymap_recurse_dir_callback(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        struct recurse_dir_userdata *data = userdata;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(de);

        /* If 'keymap_name' is non-NULL, return true if keymap 'keymap_name' is found.  Otherwise, add all
         * keymaps to 'keymaps'. */

        if (event != RECURSE_DIR_ENTRY)
                return RECURSE_DIR_CONTINUE;

        if (!IN_SET(de->d_type, DT_REG, DT_LNK))
                return RECURSE_DIR_CONTINUE;

        const char *e = endswith(de->d_name, ".map") ?: endswith(de->d_name, ".map.gz");
        if (!e)
                return RECURSE_DIR_CONTINUE;

        p = strndup(de->d_name, e - de->d_name);
        if (!p)
                return -ENOMEM;

        if (data->keymap_name)
                return streq(p, data->keymap_name) ? 1 : RECURSE_DIR_CONTINUE;

        assert(data->keymaps);

        if (!keymap_is_valid(p))
                return 0;

        r = set_consume(data->keymaps, TAKE_PTR(p));
        if (r < 0)
                return r;

        return RECURSE_DIR_CONTINUE;
}

int get_keymaps(char ***ret) {
        _cleanup_(set_free_freep) Set *keymaps = NULL;
        int r;

        keymaps = set_new(&string_hash_ops);
        if (!keymaps)
                return -ENOMEM;

        const char *dir;
        NULSTR_FOREACH(dir, KBD_KEYMAP_DIRS) {
                r = recurse_dir_at(
                                AT_FDCWD,
                                dir,
                                /* statx_mask= */ 0,
                                /* n_depth_max= */ UINT_MAX,
                                RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE,
                                keymap_recurse_dir_callback,
                                &(struct recurse_dir_userdata) {
                                        .keymaps = keymaps,
                                });
                if (r < 0) {
                        if (r == -ENOENT)
                                continue;
                        if (ERRNO_IS_RESOURCE(r))
                                return log_warning_errno(r, "Failed to read keymap list from %s: %m", dir);

                        log_debug_errno(r, "Failed to read keymap list from %s, ignoring: %m", dir);
                }
        }

        _cleanup_strv_free_ char **l = set_get_strv(keymaps);
        if (!l)
                return -ENOMEM;

        keymaps = set_free(keymaps); /* If we got the strv above, then do a set_free() rather than
                                      * set_free_free() since the entries of the set are now owned by the
                                      * strv */

        if (strv_isempty(l))
                return -ENOENT;

        strv_sort(l);

        *ret = TAKE_PTR(l);
        return 0;
}

bool keymap_is_valid(const char *name) {
        if (isempty(name))
                return false;

        if (strlen(name) >= 128)
                return false;

        if (!utf8_is_valid(name))
                return false;

        if (!filename_is_valid(name))
                return false;

        if (!string_is_safe(name))
                return false;

        return true;
}

int keymap_exists(const char *name) {
        int r = 0;

        if (!keymap_is_valid(name))
                return -EINVAL;

        const char *dir;
        NULSTR_FOREACH(dir, KBD_KEYMAP_DIRS) {
                r = recurse_dir_at(
                                AT_FDCWD,
                                dir,
                                /* statx_mask= */ 0,
                                /* n_depth_max= */ UINT_MAX,
                                RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_ENSURE_TYPE,
                                keymap_recurse_dir_callback,
                                &(struct recurse_dir_userdata) {
                                        .keymap_name = name,
                                });
                if (r == -ENOENT)
                        continue;
                if (ERRNO_IS_RESOURCE(r))
                        return r;
                if (r < 0) {
                        log_debug_errno(r, "Failed to read keymap list from %s, ignoring: %m", dir);
                        continue;
                }
                if (r > 0)
                        break;
        }

        return r > 0;
}
