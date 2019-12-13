/* SPDX-License-Identifier: LGPL-2.1+ */

#include <ftw.h>

#include "kbd-util.h"
#include "log.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

static thread_local Set *keymaps = NULL;

static int nftw_cb(
                const char *fpath,
                const struct stat *sb,
                int tflag,
                struct FTW *ftwbuf) {

        _cleanup_free_ char *p = NULL;
        char *e;
        int r;

        if (tflag != FTW_F)
                return 0;

        if (!endswith(fpath, ".map") &&
            !endswith(fpath, ".map.gz"))
                return 0;

        p = strdup(basename(fpath));
        if (!p)
                return FTW_STOP;

        e = endswith(p, ".map");
        if (e)
                *e = 0;

        e = endswith(p, ".map.gz");
        if (e)
                *e = 0;

        if (!keymap_is_valid(p))
                return 0;

        r = set_consume(keymaps, TAKE_PTR(p));
        if (r < 0 && r != -EEXIST)
                return r;

        return 0;
}

int get_keymaps(char ***ret) {
        _cleanup_strv_free_ char **l = NULL;
        const char *dir;
        int r;

        keymaps = set_new(&string_hash_ops);
        if (!keymaps)
                return -ENOMEM;

        NULSTR_FOREACH(dir, KBD_KEYMAP_DIRS) {
                r = nftw(dir, nftw_cb, 20, FTW_PHYS|FTW_ACTIONRETVAL);

                if (r == FTW_STOP)
                        log_debug("Directory not found %s", dir);
                else if (r < 0)
                        log_debug_errno(r, "Can't add keymap: %m");
        }

        l = set_get_strv(keymaps);
        if (!l) {
                set_free_free(keymaps);
                return -ENOMEM;
        }

        set_free(keymaps);

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
