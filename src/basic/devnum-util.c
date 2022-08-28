/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <sys/stat.h>

#include "chase-symlinks.h"
#include "devnum-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"

int parse_devnum(const char *s, dev_t *ret) {
        const char *major;
        unsigned x, y;
        size_t n;
        int r;

        n = strspn(s, DIGITS);
        if (n == 0)
                return -EINVAL;
        if (n > DECIMAL_STR_MAX(dev_t))
                return -EINVAL;
        if (s[n] != ':')
                return -EINVAL;

        major = strndupa_safe(s, n);
        r = safe_atou(major, &x);
        if (r < 0)
                return r;

        r = safe_atou(s + n + 1, &y);
        if (r < 0)
                return r;

        if (!DEVICE_MAJOR_VALID(x) || !DEVICE_MINOR_VALID(y))
                return -ERANGE;

        *ret = makedev(x, y);
        return 0;
}

int device_path_make_major_minor(mode_t mode, dev_t devnum, char **ret) {
        const char *t;

        /* Generates the /dev/{char|block}/MAJOR:MINOR path for a dev_t */

        if (S_ISCHR(mode))
                t = "char";
        else if (S_ISBLK(mode))
                t = "block";
        else
                return -ENODEV;

        if (asprintf(ret, "/dev/%s/" DEVNUM_FORMAT_STR, t, DEVNUM_FORMAT_VAL(devnum)) < 0)
                return -ENOMEM;

        return 0;
}

int device_path_make_inaccessible(mode_t mode, char **ret) {
        char *s;

        assert(ret);

        if (S_ISCHR(mode))
                s = strdup("/run/systemd/inaccessible/chr");
        else if (S_ISBLK(mode))
                s = strdup("/run/systemd/inaccessible/blk");
        else
                return -ENODEV;
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

int device_path_make_canonical(mode_t mode, dev_t devnum, char **ret) {
        _cleanup_free_ char *p = NULL;
        int r;

        /* Finds the canonical path for a device, i.e. resolves the /dev/{char|block}/MAJOR:MINOR path to the end. */

        assert(ret);

        if (major(devnum) == 0 && minor(devnum) == 0)
                /* A special hack to make sure our 'inaccessible' device nodes work. They won't have symlinks in
                 * /dev/block/ and /dev/char/, hence we handle them specially here. */
                return device_path_make_inaccessible(mode, ret);

        r = device_path_make_major_minor(mode, devnum, &p);
        if (r < 0)
                return r;

        return chase_symlinks(p, NULL, 0, ret, NULL);
}

int device_path_parse_major_minor(const char *path, mode_t *ret_mode, dev_t *ret_devnum) {
        mode_t mode;
        dev_t devnum;
        int r;

        /* Tries to extract the major/minor directly from the device path if we can. Handles /dev/block/ and /dev/char/
         * paths, as well out synthetic inaccessible device nodes. Never goes to disk. Returns -ENODEV if the device
         * path cannot be parsed like this.  */

        if (path_equal(path, "/run/systemd/inaccessible/chr")) {
                mode = S_IFCHR;
                devnum = makedev(0, 0);
        } else if (path_equal(path, "/run/systemd/inaccessible/blk")) {
                mode = S_IFBLK;
                devnum = makedev(0, 0);
        } else {
                const char *w;

                w = path_startswith(path, "/dev/block/");
                if (w)
                        mode = S_IFBLK;
                else {
                        w = path_startswith(path, "/dev/char/");
                        if (!w)
                                return -ENODEV;

                        mode = S_IFCHR;
                }

                r = parse_devnum(w, &devnum);
                if (r < 0)
                        return r;
        }

        if (ret_mode)
                *ret_mode = mode;
        if (ret_devnum)
                *ret_devnum = devnum;

        return 0;
}
