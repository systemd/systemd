/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <sys/stat.h>

#include "dirent-util.h"
#include "path-util.h"
#include "string-util.h"

int dirent_ensure_type(DIR *d, struct dirent *de) {
        struct stat st;

        assert(d);
        assert(de);

        if (de->d_type != DT_UNKNOWN)
                return 0;

        if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
                return -errno;

        de->d_type =
                S_ISREG(st.st_mode)  ? DT_REG  :
                S_ISDIR(st.st_mode)  ? DT_DIR  :
                S_ISLNK(st.st_mode)  ? DT_LNK  :
                S_ISFIFO(st.st_mode) ? DT_FIFO :
                S_ISSOCK(st.st_mode) ? DT_SOCK :
                S_ISCHR(st.st_mode)  ? DT_CHR  :
                S_ISBLK(st.st_mode)  ? DT_BLK  :
                                       DT_UNKNOWN;

        return 0;
}

bool dirent_is_file(const struct dirent *de) {
        assert(de);

        if (!IN_SET(de->d_type, DT_REG, DT_LNK, DT_UNKNOWN))
                return false;

        if (hidden_or_backup_file(de->d_name))
                return false;

        return true;
}

bool dirent_is_file_with_suffix(const struct dirent *de, const char *suffix) {
        assert(de);

        if (!IN_SET(de->d_type, DT_REG, DT_LNK, DT_UNKNOWN))
                return false;

        if (de->d_name[0] == '.')
                return false;

        if (!suffix)
                return true;

        return endswith(de->d_name, suffix);
}

struct dirent* readdir_no_dot(DIR *dirp) {
        struct dirent* d;

        for (;;) {
                d = readdir(dirp);
                if (d && dot_or_dot_dot(d->d_name))
                        continue;
                return d;
        }
}
