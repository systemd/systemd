/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ftw.h>

#include "fd-util.h"
#include "log.h"
#include "missing_magic.h"
#include "recurse-dir.h"
#include "stat-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

static char **list_nftw = NULL;

static int nftw_cb(
                const char *fpath,
                const struct stat *sb,
                int typeflag,
                struct FTW *ftwbuf) {

        if (ftwbuf->level == 0) /* skip top-level */
                return FTW_CONTINUE;

        switch (typeflag) {

        case FTW_F:
                log_debug("ftw found %s", fpath);
                assert_se(strv_extend(&list_nftw, fpath) >= 0);
                break;

        case FTW_SL:
                log_debug("ftw found symlink %s, ignoring.", fpath);
                break;

        case FTW_D:
                log_debug("ftw entering %s", fpath);
                assert_se(strv_extendf(&list_nftw, "%s/", fpath) >= 0);
                break;

        case FTW_DNR:
                log_debug("ftw open directory failed %s", fpath);
                break;

        case FTW_NS:
                log_debug("ftw stat inode failed %s", fpath);
                break;

        case FTW_DP:
        case FTW_SLN:
        default:
                assert_not_reached();
        }

        return FTW_CONTINUE;
}

static int recurse_dir_callback(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        char ***l = userdata;

        assert_se(path);
        assert_se(de);

        switch (event) {

        case RECURSE_DIR_ENTRY:
                assert_se(!IN_SET(de->d_type, DT_UNKNOWN, DT_DIR));

                log_debug("found %s%s", path,
                          de->d_type == DT_LNK ? ", ignoring." : "");

                if (de->d_type != DT_LNK)
                        assert_se(strv_extend(l, path) >= 0);
                break;

        case RECURSE_DIR_ENTER:
                assert_se(de->d_type == DT_DIR);

                log_debug("entering %s", path);
                assert_se(strv_extendf(l, "%s/", path) >= 0);
                break;

        case RECURSE_DIR_LEAVE:
                log_debug("leaving %s", path);
                break;

        case RECURSE_DIR_SKIP_MOUNT:
                log_debug("skipping mount %s", path);
                break;

        case RECURSE_DIR_SKIP_DEPTH:
                log_debug("skipping depth %s", path);
                break;

        case RECURSE_DIR_SKIP_OPEN_DIR_ERROR_BASE...RECURSE_DIR_SKIP_OPEN_DIR_ERROR_MAX:
                log_debug_errno(event - RECURSE_DIR_SKIP_OPEN_DIR_ERROR_BASE, "failed to open dir %s: %m", path);
                break;

        case RECURSE_DIR_SKIP_OPEN_INODE_ERROR_BASE...RECURSE_DIR_SKIP_OPEN_INODE_ERROR_MAX:
                log_debug_errno(event - RECURSE_DIR_SKIP_OPEN_INODE_ERROR_BASE, "failed to open inode %s: %m", path);
                break;

        case RECURSE_DIR_SKIP_STAT_INODE_ERROR_BASE...RECURSE_DIR_SKIP_STAT_INODE_ERROR_MAX:
                log_debug_errno(event - RECURSE_DIR_SKIP_STAT_INODE_ERROR_BASE, "failed to stat inode %s: %m", path);
                break;

        default:
                assert_not_reached();
        }

        return RECURSE_DIR_CONTINUE;
}

int main(int argc, char *argv[]) {
        _cleanup_strv_free_ char **list_recurse_dir = NULL;
        const char *p;
        usec_t t1, t2, t3, t4;
        _cleanup_close_ int fd = -EBADF;

        log_show_color(true);
        test_setup_logging(LOG_INFO);

        if (argc > 1)
                p = argv[1];
        else
                p = "/usr/share/man"; /* something hopefully reasonably stable while we run (and limited in size) */

        fd = open(p, O_DIRECTORY|O_CLOEXEC);
        if (fd < 0 && errno == ENOENT)
                return log_tests_skipped_errno(errno, "Couldn't open directory %s", p);
        assert_se(fd >= 0);

        /* If the test directory is on an overlayfs then files and their directory may return different
         * st_dev in stat results, which confuses nftw into thinking they're on different filesystems and
         * won't return the result when the FTW_MOUNT flag is set. */
        if (fd_is_fs_type(fd, OVERLAYFS_SUPER_MAGIC))
                return log_tests_skipped("nftw mountpoint detection produces false-positives on overlayfs");

        /* Enumerate the specified dirs in full, once via nftw(), and once via recurse_dir(), and ensure the
         * results are identical. nftw() sometimes skips symlinks (see
         * https://github.com/systemd/systemd/issues/29603), so ignore them to avoid bogus errors. */

        t1 = now(CLOCK_MONOTONIC);
        assert_se(recurse_dir(fd, p, 0, UINT_MAX, RECURSE_DIR_SORT|RECURSE_DIR_ENSURE_TYPE|RECURSE_DIR_SAME_MOUNT, recurse_dir_callback, &list_recurse_dir) >= 0);
        t2 = now(CLOCK_MONOTONIC);

        t3 = now(CLOCK_MONOTONIC);
        assert_se(nftw(p, nftw_cb, 64, FTW_PHYS|FTW_MOUNT) >= 0);
        t4 = now(CLOCK_MONOTONIC);

        log_info("recurse_dir(): %s – nftw(): %s", FORMAT_TIMESPAN(t2 - t1, 1), FORMAT_TIMESPAN(t4 - t3, 1));

        strv_sort(list_recurse_dir);
        strv_sort(list_nftw);

        for (size_t i = 0;; i++) {
                const char *a = list_nftw ? list_nftw[i] : NULL,
                        *b = list_recurse_dir ? list_recurse_dir[i] : NULL;

                if (!streq_ptr(a, b)) {
                        log_error("entry %zu different: %s vs %s", i, strna(a), strna(b));
                        assert_not_reached();
                }

                if (!a)
                        break;
        }

        list_nftw = strv_free(list_nftw);
        return 0;
}
