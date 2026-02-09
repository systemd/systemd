/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "bootctl.h"
#include "bootctl-cleanup.h"
#include "bootctl-unlink.h"
#include "bootctl-util.h"
#include "bootspec.h"
#include "bootspec-util.h"
#include "chase.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "log.h"
#include "path-util.h"
#include "recurse-dir.h"

static int list_remove_orphaned_file(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        Hashmap *known_files = userdata;

        assert(path);

        if (event != RECURSE_DIR_ENTRY)
                return RECURSE_DIR_CONTINUE;

        if (hashmap_get(known_files, path))
                return RECURSE_DIR_CONTINUE; /* keep! */

        if (arg_dry_run)
                log_info("Would remove %s", path);
        else if (unlinkat(dir_fd, de->d_name, 0) < 0)
                log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                               "Failed to remove \"%s\", ignoring: %m", path);
        else
                log_info("Removed %s", path);

        return RECURSE_DIR_CONTINUE;
}

static int cleanup_orphaned_files(
                const BootConfig *config,
                const char *root) {

        _cleanup_hashmap_free_ Hashmap *known_files = NULL;
        _cleanup_free_ char *full = NULL, *p = NULL;
        _cleanup_close_ int dir_fd = -EBADF;
        int r;

        assert(config);
        assert(root);

        log_info("Cleaning %s", root);

        r = settle_entry_token();
        if (r < 0)
                return r;

        r = boot_config_count_known_files(config, root, &known_files);
        if (r < 0)
                return log_error_errno(r, "Failed to count files in %s: %m", root);

        dir_fd = chase_and_open(arg_entry_token, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_TRIGGER_AUTOFS,
                        O_DIRECTORY|O_CLOEXEC, &full);
        if (dir_fd == -ENOENT)
                return 0;
        if (dir_fd < 0)
                return log_error_errno(dir_fd, "Failed to open '%s/%s': %m", root, skip_leading_slash(arg_entry_token));

        p = path_join("/", arg_entry_token);
        if (!p)
                return log_oom();

        r = recurse_dir(dir_fd, p, 0, UINT_MAX, RECURSE_DIR_SORT, list_remove_orphaned_file, known_files);
        if (r < 0)
                return log_error_errno(r, "Failed to cleanup %s: %m", full);

        return r;
}

int verb_cleanup(int argc, char *argv[], void *userdata) {
        dev_t esp_devid = 0, xbootldr_devid = 0;
        int r;

        r = acquire_esp(/* unprivileged_mode= */ false,
                        /* graceful= */ false,
                        /* ret_part= */ NULL,
                        /* ret_pstart= */ NULL,
                        /* ret_psize= */ NULL,
                        /* ret_uuid= */ NULL,
                        &esp_devid);
        if (r == -EACCES) /* We really need the ESP path for this call, hence also log about access errors */
                return log_error_errno(r, "Failed to determine ESP location: %m");
        if (r < 0)
                return r;

        r = acquire_xbootldr(
                        /* unprivileged_mode= */ false,
                        /* ret_uuid= */ NULL,
                        &xbootldr_devid);
        if (r == -EACCES)
                return log_error_errno(r, "Failed to determine XBOOTLDR partition: %m");
        if (r < 0)
                return r;

        _cleanup_(boot_config_free) BootConfig config = BOOT_CONFIG_NULL;
        r = boot_config_load_and_select(&config, arg_esp_path, esp_devid, arg_xbootldr_path, xbootldr_devid);
        if (r < 0)
                return r;

        r = 0;
        RET_GATHER(r, cleanup_orphaned_files(&config, arg_esp_path));

        if (arg_xbootldr_path && xbootldr_devid != esp_devid)
                RET_GATHER(r, cleanup_orphaned_files(&config, arg_xbootldr_path));

        return r;
}
