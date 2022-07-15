/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "generator.h"
#include "log.h"
#include "mkdir-label.h"
#include "string-util.h"
#include "util.h"

static const char *arg_dest = NULL;

/* So you are reading this, and might wonder: why is this implemented as a generator rather than as a plain, statically
 * enabled service that carries appropriate ConditionFileIsExecutable= lines? The answer is this: conditions bypass
 * execution of a service's binary, but they have no influence on unit dependencies. Thus, a service that is
 * conditioned out will still act as synchronization point in the dependency tree, and we'd rather not have that for
 * these two legacy scripts. */

static int add_symlink(const char *service, const char *where) {
        const char *from, *to;

        assert(service);
        assert(where);

        from = strjoina(SYSTEM_DATA_UNIT_DIR "/", service);
        to = strjoina(arg_dest, "/", where, ".wants/", service);

        (void) mkdir_parents_label(to, 0755);

        if (symlink(from, to) < 0) {
                if (errno == EEXIST)
                        return 0;

                return log_error_errno(errno, "Failed to create symlink %s: %m", to);
        }

        return 1;
}

static int check_executable(const char *path) {
        assert(path);

        if (access(path, X_OK) < 0) {
                if (errno == ENOENT)
                        return log_debug_errno(errno, "%s does not exist, skipping.", path);
                if (errno == EACCES)
                        return log_info_errno(errno, "%s is not marked executable, skipping.", path);

                return log_warning_errno(errno, "Couldn't determine if %s exists and is executable, skipping: %m", path);
        }

        return 0;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r = 0, k = 0;

        assert_se(arg_dest = dest);

        if (check_executable(RC_LOCAL_PATH) >= 0) {
                log_debug("Automatically adding rc-local.service.");

                r = add_symlink("rc-local.service", "multi-user.target");
        }

        return r < 0 ? r : k;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
