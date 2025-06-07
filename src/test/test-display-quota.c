/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bitfield.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "main-func.h"
#include "quota-util.h"
#include "strv.h"
#include "user-util.h"
#include "userdb.h"

static int show_quota(uid_t uid, const char *path) {
        int r;

        _cleanup_close_ int fd = open(path, O_DIRECTORY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open '%s': %m", path);

        struct dqblk req;
        r = quotactl_fd_with_fallback(fd, QCMD_FIXED(Q_GETQUOTA, USRQUOTA), uid, &req);
        if (r == -ESRCH) {
                log_info_errno(r, "No quota set on %s for UID "UID_FMT": %m", path, uid);
                return 0;
        }
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return log_warning_errno(r, "No UID quota support on %s: %m", path);
        if (ERRNO_IS_NEG_PRIVILEGE(r))
                return log_error_errno(r, "Lacking privileges to query UID quota on %s: %m", path);
        if (r < 0)
                return log_error_errno(r, "Failed to query disk quota on %s for UID "UID_FMT": %m", path, uid);

        printf("** Quota on %s for UID "UID_FMT" **\n"
               "block hardlimit:   %"PRIu64"\n"
               "block softlimit:   %"PRIu64"\n"
               "blocks current:    %"PRIu64"\n"
               "inodes hardlimit:  %"PRIu64"\n"
               "inodes softlimit:  %"PRIu64"\n"
               "inodes current:    %"PRIu64"\n"
               "excess block time: %"PRIu64"\n"
               "excess inode time: %"PRIu64"\n"
               "validity mask:     0x%"PRIx32,
               path, uid,
               req.dqb_bhardlimit,
               req.dqb_bsoftlimit,
               req.dqb_curspace,
               req.dqb_ihardlimit,
               req.dqb_isoftlimit,
               req.dqb_curinodes,
               req.dqb_btime,
               req.dqb_itime,
               req.dqb_valid);

        const char* fields[] = {"BLIMITS", "SPACE", "INODES", "BTIME", "ITIME"};
        bool first = true;
        for (size_t i = 0; i < ELEMENTSOF(fields); i++)
                if (BIT_SET(req.dqb_valid, i)) {
                        printf("%c%s", first ? ' ' : '|', fields[i]);
                        first = false;
                }
        printf("%s\n", first ? "(none)" : "");

        return 0;
}

static int run(int argc, char **argv) {
        int r;

        if (argc < 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program requires at least one argument\n"
                                       "syntax: test-display-quota USER PATH…");

        const char *user = argv[1];
        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        r = userdb_by_name(user, /* match= */ NULL, USERDB_PARSE_NUMERIC|USERDB_SUPPRESS_SHADOW, &ur);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve user '%s': %m", user);

        if (!uid_is_valid(ur->uid))
                return log_error_errno(SYNTHETIC_ERRNO(ENOMSG), "User '%s' lacks UID.", ur->user_name);

        r = 0;
        STRV_FOREACH(path, strv_skip(argv, 2))
                RET_GATHER(r, show_quota(ur->uid, *path));

        return r;
}

DEFINE_MAIN_FUNCTION(run);
