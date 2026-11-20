/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>
#include <sys/vfs.h>

#include "alloc-util.h"
#include "binfmt-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "stat-util.h"
#include "string-table.h"

int binfmt_mounted_and_writable(void) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        fd = xopenat(AT_FDCWD, "/proc/sys/fs/binfmt_misc", O_DIRECTORY | O_PATH);
        if (fd == -ENOENT)
                return false;
        /* ELOOP happens when binfmt_misc is an automount point under a read-only bind mount of /proc —
         * the kernel cannot trigger the automount and returns ELOOP instead. Common in mock/Koji buildroots. */
        if (fd == -ELOOP || ERRNO_IS_NEG_PRIVILEGE(fd)) {
                log_debug_errno(fd, "Failed to open /proc/sys/fs/binfmt_misc, ignoring: %m");
                return false;
        }
        if (fd < 0)
                return fd;

        r = fd_is_fs_type(fd, BINFMTFS_MAGIC);
        if (r <= 0)
                return r;

        r = access_fd(fd, W_OK);
        if (ERRNO_IS_NEG_FS_WRITE_REFUSED(r))
                return false;
        if (r < 0)
                return r;

        return true;
}

int disable_binfmt(void) {
        int r;

        /* Flush out all rules. This is important during shutdown to cover for rules using "F", since those
         * might pin a file and thus block us from unmounting stuff cleanly.
         *
         * We are a bit careful here, since binfmt_misc might still be an autofs which we don't want to
         * trigger. */

        r = binfmt_mounted_and_writable();
        if (r < 0)
                return log_warning_errno(r, "Failed to determine whether binfmt_misc is mounted: %m");
        if (r == 0) {
                log_debug("binfmt_misc is not mounted in read-write mode, not detaching entries.");
                return 0;
        }

        r = write_string_file("/proc/sys/fs/binfmt_misc/status", "-1", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_warning_errno(r, "Failed to unregister binfmt_misc entries: %m");

        log_debug("Unregistered all remaining binfmt_misc entries.");
        return 0;
}

void binfmt_rule_done(BinfmtRule *rule) {
        assert(rule);

        rule->buffer = mfree(rule->buffer);
}

static const char* const binfmt_rule_type_table[_BINFMT_RULE_TYPE_MAX] = {
        [BINFMT_RULE_MAGIC]     = "M",
        [BINFMT_RULE_EXTENSION] = "E",
        [BINFMT_RULE_BPF]       = "B",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(binfmt_rule_type, BinfmtRuleType);

int binfmt_rule_parse(const char *s, BinfmtRule *ret) {
        enum {
                FIELD_NAME,
                FIELD_TYPE,
                FIELD_OFFSET,
                FIELD_MAGIC,
                FIELD_MASK,
                FIELD_INTERPRETER,
                _FIELD_MAX,
        };
        _cleanup_free_ char *buffer = NULL;
        const char *fields[_FIELD_MAX];
        BinfmtRuleType type;
        char *p;

        assert(s);
        assert(ret);

        /* The first character of the rule is the delimiter of its fields. */
        if (s[0] == 0)
                return -EINVAL;

        buffer = strdup(s + 1);
        if (!buffer)
                return -ENOMEM;

        /* Split the fields like create_entry() in the kernel's fs/binfmt_misc.c does. A field missing at
         * the end of the rule is left empty here, the kernel refuses such a rule when it is written. The
         * flags field is not looked at. */
        p = buffer;
        for (size_t i = 0; i < _FIELD_MAX; i++) {
                fields[i] = p;

                p += strcspn(p, CHAR_TO_STR(s[0]));
                if (*p != 0)
                        *(p++) = 0;
        }

        /* An unknown type is not an error here, the kernel refuses the rule when it is written. As in the
         * kernel, the interpreter field of a bpf-backed rule carries the name of its handler instead. */
        type = binfmt_rule_type_from_string(fields[FIELD_TYPE]);

        *ret = (BinfmtRule) {
                .buffer = TAKE_PTR(buffer),
                .name = fields[FIELD_NAME],
                .type = type,
                .interpreter = type == BINFMT_RULE_BPF ? NULL : fields[FIELD_INTERPRETER],
                .bpf_handler = type == BINFMT_RULE_BPF ? fields[FIELD_INTERPRETER] : NULL,
        };
        return 0;
}
