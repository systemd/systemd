/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sched.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "nsflags.h"
#include "string-util.h"

const struct namespace_flag_map namespace_flag_map[] = {
        { CLONE_NEWCGROUP, "cgroup" },
        { CLONE_NEWIPC,    "ipc"    },
        { CLONE_NEWNET,    "net"    },
        /* So, the mount namespace flag is called CLONE_NEWNS for historical reasons. Let's expose it here under a more
         * explanatory name: "mnt". This is in-line with how the kernel exposes namespaces in /proc/$PID/ns. */
        { CLONE_NEWNS,     "mnt"    },
        { CLONE_NEWPID,    "pid"    },
        { CLONE_NEWUSER,   "user"   },
        { CLONE_NEWUTS,    "uts"    },
        {}
};

int namespace_flags_from_string(const char *name, unsigned long *ret) {
        unsigned long flags = 0;
        int r;

        assert_se(ret);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                unsigned long f = 0;
                unsigned i;

                r = extract_first_word(&name, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                for (i = 0; namespace_flag_map[i].name; i++)
                        if (streq(word, namespace_flag_map[i].name)) {
                                 f = namespace_flag_map[i].flag;
                                 break;
                        }

                if (f == 0)
                        return -EINVAL;

                flags |= f;
        }

        *ret = flags;
        return 0;
}

int namespace_flags_to_string(unsigned long flags, char **ret) {
        _cleanup_free_ char *s = NULL;
        unsigned i;

        for (i = 0; namespace_flag_map[i].name; i++) {
                if ((flags & namespace_flag_map[i].flag) != namespace_flag_map[i].flag)
                        continue;

                if (!strextend_with_separator(&s, " ", namespace_flag_map[i].name, NULL))
                        return -ENOMEM;
        }

        if (!s) {
                s = strdup("");
                if (!s)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(s);

        return 0;
}
