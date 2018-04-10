/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering
***/

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

const char* namespace_flag_to_string(unsigned long flag) {
        unsigned i;

        flag &= NAMESPACE_FLAGS_ALL;

        for (i = 0; namespace_flag_map[i].name; i++)
                if (flag == namespace_flag_map[i].flag)
                        return namespace_flag_map[i].name;

        return NULL; /* either unknown namespace flag, or a combination of many. This call supports neither. */
}

unsigned long namespace_flag_from_string(const char *name) {
        unsigned i;

        if (isempty(name))
                return 0;

        for (i = 0; namespace_flag_map[i].name; i++)
                if (streq(name, namespace_flag_map[i].name))
                        return namespace_flag_map[i].flag;

        return 0;
}

int namespace_flag_from_string_many(const char *name, unsigned long *ret) {
        unsigned long flags = 0;
        int r;

        assert_se(ret);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                unsigned long f;

                r = extract_first_word(&name, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                f = namespace_flag_from_string(word);
                if (f == 0)
                        return -EINVAL;

                flags |= f;
        }

        *ret = flags;
        return 0;
}

int namespace_flag_to_string_many(unsigned long flags, char **ret) {
        _cleanup_free_ char *s = NULL;
        unsigned i;

        for (i = 0; namespace_flag_map[i].name; i++) {
                if ((flags & namespace_flag_map[i].flag) != namespace_flag_map[i].flag)
                        continue;

                if (!s) {
                        s = strdup(namespace_flag_map[i].name);
                        if (!s)
                                return -ENOMEM;
                } else {
                        if (!strextend(&s, " ", namespace_flag_map[i].name, NULL))
                                return -ENOMEM;
                }
        }

        if (!s) {
                s = strdup("");
                if (!s)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(s);

        return 0;
}
