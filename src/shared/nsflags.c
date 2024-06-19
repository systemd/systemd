/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "namespace-util.h"
#include "nsflags.h"
#include "string-util.h"

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

                for (i = 0; namespace_info[i].proc_name; i++)
                        if (streq(word, namespace_info[i].proc_name)) {
                                 f = namespace_info[i].clone_flag;
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

        for (i = 0; namespace_info[i].proc_name; i++) {
                if ((flags & namespace_info[i].clone_flag) != namespace_info[i].clone_flag)
                        continue;

                if (!strextend_with_separator(&s, " ", namespace_info[i].proc_name))
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(s);

        return 0;
}

const char* namespace_single_flag_to_string(unsigned long flag) {
        for (unsigned i = 0; namespace_info[i].proc_name; i++)
                if (namespace_info[i].clone_flag == flag)
                        return namespace_info[i].proc_name;

        return NULL;
}
