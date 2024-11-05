/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "namespace-util.h"
#include "nsflags.h"
#include "string-util.h"
#include "strv.h"

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
        _cleanup_strv_free_ char **l = NULL;

        l = namespace_flags_to_strv(flags);
        if (!l)
                return -ENOMEM;

        char *s = strv_join(l, NULL);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

const char* namespace_single_flag_to_string(unsigned long flag) {
        for (unsigned i = 0; namespace_info[i].proc_name; i++)
                if (namespace_info[i].clone_flag == flag)
                        return namespace_info[i].proc_name;

        return NULL;
}

char** namespace_flags_to_strv(unsigned long flags) {
        _cleanup_strv_free_ char **s = NULL;
        unsigned i;

        for (i = 0; namespace_info[i].proc_name; i++) {
                if ((flags & namespace_info[i].clone_flag) != namespace_info[i].clone_flag)
                        continue;

                if (strv_extend(&s, namespace_info[i].proc_name) < 0)
                        return NULL;
        }

        return s ? TAKE_PTR(s) : strv_new(NULL);
}
