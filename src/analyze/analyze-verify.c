/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-verify.h"
#include "analyze-verify-util.h"
#include "copy.h"
#include "rm-rf.h"
#include "tmpfile-util.h"

static int process_aliases(char *argv[], char *tempdir, char ***ret) {
        _cleanup_strv_free_ char **filenames = NULL;
        int r;

        assert(argv);
        assert(tempdir);
        assert(ret);

        STRV_FOREACH(filename, strv_skip(argv, 1)) {
                _cleanup_free_ char *src = NULL, *dst = NULL, *base = NULL;
                const char *parse_arg;

                parse_arg = *filename;
                r = extract_first_word(&parse_arg, &src, ":", EXTRACT_DONT_COALESCE_SEPARATORS|EXTRACT_RETAIN_ESCAPE);
                if (r < 0)
                        return r;

                if (!parse_arg) {
                        r = strv_consume(&filenames, TAKE_PTR(src));
                        if (r < 0)
                                return r;

                        continue;
                }

                r = path_extract_filename(parse_arg, &base);
                if (r < 0)
                        return r;

                dst = path_join(tempdir, base);
                if (!dst)
                        return -ENOMEM;

                r = copy_file(src, dst, 0, 0644, 0, 0, COPY_REFLINK);
                if (r < 0)
                        return r;

                r = strv_consume(&filenames, TAKE_PTR(dst));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(filenames);
        return 0;
}

int verb_verify(int argc, char *argv[], void *userdata) {
        _cleanup_strv_free_ char **filenames = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *tempdir = NULL;
        int r;

        r = mkdtemp_malloc("/tmp/systemd-analyze-XXXXXX", &tempdir);
        if (r < 0)
                return log_error_errno(r, "Failed to setup working directory: %m");

        r = process_aliases(argv, tempdir, &filenames);
        if (r < 0)
                return log_error_errno(r, "Couldn't process aliases: %m");

        return verify_units(filenames, arg_runtime_scope, arg_man, arg_generators, arg_recursive_errors, arg_root);
}
