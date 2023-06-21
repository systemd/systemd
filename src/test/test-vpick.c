/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "vpick.h"

TEST(path_pick) {
        _cleanup_(rm_rf_physical_and_freep) char *p = NULL;
        _cleanup_close_ int dfd = -EBADF, sub_dfd = -EBADF;

        dfd = mkdtemp_open(NULL, O_DIRECTORY|O_CLOEXEC, &p);
        assert(dfd >= 0);

        sub_dfd = open_mkdir_at(dfd, "foo.v", O_CLOEXEC, 0777);
        assert(sub_dfd >= 0);

        assert_se(write_string_file_at(sub_dfd, "foo_5.5.raw", "5.5", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_55.raw", "55", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_5.raw", "5", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_5_ia64.raw", "5", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_7.raw", "7", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_7_x86-64.raw", "7 64bit", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_55_x86-64.raw", "55 64bit", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_55_x86.raw", "55 32bit", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(write_string_file_at(sub_dfd, "foo_99_x86.raw", "99 32bit", WRITE_STRING_FILE_CREATE) >= 0);

        /* Let's add an entry for sparc (which is a valid arch, but almost certainly not what we test
         * on). This entry should hence always be ignored */
        if (native_architecture() != ARCHITECTURE_SPARC)
                assert_se(write_string_file_at(sub_dfd, "foo_100_sparc.raw", "100 sparc", WRITE_STRING_FILE_CREATE) >= 0);

        _cleanup_free_ char *pp = NULL, *rp = NULL, *rv = NULL;
        Architecture ra;
        mode_t rm;

        pp = path_join(p, "foo.v");
        assert_se(pp);

        if (IN_SET(native_architecture(), ARCHITECTURE_X86, ARCHITECTURE_X86_64)) {

                assert_se(path_pick(NULL, AT_FDCWD, pp, MODE_INVALID, NULL, NULL, _ARCHITECTURE_INVALID, ".raw", &rp, NULL, &rm, &rv, &ra) > 0);
                assert_se(S_ISREG(rm));
                assert_se(streq_ptr(rv, "99"));
                assert_se(ra == ARCHITECTURE_X86);
                assert_se(endswith(rp, "/foo_99_x86.raw"));
                rp = mfree(rp);
                rv = mfree(rv);
        }

        assert_se(path_pick(NULL, AT_FDCWD, pp, MODE_INVALID, NULL, NULL, ARCHITECTURE_X86_64, ".raw", &rp, NULL, &rm, &rv, &ra) > 0);
        assert_se(S_ISREG(rm));
        assert_se(streq_ptr(rv, "55"));
        assert_se(ra == ARCHITECTURE_X86_64);
        assert_se(endswith(rp, "/foo_55_x86-64.raw"));
        rp = mfree(rp);
        rv = mfree(rv);

        assert_se(path_pick(NULL, AT_FDCWD, pp, MODE_INVALID, NULL, NULL, ARCHITECTURE_IA64, ".raw", &rp, NULL, &rm, &rv, &ra) > 0);
        assert_se(S_ISREG(rm));
        assert_se(streq_ptr(rv, "5"));
        assert_se(ra == ARCHITECTURE_IA64);
        assert_se(endswith(rp, "/foo_5_ia64.raw"));
        rp = mfree(rp);
        rv = mfree(rv);

        assert_se(path_pick(NULL, AT_FDCWD, pp, MODE_INVALID, NULL, "5", _ARCHITECTURE_INVALID, ".raw", &rp, NULL, &rm, &rv, &ra) > 0);
        assert_se(S_ISREG(rm));
        assert_se(streq_ptr(rv, "5"));
        if (native_architecture() != ARCHITECTURE_IA64) {
                assert_se(ra == _ARCHITECTURE_INVALID);
                assert_se(endswith(rp, "/foo_5.raw"));
        }
        rp = mfree(rp);
        rv = mfree(rv);

        assert_se(path_pick(NULL, AT_FDCWD, pp, MODE_INVALID, NULL, "5", ARCHITECTURE_IA64, ".raw", &rp, NULL, &rm, &rv, &ra) > 0);
        assert_se(S_ISREG(rm));
        assert_se(streq_ptr(rv, "5"));
        assert_se(ra == ARCHITECTURE_IA64);
        assert_se(endswith(rp, "/foo_5_ia64.raw"));
        rp = mfree(rp);
        rv = mfree(rv);

        assert_se(path_pick(NULL, AT_FDCWD, pp, MODE_INVALID, NULL, "5", ARCHITECTURE_CRIS, ".raw", &rp, NULL, &rm, &rv, &ra) == 0);
        assert_se(rm == MODE_INVALID);
        assert_se(!rv);
        assert_se(ra < 0);
        assert_se(!rp);

        assert_se(unlinkat(sub_dfd, "foo_99_x86.raw", 0) >= 0);

        if (IN_SET(native_architecture(), ARCHITECTURE_X86_64, ARCHITECTURE_X86)) {
                assert_se(path_pick(NULL, AT_FDCWD, pp, MODE_INVALID, NULL, NULL, _ARCHITECTURE_INVALID, ".raw", &rp, NULL, &rm, &rv, &ra) > 0);
                assert_se(S_ISREG(rm));
                assert_se(streq_ptr(rv, "55"));

                if (native_architecture() == ARCHITECTURE_X86_64) {
                        assert_se(ra == ARCHITECTURE_X86_64);
                        assert_se(endswith(rp, "/foo_55_x86-64.raw"));
                } else {
                        assert_se(ra == ARCHITECTURE_X86);
                        assert_se(endswith(rp, "/foo_55_x86.raw"));
                }

                rp = mfree(rp);
                rv = mfree(rv);
        }

        /* Test explicit patterns in last component of path not being .v */
        free(pp);
        pp = path_join(p, "foo.v/foo___.raw");
        assert_se(pp);

        if (IN_SET(native_architecture(), ARCHITECTURE_X86, ARCHITECTURE_X86_64)) {
                assert_se(path_pick(NULL, AT_FDCWD, pp, MODE_INVALID, NULL, NULL, _ARCHITECTURE_INVALID, ".raw", &rp, NULL, &rm, &rv, &ra) > 0);
                assert_se(S_ISREG(rm));
                assert_se(streq_ptr(rv, "55"));
                assert_se(ra == native_architecture());
                assert_se(endswith(rp, ".raw"));
                assert_se(strrstr(rp, "/foo_55_x86"));
                rp = mfree(rp);
                rv = mfree(rv);
        }

        /* Now test patterns in last component of path being .v */
        assert_se(symlinkat("foo.v", dfd, "foo___.raw.v") >= 0);
        free(pp);
        pp = path_join(p, "foo___.raw.v");
        assert_se(pp);

        if (IN_SET(native_architecture(), ARCHITECTURE_X86, ARCHITECTURE_X86_64)) {
                assert_se(path_pick(NULL, AT_FDCWD, pp, MODE_INVALID, NULL, NULL, _ARCHITECTURE_INVALID, ".raw", &rp, NULL, &rm, &rv, &ra) > 0);
                assert_se(S_ISREG(rm));
                assert_se(streq_ptr(rv, "55"));
                assert_se(ra == native_architecture());
                assert_se(endswith(rp, ".raw"));
                assert_se(strrstr(rp, "/foo_55_x86"));
                rp = mfree(rp);
                rv = mfree(rv);
        }

        /* Pattern refers ot a dir, but we ask for a regular file */
        free(pp);
        pp = path_join(p, "foo.v/foo___.raw/");
        assert_se(pp);

        assert_se(path_pick(NULL, AT_FDCWD, pp, S_IFREG, NULL, NULL, _ARCHITECTURE_INVALID, ".raw", &rp, NULL, &rm, &rv, &ra) == -EISDIR);

        /* Specify an explicit path */
        free(pp);
        pp = path_join(p, "foo.v/foo_5.raw");
        assert_se(pp);
        assert_se(path_pick(NULL, AT_FDCWD, pp, S_IFDIR, NULL, NULL, _ARCHITECTURE_INVALID, ".raw", &rp, NULL, &rm, &rv, &ra) == -ENOTDIR);
        assert_se(path_pick(NULL, AT_FDCWD, pp, S_IFREG, NULL, NULL, _ARCHITECTURE_INVALID, ".raw", &rp, NULL, &rm, &rv, &ra) > 0);
        assert_se(S_ISREG(rm));
        assert_se(!rv);
        assert_se(ra == _ARCHITECTURE_INVALID);
        assert_se(path_equal(rp, pp));

}

DEFINE_TEST_MAIN(LOG_DEBUG);
