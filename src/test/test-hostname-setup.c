/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>
#include <sched.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(read_etc_hostname) {
        _cleanup_(unlink_tempfilep) char path[] = "/tmp/hostname.XXXXXX";
        char *hostname;
        int r;

        safe_close(ASSERT_FD(mkostemp_safe(path)));

        /* simple hostname */
        ASSERT_OK(write_string_file(path, "foo", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(read_etc_hostname(path, /* substitute_wildcards= */ false, &hostname));
        ASSERT_STREQ(hostname, "foo");
        hostname = mfree(hostname);

        /* with comment */
        ASSERT_OK(write_string_file(path, "# comment\nfoo", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(read_etc_hostname(path, /* substitute_wildcards= */ false, &hostname));
        ASSERT_NOT_NULL(hostname);
        ASSERT_STREQ(hostname, "foo");
        hostname = mfree(hostname);

        /* with comment and extra whitespace */
        ASSERT_OK(write_string_file(path, "# comment\n\n foo ", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(read_etc_hostname(path, /* substitute_wildcards= */ false, &hostname));
        ASSERT_NOT_NULL(hostname);
        ASSERT_STREQ(hostname, "foo");
        hostname = mfree(hostname);

        /* cleans up name */
        ASSERT_OK(write_string_file(path, "!foo/bar.com", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(read_etc_hostname(path, /* substitute_wildcards= */ false, &hostname));
        ASSERT_NOT_NULL(hostname);
        ASSERT_STREQ(hostname, "foobar.com");
        hostname = mfree(hostname);

        /* with wildcards */
        ASSERT_OK(write_string_file(path, "foo????????x??????????u", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(read_etc_hostname(path, /* substitute_wildcards= */ false, &hostname));
        ASSERT_NOT_NULL(hostname);
        ASSERT_STREQ(hostname, "foo????????x??????????u");
        hostname = mfree(hostname);
        r = read_etc_hostname(path, /* substitute_wildcards= */ true, &hostname);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r))
                log_tests_skipped("skipping wildcard hostname tests, no machine ID defined");
        else {
                ASSERT_OK(r);
                ASSERT_NOT_NULL(hostname);
                ASSERT_NULL(strchr(hostname, '?'));
                ASSERT_EQ(fnmatch("foo????????x??????????u", hostname, /* flags= */ 0), 0);
                ASSERT_TRUE(hostname_is_valid(hostname, /* flags= */ 0));
                hostname = mfree(hostname);
        }

        /* no value set */
        hostname = (char*) 0x1234;
        ASSERT_OK(write_string_file(path, "# nothing here\n", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE));
        ASSERT_ERROR(read_etc_hostname(path, /* substitute_wildcards= */ false, &hostname), ENOENT);
        assert(hostname == (char*) 0x1234);  /* does not touch argument on error */

        /* nonexisting file */
        ASSERT_ERROR(read_etc_hostname("/non/existing", /* substitute_wildcards= */ false, &hostname), ENOENT);
        assert(hostname == (char*) 0x1234);  /* does not touch argument on error */
}

TEST(hostname_substitute_wildcards) {
        int r;

        r = sd_id128_get_machine(NULL);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r))
                return (void) log_tests_skipped_errno(r, "skipping wildcard hostname tests, no machine ID defined");

        _cleanup_free_ char *buf = NULL;
        ASSERT_OK(hostname_substitute_wildcards("", &buf));
        ASSERT_STREQ(buf, "");
        ASSERT_NULL(buf = mfree(buf));

        ASSERT_OK(hostname_substitute_wildcards("hogehoge", &buf));
        ASSERT_STREQ(buf, "hogehoge");
        ASSERT_NULL(buf = mfree(buf));

        ASSERT_OK(hostname_substitute_wildcards("hoge??hoge??foo?", &buf));
        log_debug("hostname_substitute_wildcards(\"hoge??hoge??foo?\"): → \"%s\"", buf);
        ASSERT_EQ(fnmatch("hoge??hoge??foo?", buf, /* flags= */ 0), 0);
        ASSERT_TRUE(hostname_is_valid(buf, /* flags= */ 0));
        ASSERT_NULL(buf = mfree(buf));
}

TEST(hostname_substitute_wildcards_words) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        int r;

        r = sd_id128_get_machine(NULL);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r))
                return (void) log_tests_skipped_errno(r, "skipping word hostname tests, no machine ID defined");

        ASSERT_OK(mkdtemp_malloc("/tmp/hostname-wordlist.XXXXXX", &d));

        /* The n-th '$' reads the word list file named after its position. */
        _cleanup_free_ char *one_list = ASSERT_PTR(path_join(d, "1"));
        _cleanup_free_ char *two_list = ASSERT_PTR(path_join(d, "2"));
        ASSERT_OK(write_string_file(one_list, "happy\nsad\n# comment\n\njolly\n", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file(two_list, "octopus\nfalcon\nINVALID_WORD!\nbadger\n", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(setenv("SYSTEMD_HOSTNAME_WORDLIST_PATH", d, /* overwrite= */ true));

        _cleanup_free_ char *a = NULL, *b = NULL;
        ASSERT_OK(hostname_substitute_wildcards("$-$", &a));
        log_debug("hostname_substitute_wildcards(\"$-$\"): → \"%s\"", a);
        ASSERT_TRUE(hostname_is_valid(a, /* flags= */ 0));

        /* Fully deterministic: same machine ID + same lists → same name */
        ASSERT_OK(hostname_substitute_wildcards("$-$", &b));
        ASSERT_STREQ(a, b);

        /* Missing list (no file "3") → error (caller falls back to built-in hostname) */
        _cleanup_free_ char *e = NULL;
        ASSERT_ERROR(hostname_substitute_wildcards("$-$-$", &e), ENOENT);

        ASSERT_OK(unsetenv("SYSTEMD_HOSTNAME_WORDLIST_PATH"));
}

TEST(hostname_setup_rederive_default) {
        int r;

        /* hostname_setup() only re-derives the hostname if it is the default we recorded ourselves
         * earlier. Check that we do so in that case, and leave the hostname alone in every other. */

        if (geteuid() != 0)
                return (void) log_tests_skipped("Not privileged");

        r = sd_id128_get_machine(NULL);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r))
                return (void) log_tests_skipped_errno(r, "skipping re-derive hostname tests, no machine ID defined");

        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        ASSERT_OK(mkdtemp_malloc("/tmp/hostname-hint.XXXXXX", &d));

        _cleanup_free_ char *hint = ASSERT_PTR(path_join(d, "default-hostname"));
        ASSERT_OK(setenv("SYSTEMD_RUN_DEFAULT_HOSTNAME_PATH", hint, /* overwrite= */ true));
        ASSERT_OK(setenv("SYSTEMD_DEFAULT_HOSTNAME", "test-????", /* overwrite= */ true));
        ASSERT_OK(setenv("SYSTEMD_PROC_CMDLINE", "", /* overwrite= */ true));

        /* We apply the hostname for real, so do it in a UTS namespace of our own. */
        r = ASSERT_OK(pidref_safe_fork("(test-rederive)", FORK_LOG|FORK_WAIT|FORK_DEATHSIG_SIGKILL, /* ret= */ NULL));
        if (r == 0) {
                _cleanup_free_ char *h = NULL;

                ASSERT_OK_ERRNO(unshare(CLONE_NEWUTS));

                /* No hint at all: the hostname is not ours, leave it alone. */
                ASSERT_OK(sethostname_idempotent("no-hint"));
                ASSERT_OK(hostname_setup(/* really= */ true));
                ASSERT_NOT_NULL(h = gethostname_malloc());
                ASSERT_STREQ(h, "no-hint");
                h = mfree(h);

                /* Hint holds some other name: somebody else set the current one, leave it alone. */
                ASSERT_OK(write_string_file(hint, "some-other-name", WRITE_STRING_FILE_CREATE));
                ASSERT_OK(sethostname_idempotent("stale-hint"));
                ASSERT_OK(hostname_setup(/* really= */ true));
                ASSERT_NOT_NULL(h = gethostname_malloc());
                ASSERT_STREQ(h, "stale-hint");
                h = mfree(h);

                /* Hint matches the current hostname: it is the default we set earlier, re-derive it. */
                ASSERT_OK(sethostname_idempotent("ours-dead"));
                ASSERT_OK(write_string_file(hint, "ours-dead", WRITE_STRING_FILE_CREATE));
                ASSERT_OK(hostname_setup(/* really= */ true));
                ASSERT_NOT_NULL(h = gethostname_malloc());
                ASSERT_EQ(fnmatch("test-????", h, /* flags= */ 0), 0);

                /* ... and the hint is updated to the name we just applied. */
                _cleanup_free_ char *recorded = NULL;
                ASSERT_OK(read_one_line_file(hint, &recorded));
                ASSERT_STREQ(recorded, h);

                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(unsetenv("SYSTEMD_PROC_CMDLINE"));
        ASSERT_OK(unsetenv("SYSTEMD_DEFAULT_HOSTNAME"));
        ASSERT_OK(unsetenv("SYSTEMD_RUN_DEFAULT_HOSTNAME_PATH"));
}

TEST(hostname_setup_cmdline_wildcards) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        int r;

        r = sd_id128_get_machine(NULL);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r))
                return (void) log_tests_skipped_errno(r, "skipping cmdline wildcard hostname tests, no machine ID defined");

        ASSERT_OK(mkdtemp_malloc("/tmp/hostname-wordlist.XXXXXX", &d));
        ASSERT_OK(setenv("SYSTEMD_PROC_CMDLINE", "systemd.hostname=$-????", /* overwrite= */ true));
        ASSERT_OK(setenv("SYSTEMD_HOSTNAME_WORDLIST_PATH", d, /* overwrite= */ true));

        /* Word list missing (as e.g. in the initrd): the kernel command line hostname is ignored and the
         * usual fallback logic applies, hostname_setup() must still succeed. */
        ASSERT_OK(hostname_setup(/* really= */ false));

        /* Word list present: hostname_setup() now exercises the cmdline expansion path and must still
         * succeed. With really=false nothing is applied and the resolved name is not surfaced, so the
         * concrete expansion is asserted separately in the hostname_substitute_wildcards test above. */
        _cleanup_free_ char *one_list = ASSERT_PTR(path_join(d, "1"));
        ASSERT_OK(write_string_file(one_list, "happy\nsad\n", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(hostname_setup(/* really= */ false));

        ASSERT_OK(unsetenv("SYSTEMD_PROC_CMDLINE"));
        ASSERT_OK(unsetenv("SYSTEMD_HOSTNAME_WORDLIST_PATH"));
}

TEST(hostname_setup) {
        hostname_setup(false);
}

TEST(hostname_malloc) {
        _cleanup_free_ char *h = NULL, *l = NULL;

        assert_se(h = gethostname_malloc());
        log_info("hostname_malloc: \"%s\"", h);

        assert_se(l = gethostname_short_malloc());
        log_info("hostname_short_malloc: \"%s\"", l);
}

TEST(default_hostname) {
        if (!hostname_is_valid(FALLBACK_HOSTNAME, 0)) {
                log_error("Configured fallback hostname \"%s\" is not valid.", FALLBACK_HOSTNAME);
                exit(EXIT_FAILURE);
        }

        _cleanup_free_ char *n = get_default_hostname_or_fallback();
        ASSERT_NOT_NULL(n);
        log_info("get_default_hostname_or_fallback: \"%s\"", n);
        ASSERT_TRUE(hostname_is_valid(n, /* flags= */ 0));

        _cleanup_free_ char *m = get_default_hostname_raw();
        ASSERT_NOT_NULL(m);
        log_info("get_default_hostname_raw: \"%s\"", m);
        ASSERT_TRUE(hostname_is_valid(m, VALID_HOSTNAME_QUESTION_MARK));
}

TEST(pidref_gethostname_full) {
        int r;

        if (geteuid() != 0)
                return (void) log_tests_skipped("Not privileged");

        _cleanup_free_ char *original = NULL, *original_short = NULL;
        ASSERT_NOT_NULL(original = gethostname_malloc());
        ASSERT_NOT_NULL(original_short = gethostname_short_malloc());

        _cleanup_close_pair_ int fds[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(fds, O_CLOEXEC));

        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork("(test-pidref-gethostname)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL, &pidref);
        ASSERT_OK(r);
        if (r == 0) {
                fds[0] = safe_close(fds[0]);

                ASSERT_OK_ERRNO(unshare(CLONE_NEWUTS));
                ASSERT_OK(sethostname_idempotent("hogehoge.example.com"));

                ASSERT_OK_EQ_ERRNO(write(fds[1], &(const char[]) { 'x' }, 1), 1);
                freeze();
        }

        fds[1] = safe_close(fds[1]);

        char x;
        ASSERT_OK_EQ_ERRNO(read(fds[0], &x, 1), 1);
        ASSERT_EQ(x, 'x');

        _cleanup_free_ char *s = NULL;
        ASSERT_OK(pidref_gethostname_full(&pidref, /* flags= */ 0, &s));
        ASSERT_STREQ(s, "hogehoge.example.com");

        s = mfree(s);

        ASSERT_OK(pidref_gethostname_full(&pidref, GET_HOSTNAME_SHORT, &s));
        ASSERT_STREQ(s, "hogehoge");

        s = mfree(s);

        _cleanup_(pidref_done) PidRef self = PIDREF_NULL;
        ASSERT_OK(pidref_set_self(&self));

        ASSERT_OK(pidref_gethostname_full(&self, /* flags= */ 0, &s));
        ASSERT_STREQ(s, original);

        s = mfree(s);

        ASSERT_OK(pidref_gethostname_full(&self, GET_HOSTNAME_SHORT, &s));
        ASSERT_STREQ(s, original_short);

        s = mfree(s);

        ASSERT_NOT_NULL(s = gethostname_malloc());
        ASSERT_STREQ(s, original);

        s = mfree(s);

        ASSERT_NOT_NULL(s = gethostname_short_malloc());
        ASSERT_STREQ(s, original_short);
}

static int intro(void) {
        /* hostname_setup() consults /etc/hostname before falling back to the default hostname, so point it
         * at a path that does not exist: otherwise which branch these tests take depends on whether the host
         * running them happens to have that file. */
        ASSERT_OK(setenv("SYSTEMD_ETC_HOSTNAME", "/tmp/test-hostname-setup-no-such-file", /* overwrite= */ true));

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
