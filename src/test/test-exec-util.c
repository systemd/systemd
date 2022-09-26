/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "alloc-util.h"
#include "copy.h"
#include "def.h"
#include "env-util.h"
#include "exec-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

static int here = 0, here2 = 0, here3 = 0;
static void *ignore_stdout_args[] = { &here, &here2, &here3 };

/* noop handlers, just check that arguments are passed correctly */
static int ignore_stdout_func(int fd, void *arg) {
        assert_se(fd >= 0);
        assert_se(arg == &here);
        safe_close(fd);

        return 0;
}
static int ignore_stdout_func2(int fd, void *arg) {
        assert_se(fd >= 0);
        assert_se(arg == &here2);
        safe_close(fd);

        return 0;
}
static int ignore_stdout_func3(int fd, void *arg) {
        assert_se(fd >= 0);
        assert_se(arg == &here3);
        safe_close(fd);

        return 0;
}

static const gather_stdout_callback_t ignore_stdout[] = {
        ignore_stdout_func,
        ignore_stdout_func2,
        ignore_stdout_func3,
};

static void test_execute_directory_one(bool gather_stdout) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp_lo = NULL, *tmp_hi = NULL;
        const char *name, *name2, *name3,
                *overridden, *override,
                *masked, *mask,
                *masked2, *mask2,   /* the mask is non-executable */
                *masked2e, *mask2e; /* the mask is executable */

        log_info("/* %s (%s) */", __func__, gather_stdout ? "gathering stdout" : "asynchronous");

        assert_se(mkdtemp_malloc("/tmp/test-exec-util.lo.XXXXXXX", &tmp_lo) >= 0);
        assert_se(mkdtemp_malloc("/tmp/test-exec-util.hi.XXXXXXX", &tmp_hi) >= 0);

        const char * dirs[] = { tmp_hi, tmp_lo, NULL };

        name = strjoina(tmp_lo, "/script");
        name2 = strjoina(tmp_hi, "/script2");
        name3 = strjoina(tmp_lo, "/useless");
        overridden = strjoina(tmp_lo, "/overridden");
        override = strjoina(tmp_hi, "/overridden");
        masked = strjoina(tmp_lo, "/masked");
        mask = strjoina(tmp_hi, "/masked");
        masked2 = strjoina(tmp_lo, "/masked2");
        mask2 = strjoina(tmp_hi, "/masked2");
        masked2e = strjoina(tmp_lo, "/masked2e");
        mask2e = strjoina(tmp_hi, "/masked2e");

        assert_se(write_string_file(name,
                                    "#!/bin/sh\necho 'Executing '$0\ntouch $(dirname $0)/it_works",
                                    WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(name2,
                                    "#!/bin/sh\necho 'Executing '$0\ntouch $(dirname $0)/it_works2",
                                    WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(overridden,
                                    "#!/bin/sh\necho 'Executing '$0\ntouch $(dirname $0)/failed",
                                    WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(override,
                                    "#!/bin/sh\necho 'Executing '$0",
                                    WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(masked,
                                    "#!/bin/sh\necho 'Executing '$0\ntouch $(dirname $0)/failed",
                                    WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(masked2,
                                    "#!/bin/sh\necho 'Executing '$0\ntouch $(dirname $0)/failed",
                                    WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(masked2e,
                                    "#!/bin/sh\necho 'Executing '$0\ntouch $(dirname $0)/failed",
                                    WRITE_STRING_FILE_CREATE) == 0);
        assert_se(symlink("/dev/null", mask) == 0);
        assert_se(touch(mask2) == 0);
        assert_se(touch(mask2e) == 0);
        assert_se(touch(name3) >= 0);

        assert_se(chmod(name, 0755) == 0);
        assert_se(chmod(name2, 0755) == 0);
        assert_se(chmod(overridden, 0755) == 0);
        assert_se(chmod(override, 0755) == 0);
        assert_se(chmod(masked, 0755) == 0);
        assert_se(chmod(masked2, 0755) == 0);
        assert_se(chmod(masked2e, 0755) == 0);
        assert_se(chmod(mask2e, 0755) == 0);

        if (access(name, X_OK) < 0 && ERRNO_IS_PRIVILEGE(errno))
                return;

        if (gather_stdout)
                execute_directories(dirs, DEFAULT_TIMEOUT_USEC, ignore_stdout, ignore_stdout_args, NULL, NULL, EXEC_DIR_PARALLEL | EXEC_DIR_IGNORE_ERRORS);
        else
                execute_directories(dirs, DEFAULT_TIMEOUT_USEC, NULL, NULL, NULL, NULL, EXEC_DIR_PARALLEL | EXEC_DIR_IGNORE_ERRORS);

        assert_se(chdir(tmp_lo) == 0);
        assert_se(access("it_works", F_OK) >= 0);
        assert_se(access("failed", F_OK) < 0);

        assert_se(chdir(tmp_hi) == 0);
        assert_se(access("it_works2", F_OK) >= 0);
        assert_se(access("failed", F_OK) < 0);
}

TEST(execute_directory) {
        test_execute_directory_one(true);
        test_execute_directory_one(false);
}

TEST(execution_order) {
        _cleanup_(rm_rf_physical_and_freep) char *tmp_lo = NULL, *tmp_hi = NULL;
        const char *name, *name2, *name3, *overridden, *override, *masked, *mask;
        const char *output, *t;
        _cleanup_free_ char *contents = NULL;

        assert_se(mkdtemp_malloc("/tmp/test-exec-util-lo.XXXXXXX", &tmp_lo) >= 0);
        assert_se(mkdtemp_malloc("/tmp/test-exec-util-hi.XXXXXXX", &tmp_hi) >= 0);

        const char *dirs[] = { tmp_hi, tmp_lo, NULL };

        output = strjoina(tmp_hi, "/output");

        log_info("/* %s >>%s */", __func__, output);

        /* write files in "random" order */
        name2 = strjoina(tmp_lo, "/90-bar");
        name = strjoina(tmp_hi, "/80-foo");
        name3 = strjoina(tmp_lo, "/last");
        overridden = strjoina(tmp_lo, "/30-override");
        override = strjoina(tmp_hi, "/30-override");
        masked = strjoina(tmp_lo, "/10-masked");
        mask = strjoina(tmp_hi, "/10-masked");

        t = strjoina("#!/bin/sh\necho $(basename $0) >>", output);
        assert_se(write_string_file(name, t, WRITE_STRING_FILE_CREATE) == 0);

        t = strjoina("#!/bin/sh\necho $(basename $0) >>", output);
        assert_se(write_string_file(name2, t, WRITE_STRING_FILE_CREATE) == 0);

        t = strjoina("#!/bin/sh\necho $(basename $0) >>", output);
        assert_se(write_string_file(name3, t, WRITE_STRING_FILE_CREATE) == 0);

        t = strjoina("#!/bin/sh\necho OVERRIDDEN >>", output);
        assert_se(write_string_file(overridden, t, WRITE_STRING_FILE_CREATE) == 0);

        t = strjoina("#!/bin/sh\necho $(basename $0) >>", output);
        assert_se(write_string_file(override, t, WRITE_STRING_FILE_CREATE) == 0);

        t = strjoina("#!/bin/sh\necho MASKED >>", output);
        assert_se(write_string_file(masked, t, WRITE_STRING_FILE_CREATE) == 0);

        assert_se(symlink("/dev/null", mask) == 0);

        assert_se(chmod(name, 0755) == 0);
        assert_se(chmod(name2, 0755) == 0);
        assert_se(chmod(name3, 0755) == 0);
        assert_se(chmod(overridden, 0755) == 0);
        assert_se(chmod(override, 0755) == 0);
        assert_se(chmod(masked, 0755) == 0);

        if (access(name, X_OK) < 0 && ERRNO_IS_PRIVILEGE(errno))
                return;

        execute_directories(dirs, DEFAULT_TIMEOUT_USEC, ignore_stdout, ignore_stdout_args, NULL, NULL, EXEC_DIR_PARALLEL | EXEC_DIR_IGNORE_ERRORS);

        assert_se(read_full_file(output, &contents, NULL) >= 0);
        assert_se(streq(contents, "30-override\n80-foo\n90-bar\nlast\n"));
}

static int gather_stdout_one(int fd, void *arg) {
        char ***s = arg, *t;
        char buf[128] = {};

        assert_se(s);
        assert_se(read(fd, buf, sizeof buf) >= 0);
        safe_close(fd);

        assert_se(t = strndup(buf, sizeof buf));
        assert_se(strv_push(s, t) >= 0);

        return 0;
}
static int gather_stdout_two(int fd, void *arg) {
        char ***s = arg;

        STRV_FOREACH(t, *s)
                assert_se(write(fd, *t, strlen(*t)) == (ssize_t) strlen(*t));
        safe_close(fd);

        return 0;
}
static int gather_stdout_three(int fd, void *arg) {
        char **s = arg;
        char buf[128] = {};

        assert_se(read(fd, buf, sizeof buf - 1) > 0);
        safe_close(fd);
        assert_se(*s = strndup(buf, sizeof buf));

        return 0;
}

const gather_stdout_callback_t gather_stdouts[] = {
        gather_stdout_one,
        gather_stdout_two,
        gather_stdout_three,
};

TEST(stdout_gathering) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        const char *name, *name2, *name3;
        int r;

        char **tmp = NULL; /* this is only used in the forked process, no cleanup here */
        _cleanup_free_ char *output = NULL;

        void* args[] = {&tmp, &tmp, &output};

        assert_se(mkdtemp_malloc("/tmp/test-exec-util.XXXXXXX", &tmpdir) >= 0);

        const char *dirs[] = { tmpdir, NULL };

        /* write files */
        name = strjoina(tmpdir, "/10-foo");
        name2 = strjoina(tmpdir, "/20-bar");
        name3 = strjoina(tmpdir, "/30-last");

        assert_se(write_string_file(name,
                                    "#!/bin/sh\necho a\necho b\necho c\n",
                                    WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(name2,
                                    "#!/bin/sh\necho d\n",
                                    WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(name3,
                                    "#!/bin/sh\nsleep 1",
                                    WRITE_STRING_FILE_CREATE) == 0);

        assert_se(chmod(name, 0755) == 0);
        assert_se(chmod(name2, 0755) == 0);
        assert_se(chmod(name3, 0755) == 0);

        if (access(name, X_OK) < 0 && ERRNO_IS_PRIVILEGE(errno))
                return;

        r = execute_directories(dirs, DEFAULT_TIMEOUT_USEC, gather_stdouts, args, NULL, NULL,
                                EXEC_DIR_PARALLEL | EXEC_DIR_IGNORE_ERRORS);
        assert_se(r >= 0);

        log_info("got: %s", output);

        assert_se(streq(output, "a\nb\nc\nd\n"));
}

TEST(environment_gathering) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        const char *name, *name2, *name3, *old;
        int r;

        char **tmp = NULL; /* this is only used in the forked process, no cleanup here */
        _cleanup_strv_free_ char **env = NULL;

        void* const args[] = { &tmp, &tmp, &env };

        assert_se(mkdtemp_malloc("/tmp/test-exec-util.XXXXXXX", &tmpdir) >= 0);

        const char *dirs[] = { tmpdir, NULL };

        /* write files */
        name = strjoina(tmpdir, "/10-foo");
        name2 = strjoina(tmpdir, "/20-bar");
        name3 = strjoina(tmpdir, "/30-last");

        assert_se(write_string_file(name,
                                    "#!/bin/sh\n"
                                    "echo A=23\n",
                                    WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(name2,
                                    "#!/bin/sh\n"
                                    "echo A=22:$A\n\n\n",            /* substitution from previous generator */
                                    WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(name3,
                                    "#!/bin/sh\n"
                                    "echo A=$A:24\n"
                                    "echo B=12\n"
                                    "echo C=000\n"
                                    "echo C=001\n"                    /* variable overwriting */
                                     /* various invalid entries */
                                    "echo unset A\n"
                                    "echo unset A=\n"
                                    "echo unset A=B\n"
                                    "echo unset \n"
                                    "echo A B=C\n"
                                    "echo A\n"
                                    /* test variable assignment without newline */
                                    "echo PATH=$PATH:/no/such/file",   /* no newline */
                                    WRITE_STRING_FILE_CREATE) == 0);

        assert_se(chmod(name, 0755) == 0);
        assert_se(chmod(name2, 0755) == 0);
        assert_se(chmod(name3, 0755) == 0);

        /* When booting in containers or without initrd there might not be any PATH in the environment and if
         * there is no PATH /bin/sh built-in PATH may leak and override systemd's DEFAULT_PATH which is not
         * good. Force our own PATH in environment, to prevent expansion of sh built-in $PATH */
        old = getenv("PATH");
        r = setenv("PATH", "no-sh-built-in-path", 1);
        assert_se(r >= 0);

        if (access(name, X_OK) < 0 && ERRNO_IS_PRIVILEGE(errno))
                return;

        r = execute_directories(dirs, DEFAULT_TIMEOUT_USEC, gather_environment, args, NULL, NULL, EXEC_DIR_PARALLEL | EXEC_DIR_IGNORE_ERRORS);
        assert_se(r >= 0);

        STRV_FOREACH(p, env)
                log_info("got env: \"%s\"", *p);

        assert_se(streq(strv_env_get(env, "A"), "22:23:24"));
        assert_se(streq(strv_env_get(env, "B"), "12"));
        assert_se(streq(strv_env_get(env, "C"), "001"));
        assert_se(streq(strv_env_get(env, "PATH"), "no-sh-built-in-path:/no/such/file"));

        /* now retest with "default" path passed in, as created by
         * manager_default_environment */
        env = strv_free(env);
        env = strv_new("PATH=" DEFAULT_PATH);
        assert_se(env);

        r = execute_directories(dirs, DEFAULT_TIMEOUT_USEC, gather_environment, args, NULL, env, EXEC_DIR_PARALLEL | EXEC_DIR_IGNORE_ERRORS);
        assert_se(r >= 0);

        STRV_FOREACH(p, env)
                log_info("got env: \"%s\"", *p);

        assert_se(streq(strv_env_get(env, "A"), "22:23:24"));
        assert_se(streq(strv_env_get(env, "B"), "12"));
        assert_se(streq(strv_env_get(env, "C"), "001"));
        assert_se(streq(strv_env_get(env, "PATH"), DEFAULT_PATH ":/no/such/file"));

        /* reset environ PATH */
        assert_se(set_unset_env("PATH", old, true) == 0);
}

TEST(error_catching) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        const char *name, *name2, *name3;
        int r;

        assert_se(mkdtemp_malloc("/tmp/test-exec-util.XXXXXXX", &tmpdir) >= 0);

        const char *dirs[] = { tmpdir, NULL };

        /* write files */
        name = strjoina(tmpdir, "/10-foo");
        name2 = strjoina(tmpdir, "/20-bar");
        name3 = strjoina(tmpdir, "/30-last");

        assert_se(write_string_file(name,
                                    "#!/bin/sh\necho a\necho b\necho c\n",
                                    WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(name2,
                                    "#!/bin/sh\nexit 42\n",
                                    WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(name3,
                                    "#!/bin/sh\nexit 12",
                                    WRITE_STRING_FILE_CREATE) == 0);

        assert_se(chmod(name, 0755) == 0);
        assert_se(chmod(name2, 0755) == 0);
        assert_se(chmod(name3, 0755) == 0);

        if (access(name, X_OK) < 0 && ERRNO_IS_PRIVILEGE(errno))
                return;

        r = execute_directories(dirs, DEFAULT_TIMEOUT_USEC, NULL, NULL, NULL, NULL, EXEC_DIR_NONE);

        /* we should exit with the error code of the first script that failed */
        assert_se(r == 42);
}

TEST(exec_command_flags_from_strv) {
        ExecCommandFlags flags = 0;
        char **valid_strv = STRV_MAKE("no-env-expand", "no-setuid", "ignore-failure");
        char **invalid_strv = STRV_MAKE("no-env-expand", "no-setuid", "nonexistent-option", "ignore-failure");
        int r;

        r = exec_command_flags_from_strv(valid_strv, &flags);

        assert_se(r == 0);
        assert_se(FLAGS_SET(flags, EXEC_COMMAND_NO_ENV_EXPAND));
        assert_se(FLAGS_SET(flags, EXEC_COMMAND_NO_SETUID));
        assert_se(FLAGS_SET(flags, EXEC_COMMAND_IGNORE_FAILURE));
        assert_se(!FLAGS_SET(flags, EXEC_COMMAND_AMBIENT_MAGIC));
        assert_se(!FLAGS_SET(flags, EXEC_COMMAND_FULLY_PRIVILEGED));

        r = exec_command_flags_from_strv(invalid_strv, &flags);

        assert_se(r == -EINVAL);
}

TEST(exec_command_flags_to_strv) {
        _cleanup_strv_free_ char **opts = NULL, **empty_opts = NULL, **invalid_opts = NULL;
        ExecCommandFlags flags = 0;
        int r;

        flags |= (EXEC_COMMAND_AMBIENT_MAGIC|EXEC_COMMAND_NO_ENV_EXPAND|EXEC_COMMAND_IGNORE_FAILURE);

        r = exec_command_flags_to_strv(flags, &opts);

        assert_se(r == 0);
        assert_se(strv_equal(opts, STRV_MAKE("ignore-failure", "ambient", "no-env-expand")));

        r = exec_command_flags_to_strv(0, &empty_opts);

        assert_se(r == 0);
        assert_se(strv_equal(empty_opts, STRV_MAKE_EMPTY));

        flags = _EXEC_COMMAND_FLAGS_INVALID;

        r = exec_command_flags_to_strv(flags, &invalid_opts);

        assert_se(r == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
