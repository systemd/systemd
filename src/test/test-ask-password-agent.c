/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>
#include <signal.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ask-password-api.h"
#include "fd-util.h"
#include "fileio.h"
#include "keyring-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

TEST(prompt_fields_are_safe) {
        AskPasswordRequest req = {
                .message = "Password for /dev/disk/by-label/über?",
                .icon = "drive-harddisk",
                .id = "cryptsetup:/dev/disk\\by-label/'data'[*]",
                .tty_fd = -EBADF,
                .hup_fd = -EBADF,
        };

        ASSERT_TRUE(ask_password_agent_prompt_fields_are_safe(&req));

        req.message = "";
        ASSERT_TRUE(ask_password_agent_prompt_fields_are_safe(&req));

        req.message = "first line\nSocket=/tmp/injected";
        ASSERT_FALSE(ask_password_agent_prompt_fields_are_safe(&req));

        req.message = "Password:";
        req.icon = "drive\rIcon";
        ASSERT_FALSE(ask_password_agent_prompt_fields_are_safe(&req));

        req.icon = "drive-harddisk";
        req.id = "cryptsetup:\x01/dev/sda";
        ASSERT_FALSE(ask_password_agent_prompt_fields_are_safe(&req));

        req.id = "cryptsetup:\xff/dev/sda";
        ASSERT_FALSE(ask_password_agent_prompt_fields_are_safe(&req));
}

static pid_t start_request(
                const char *key,
                AskPasswordFlags flags,
                bool new_session,
                usec_t timeout,
                int hup_fd,
                int expected) {

        static unsigned sequence = 0;
        bool use_auto = sequence++ % 2;
        pid_t pid = fork();
        ASSERT_OK_ERRNO(pid);
        if (pid == 0) {
                alarm(15);
                if (new_session)
                        ASSERT_OK_ERRNO(keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0));

                AskPasswordRequest req = {
                        .keyring = key,
                        .message = "Test password",
                        .tty_fd = -EBADF,
                        .hup_fd = hup_fd,
                        .until = now(CLOCK_MONOTONIC) + timeout,
                };
                _cleanup_strv_free_erase_ char **answer = NULL;
                int r;

                if (use_auto)
                        r = ask_password_auto(&req, flags|ASK_PASSWORD_USER|ASK_PASSWORD_NO_TTY, &answer);
                else
                        r = ask_password_agent(&req, flags|ASK_PASSWORD_USER, &answer);
                ASSERT_EQ(r, expected);
                if (r >= 0) {
                        ASSERT_EQ(strv_length(answer), 1u);
                        ASSERT_STREQ(answer[0], "test-password");
                }
                _exit(EXIT_SUCCESS);
        }
        return pid;
}

static void finish_request(pid_t pid) {
        int status;

        ASSERT_EQ(waitpid(pid, &status, 0), pid);
        ASSERT_TRUE(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
}

static char** request_files(const char *directory) {
        _cleanup_closedir_ DIR *d = opendir(directory);
        char **files = NULL;

        if (!d) {
                ASSERT_EQ(errno, ENOENT);
                return NULL;
        }
        for (struct dirent *de; (de = readdir(d));)
                if (startswith(de->d_name, "ask.")) {
                        _cleanup_free_ char *p = path_join(directory, de->d_name);
                        ASSERT_NOT_NULL(p);
                        ASSERT_OK(strv_extend(&files, p));
                }
        return files;
}

static void wait_requests(const char *directory, size_t count) {
        usec_t until = now(CLOCK_MONOTONIC) + 5 * USEC_PER_SEC;

        for (;;) {
                _cleanup_strv_free_ char **files = request_files(directory);
                if (strv_length(files) == count)
                        return;
                ASSERT_LT(now(CLOCK_MONOTONIC), until);
                ASSERT_OK_ERRNO(usleep(10 * USEC_PER_MSEC));
        }
}

static void reply_request(const char *file, const char *reply) {
        _cleanup_fclose_ FILE *f = fopen(file, "re");
        _cleanup_close_ int fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        struct sockaddr_un sa = { .sun_family = AF_UNIX };

        ASSERT_NOT_NULL(f);
        ASSERT_OK_ERRNO(fd);
        for (;;) {
                _cleanup_free_ char *line = NULL;

                ASSERT_GT(read_line(f, LONG_LINE_MAX, &line), 0);
                const char *p = startswith(line, "Socket=");
                if (!p)
                        continue;
                ASSERT_LT(strlen(p), sizeof(sa.sun_path));
                memcpy(sa.sun_path, p, strlen(p));
                ASSERT_OK_ERRNO(sendto(fd, reply, strlen(reply), 0, (struct sockaddr*) &sa, sizeof(sa)));
                return;
        }
}

static void reply_all(const char *directory) {
        _cleanup_strv_free_ char **files = request_files(directory);

        STRV_FOREACH(p, files)
                reply_request(*p, "+test-password");
}

TEST(concurrent_cache) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime = NULL;
        _cleanup_free_ char *directory = NULL, *cache_directory = NULL;
        const AskPasswordFlags cached = ASK_PASSWORD_ACCEPT_CACHED|ASK_PASSWORD_PUSH_CACHE;
        pid_t children[6];

        if (keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0) < 0)
                return (void) log_tests_skipped_errno(errno, "Cannot create session keyring");
        key_serial_t probe = add_key("user", "probe", "probe", 5, KEY_SPEC_SESSION_KEYRING);
        if (probe < 0)
                return (void) log_tests_skipped_errno(errno, "Cannot cache passwords in session keyring");
        ASSERT_OK_ERRNO(keyctl(KEYCTL_UNLINK, probe, KEY_SPEC_SESSION_KEYRING, 0, 0));

        ASSERT_OK(mkdtemp_malloc("/var/tmp/test-password-cache.XXXXXX", &runtime));
        ASSERT_OK_ERRNO(setenv("XDG_RUNTIME_DIR", runtime, 1));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_ASK_PASSWORD_KEYRING_TYPE", "session", 1));
        directory = path_join(runtime, "systemd/ask-password");
        ASSERT_NOT_NULL(directory);

        children[0] = start_request("same-key", cached, false, 10 * USEC_PER_SEC, -EBADF, 0);
        wait_requests(directory, 1);
        _cleanup_close_ int notify_fd = inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
        ASSERT_OK_ERRNO(notify_fd);
        ASSERT_OK_ERRNO(inotify_add_watch(notify_fd, directory, IN_CLOSE_WRITE|IN_MOVED_TO));
        for (size_t i = 1; i < ELEMENTSOF(children); i++)
                children[i] = start_request("same-key", cached, false, 10 * USEC_PER_SEC, -EBADF, 0);
        ASSERT_OK_ERRNO(usleep(250 * USEC_PER_MSEC));
        {
                char events[4096];
                ASSERT_ERROR_ERRNO(read(notify_fd, events, sizeof(events)), EAGAIN);
        }
        {
                _cleanup_strv_free_ char **files = request_files(directory);
                ASSERT_EQ(strv_length(files), 1u);
        }
        reply_all(directory);
        FOREACH_ELEMENT(pid, children)
                finish_request(*pid);
        wait_requests(directory, 0);
        ASSERT_OK_ERRNO(request_key("user", "same-key", NULL, 0));
        finish_request(start_request("same-key", cached, false, USEC_PER_SEC, -EBADF, 0));
        wait_requests(directory, 0);
        {
                _cleanup_strv_free_erase_ char **answer = NULL;
                AskPasswordRequest req = {
                        .keyring = "same-key",
                        .tty_fd = -EBADF,
                        .hup_fd = -EBADF,
                };

                ASSERT_OK_ERRNO(setenv("XDG_RUNTIME_DIR", "/nonexistent/password-cache-test", 1));
                ASSERT_OK(ask_password_tty(&req, cached, &answer));
                ASSERT_STREQ(answer[0], "test-password");
                ASSERT_OK_ERRNO(setenv("XDG_RUNTIME_DIR", runtime, 1));
        }

        cache_directory = path_join(runtime, "systemd/ask-password-cache");
        ASSERT_NOT_NULL(cache_directory);
        ASSERT_OK_ERRNO(rmdir(cache_directory));
        ASSERT_OK(write_string_file(cache_directory, "blocked", WRITE_STRING_FILE_CREATE));
        children[0] = start_request("setup-fails", cached, false, USEC_PER_SEC, -EBADF, 0);
        wait_requests(directory, 1);
        reply_all(directory);
        finish_request(children[0]);
        wait_requests(directory, 0);
        ASSERT_OK_ERRNO(unlink(cache_directory));

        ASSERT_OK(mkdir_p(cache_directory, 0500));
        children[0] = start_request("lock-fails", cached, false, USEC_PER_SEC, -EBADF, 0);
        wait_requests(directory, 1);
        reply_all(directory);
        finish_request(children[0]);
        wait_requests(directory, 0);
        ASSERT_OK_ERRNO(chmod(cache_directory, 0700));

        children[0] = start_request("independent", cached, false, 10 * USEC_PER_SEC, -EBADF, 0);
        wait_requests(directory, 1);
        children[1] = start_request("other", cached, false, 10 * USEC_PER_SEC, -EBADF, 0);
        children[2] = start_request("independent", cached, true, 10 * USEC_PER_SEC, -EBADF, 0);
        wait_requests(directory, 3);
        reply_all(directory);
        for (size_t i = 0; i < 3; i++)
                finish_request(children[i]);
        wait_requests(directory, 0);

        const struct {
                const char *key;
                AskPasswordFlags flags;
        } uncached[] = {
                { "uncached", 0 },
                { "accept-only", ASK_PASSWORD_ACCEPT_CACHED },
                { "push-only", ASK_PASSWORD_PUSH_CACHE },
                { NULL, cached },
        };

        FOREACH_ELEMENT(c, uncached) {
                children[0] = start_request(c->key, c->flags, false, 10 * USEC_PER_SEC, -EBADF, 0);
                children[1] = start_request(c->key, c->flags, false, 10 * USEC_PER_SEC, -EBADF, 0);
                wait_requests(directory, 2);
                reply_all(directory);
                finish_request(children[0]);
                finish_request(children[1]);
                wait_requests(directory, 0);
                if (c->key && !FLAGS_SET(c->flags, ASK_PASSWORD_PUSH_CACHE))
                        ASSERT_LT(request_key("user", c->key, NULL, 0), 0);
        }

        key_serial_t scope;
        ASSERT_OK(keyring_resolve(KEY_SPEC_SESSION_KEYRING, &scope));
        ASSERT_OK(keyring_set_perm(scope, KEY_POS_ALL & ~KEY_POS_WRITE));
        children[0] = start_request("write-fails", cached, false, 10 * USEC_PER_SEC, -EBADF, 0);
        wait_requests(directory, 1);
        children[1] = start_request("write-fails", cached, false, 10 * USEC_PER_SEC, -EBADF, 0);
        reply_all(directory);
        finish_request(children[0]);
        wait_requests(directory, 1);
        reply_all(directory);
        finish_request(children[1]);
        wait_requests(directory, 0);
        ASSERT_LT(request_key("user", "write-fails", NULL, 0), 0);
        ASSERT_OK(keyring_set_perm(scope, KEY_POS_ALL|KEY_USR_ALL));

        children[0] = start_request("waiting", cached, false, 10 * USEC_PER_SEC, -EBADF, -ECANCELED);
        wait_requests(directory, 1);
        finish_request(start_request("waiting", cached, false, 200 * USEC_PER_MSEC, -EBADF, -ETIME));
        {
                _cleanup_strv_free_erase_ char **answer = NULL;
                AskPasswordRequest req = {
                        .keyring = "waiting",
                        .tty_fd = -EBADF,
                        .hup_fd = -EBADF,
                        .until = now(CLOCK_MONOTONIC) + 100 * USEC_PER_MSEC,
                };
                ASSERT_ERROR(ask_password_tty(&req, cached|ASK_PASSWORD_USER, &answer), ETIME);
        }
        {
                sigset_t mask, oldmask;
                ASSERT_OK_ERRNO(sigemptyset(&mask));
                ASSERT_OK_ERRNO(sigaddset(&mask, SIGTERM));
                ASSERT_OK_ERRNO(sigprocmask(SIG_BLOCK, &mask, &oldmask));
                pid_t waiter = start_request("waiting", cached, false, USEC_PER_SEC, -EBADF, -EINTR);
                ASSERT_OK_ERRNO(sigprocmask(SIG_SETMASK, &oldmask, NULL));
                ASSERT_OK_ERRNO(kill(waiter, SIGTERM));
                finish_request(waiter);
        }
        {
                int pipefd[2];
                ASSERT_OK_ERRNO(pipe(pipefd));
                ASSERT_OK_ERRNO(close(pipefd[1]));
                finish_request(start_request("waiting", cached, false, USEC_PER_SEC, pipefd[0], -ECONNRESET));
                ASSERT_OK_ERRNO(close(pipefd[0]));
        }
        {
                _cleanup_strv_free_ char **files = request_files(directory);
                ASSERT_EQ(strv_length(files), 1u);
                reply_request(files[0], "-");
        }
        finish_request(children[0]);
        wait_requests(directory, 0);
        children[0] = start_request("waiting", cached, false, USEC_PER_SEC, -EBADF, 0);
        wait_requests(directory, 1);
        reply_all(directory);
        finish_request(children[0]);
        wait_requests(directory, 0);

        children[0] = start_request("killed", cached, false, 10 * USEC_PER_SEC, -EBADF, 0);
        wait_requests(directory, 1);
        children[1] = start_request("killed", cached, false, 10 * USEC_PER_SEC, -EBADF, 0);
        {
                _cleanup_strv_free_ char **files = request_files(directory);
                int status;
                ASSERT_OK_ERRNO(kill(children[0], SIGKILL));
                ASSERT_EQ(waitpid(children[0], &status, 0), children[0]);
                ASSERT_TRUE(WIFSIGNALED(status));
                ASSERT_EQ(WTERMSIG(status), SIGKILL);
                ASSERT_OK_ERRNO(unlink(files[0]));
        }
        wait_requests(directory, 1);
        reply_all(directory);
        finish_request(children[1]);
        wait_requests(directory, 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
