/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <signal.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ask-password-api.h"
#include "conf-parser.h"
#include "fd-util.h"
#include "fileio.h"
#include "glob-util.h"
#include "io-util.h"
#include "keyring-util.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "signal-util.h"
#include "socket-util.h"
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

static PidRef start_request(
                const char *key,
                AskPasswordFlags flags,
                bool new_session,
                usec_t timeout,
                int hup_fd,
                int expected) {

        static unsigned sequence = 0;
        _cleanup_(pidref_done) PidRef child = PIDREF_NULL;
        bool use_auto = sequence++ % 2;

        int r = ASSERT_OK(pidref_safe_fork_full(
                        "(password-request)", /* stdio_fds= */ NULL,
                        &hup_fd, hup_fd >= 0 ? 1 : 0,
                        FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL, &child));
        if (r == 0) {
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
                sigset_t before, after;
                int sig;

                if (expected < 0) {
                        answer = strv_new("unchanged");
                        ASSERT_NOT_NULL(answer);
                }
                ASSERT_OK_ERRNO(sigprocmask(SIG_SETMASK, NULL, &before));
                if (use_auto)
                        r = ask_password_auto(&req, flags|ASK_PASSWORD_USER|ASK_PASSWORD_NO_TTY, &answer);
                else
                        r = ask_password_agent(&req, flags|ASK_PASSWORD_USER, &answer);
                ASSERT_EQ(r, expected);
                ASSERT_OK_ERRNO(sigprocmask(SIG_SETMASK, NULL, &after));
                FOREACH_ARGUMENT(sig, SIGINT, SIGTERM)
                        ASSERT_EQ(sigismember(&before, sig), sigismember(&after, sig));
                if (r >= 0)
                        ASSERT_STRV_EQ(answer, STRV_MAKE("test-password"));
                else
                        ASSERT_STRV_EQ(answer, STRV_MAKE("unchanged"));
                ASSERT_ERROR_ERRNO(waitpid(-1, NULL, WNOHANG), ECHILD);
                _exit(EXIT_SUCCESS);
        }
        return TAKE_PIDREF(child);
}

static void finish_request(PidRef *child) {
        ASSERT_OK_ZERO(pidref_wait_for_terminate_and_check("(password-request)", child, WAIT_LOG));
        pidref_done(child);
}

static pid_t wait_lock_worker(const PidRef *requester) {
        _cleanup_free_ char *path = NULL;
        usec_t until = now(CLOCK_MONOTONIC) + 5 * USEC_PER_SEC;

        ASSERT_GE(asprintf(&path, "/proc/" PID_FMT "/task/" PID_FMT "/children", requester->pid, requester->pid), 0);
        for (;;) {
                _cleanup_free_ char *line = NULL;
                pid_t worker = 0;
                int r;

                r = read_one_line_file(path, &line);
                if (r == -ENOENT) {
                        log_tests_skipped("Kernel does not expose process children, cannot inspect lock workers");
                        return 0;
                }
                ASSERT_OK(r);
                if (!isempty(strstrip(line))) {
                        ASSERT_OK(parse_pid(line, &worker));
                        return worker;
                }
                ASSERT_LT(now(CLOCK_MONOTONIC), until);
                ASSERT_OK(usleep_safe(10 * USEC_PER_MSEC));
        }
}

static char** request_files(const char *directory) {
        _cleanup_free_ char *pattern = path_join(directory, "ask.*");
        char **files = NULL;

        ASSERT_NOT_NULL(pattern);
        int r = safe_glob(pattern, GLOB_NOSORT, &files);
        if (r != -ENOENT)
                ASSERT_OK(r);
        return files;
}

static void wait_requests(const char *directory, size_t count) {
        usec_t until = now(CLOCK_MONOTONIC) + 5 * USEC_PER_SEC;

        for (;;) {
                _cleanup_strv_free_ char **files = request_files(directory);
                if (strv_length(files) == count)
                        return;
                ASSERT_LT(now(CLOCK_MONOTONIC), until);
                ASSERT_OK(usleep_safe(10 * USEC_PER_MSEC));
        }
}

static void reply_request(const char *file, const char *reply) {
        _cleanup_free_ char *socket_name = NULL;
        _cleanup_close_ int fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        const ConfigTableItem items[] = {
                { "Ask", "Socket", config_parse_string, CONFIG_PARSE_STRING_SAFE, &socket_name },
                {}
        };

        ASSERT_OK_ERRNO(fd);
        ASSERT_OK(config_parse(/* unit= */ NULL, file, /* f= */ NULL, "Ask\0", config_item_table_lookup, items,
                               CONFIG_PARSE_RELAXED|CONFIG_PARSE_WARN, /* userdata= */ NULL, /* ret_stat= */ NULL));
        ASSERT_NOT_NULL(socket_name);
        ASSERT_OK(connect_unix_path(fd, AT_FDCWD, socket_name));
        ASSERT_EQ(send(fd, reply, strlen(reply), MSG_NOSIGNAL), (ssize_t) strlen(reply));
}

static void reply_all(const char *directory) {
        _cleanup_strv_free_ char **files = request_files(directory);

        STRV_FOREACH(p, files)
                reply_request(*p, "+test-password");
}

TEST(concurrent_cache) {
        /* A fresh session keyring and a private runtime directory isolate the cache and agent requests.
         * A controlled responder must satisfy concurrent callers of the same key with one request.
         * Different keys and sessions must proceed independently. Cancellation and cache-write failures
         * must allow later callers to acquire passwords. */
        _cleanup_(rm_rf_physical_and_freep) char *runtime = NULL;
        _cleanup_free_ char *directory = NULL, *cache_directory = NULL;
        const AskPasswordFlags cached = ASK_PASSWORD_ACCEPT_CACHED|ASK_PASSWORD_PUSH_CACHE;
        PidRef children[6];

        if (keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0) < 0)
                return (void) log_tests_skipped_errno(errno, "Cannot create session keyring");
        key_serial_t probe = add_key("user", "probe", "probe", 5, KEY_SPEC_SESSION_KEYRING);
        if (probe < 0)
                return (void) log_tests_skipped_errno(errno, "Cannot cache passwords in session keyring");
        ASSERT_OK(keyring_unlink_key(KEY_SPEC_SESSION_KEYRING, probe));

        ASSERT_OK(mkdtemp_malloc("/var/tmp/test-password-cache.XXXXXX", &runtime));
        ASSERT_OK_ERRNO(setenv("XDG_RUNTIME_DIR", runtime, 1));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_ASK_PASSWORD_KEYRING_TYPE", "session", 1));
        directory = path_join(runtime, "systemd/ask-password");
        ASSERT_NOT_NULL(directory);

        /* Contending callers must not publish duplicate requests or repeatedly notify password agents. */
        children[0] = start_request("same-key", cached, /* new_session= */ false, 10 * USEC_PER_SEC, -EBADF, /* expected= */ 0);
        wait_requests(directory, 1);
        _cleanup_close_ int notify_fd = inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
        ASSERT_OK_ERRNO(notify_fd);
        ASSERT_OK_ERRNO(inotify_add_watch(notify_fd, directory, IN_CLOSE_WRITE|IN_MOVED_TO));
        for (size_t i = 1; i < ELEMENTSOF(children); i++)
                children[i] = start_request("same-key", cached, /* new_session= */ false, 10 * USEC_PER_SEC, -EBADF, /* expected= */ 0);
        for (size_t i = 1; i < ELEMENTSOF(children); i++)
                (void) wait_lock_worker(&children[i]);

        /* Once the workers are blocked, waiting must not repeatedly reopen the lock file. */
        cache_directory = path_join(runtime, "systemd/ask-password-cache");
        ASSERT_NOT_NULL(cache_directory);
        _cleanup_close_ int lock_notify_fd = inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
        ASSERT_OK_ERRNO(lock_notify_fd);
        ASSERT_OK_ERRNO(inotify_add_watch(lock_notify_fd, cache_directory, IN_OPEN));
        ASSERT_OK(usleep_safe(250 * USEC_PER_MSEC));
        ASSERT_OK(flush_fd(lock_notify_fd));
        ASSERT_OK_ZERO(fd_wait_for_event(notify_fd, POLLIN, 100 * USEC_PER_MSEC));
        ASSERT_OK_ZERO(fd_wait_for_event(lock_notify_fd, POLLIN, 100 * USEC_PER_MSEC));
        _cleanup_strv_free_ char **files = request_files(directory);
        ASSERT_EQ(strv_length(files), 1u);
        files = strv_free(files);
        reply_all(directory);
        FOREACH_ELEMENT(child, children)
                finish_request(child);
        wait_requests(directory, /* count= */ 0);
        /* A later caller must reuse the cached answer without publishing a request. */
        ASSERT_OK_ERRNO(request_key("user", "same-key", /* callout_info= */ NULL, /* destringid= */ 0));
        children[0] = start_request("same-key", cached, /* new_session= */ false, USEC_PER_SEC, -EBADF, /* expected= */ 0);
        finish_request(&children[0]);
        wait_requests(directory, /* count= */ 0);
        /* A cache hit must not need a writable runtime directory. */
        _cleanup_strv_free_erase_ char **answer = NULL;
        AskPasswordRequest req = {
                .keyring = "same-key",
                .tty_fd = -EBADF,
                .hup_fd = -EBADF,
        };

        ASSERT_OK_ERRNO(setenv("XDG_RUNTIME_DIR", "/nonexistent/password-cache-test", 1));
        ASSERT_OK(ask_password_tty(&req, cached, &answer));
        ASSERT_STRV_EQ(answer, STRV_MAKE("test-password"));
        ASSERT_OK_ERRNO(setenv("XDG_RUNTIME_DIR", runtime, 1));
        answer = strv_free_erase(answer);

        /* A file at the lock-directory path must not prevent password acquisition. */
        ASSERT_OK_ERRNO(rmdir(cache_directory));
        ASSERT_OK(write_string_file(cache_directory, "blocked", WRITE_STRING_FILE_CREATE));
        children[0] = start_request("setup-fails", cached, /* new_session= */ false, USEC_PER_SEC, -EBADF, /* expected= */ 0);
        wait_requests(directory, 1);
        reply_all(directory);
        finish_request(&children[0]);
        wait_requests(directory, /* count= */ 0);
        ASSERT_OK_ERRNO(unlink(cache_directory));

        /* A lock directory without write permission must not prevent password acquisition. */
        ASSERT_OK(mkdir_p(cache_directory, 0500));
        children[0] = start_request("lock-fails", cached, /* new_session= */ false, USEC_PER_SEC, -EBADF, /* expected= */ 0);
        wait_requests(directory, 1);
        reply_all(directory);
        finish_request(&children[0]);
        wait_requests(directory, /* count= */ 0);
        ASSERT_OK_ERRNO(chmod(cache_directory, 0700));

        /* Different keys and separate session keyrings must publish requests concurrently. */
        children[0] = start_request("independent", cached, /* new_session= */ false, 10 * USEC_PER_SEC, -EBADF, /* expected= */ 0);
        wait_requests(directory, 1);
        children[1] = start_request("other", cached, /* new_session= */ false, 10 * USEC_PER_SEC, -EBADF, /* expected= */ 0);
        children[2] = start_request("independent", cached, /* new_session= */ true, 10 * USEC_PER_SEC, -EBADF, /* expected= */ 0);
        wait_requests(directory, 3);
        reply_all(directory);
        for (size_t i = 0; i < 3; i++)
                finish_request(&children[i]);
        wait_requests(directory, /* count= */ 0);

        /* Missing cache keys and incomplete caching flags must preserve independent requests. */
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
                children[0] = start_request(c->key, c->flags, /* new_session= */ false, 10 * USEC_PER_SEC, -EBADF, /* expected= */ 0);
                children[1] = start_request(c->key, c->flags, /* new_session= */ false, 10 * USEC_PER_SEC, -EBADF, /* expected= */ 0);
                wait_requests(directory, 2);
                reply_all(directory);
                finish_request(&children[0]);
                finish_request(&children[1]);
                wait_requests(directory, /* count= */ 0);
                if (c->key && !FLAGS_SET(c->flags, ASK_PASSWORD_PUSH_CACHE))
                        ASSERT_LT(request_key("user", c->key, /* callout_info= */ NULL, /* destringid= */ 0), 0);
        }

        /* A failed cache write must allow the next caller to issue another request. */
        key_serial_t scope = 0;
        ASSERT_OK(keyring_resolve(KEY_SPEC_SESSION_KEYRING, &scope));
        ASSERT_OK(keyring_set_perm(scope, KEY_POS_ALL & ~KEY_POS_WRITE));
        children[0] = start_request("write-fails", cached, /* new_session= */ false, 10 * USEC_PER_SEC, -EBADF, /* expected= */ 0);
        wait_requests(directory, 1);
        children[1] = start_request("write-fails", cached, /* new_session= */ false, 10 * USEC_PER_SEC, -EBADF, /* expected= */ 0);
        reply_all(directory);
        finish_request(&children[0]);
        wait_requests(directory, 1);
        reply_all(directory);
        finish_request(&children[1]);
        wait_requests(directory, /* count= */ 0);
        ASSERT_LT(request_key("user", "write-fails", /* callout_info= */ NULL, /* destringid= */ 0), 0);
        ASSERT_OK(keyring_set_perm(scope, KEY_POS_ALL|KEY_USR_ALL));

        /* Waiters must enforce their deadlines while an agent request holds the cache lock. */
        children[0] = start_request("waiting", cached, /* new_session= */ false, 10 * USEC_PER_SEC, -EBADF, -ECANCELED);
        wait_requests(directory, 1);
        children[1] = start_request("waiting", cached, /* new_session= */ false, 200 * USEC_PER_MSEC, -EBADF, -ETIME);
        finish_request(&children[1]);
        req = (AskPasswordRequest) {
                .keyring = "waiting",
                .tty_fd = -EBADF,
                .hup_fd = -EBADF,
                .until = now(CLOCK_MONOTONIC) + 100 * USEC_PER_MSEC,
        };
        answer = strv_new("unchanged");
        ASSERT_NOT_NULL(answer);
        ASSERT_ERROR(ask_password_tty(&req, cached|ASK_PASSWORD_USER, &answer), ETIME);
        ASSERT_STRV_EQ(answer, STRV_MAKE("unchanged"));

        /* A missing TTY flag file must preserve the output after acquiring the cache lock. */
        req.keyring = "missing-flag";
        req.flag_file = strjoina(runtime, "/missing-flag");
        req.until = 0;
        ASSERT_ERROR(ask_password_tty(&req, cached|ASK_PASSWORD_USER, &answer), ENOENT);
        ASSERT_STRV_EQ(answer, STRV_MAKE("unchanged"));
        answer = strv_free_erase(answer);

        /* A waiter with SIGTERM blocked must report the signal as an interruption. */
        sigset_t oldmask;

        ASSERT_OK(sigprocmask_many(SIG_BLOCK, &oldmask, SIGTERM));
        _cleanup_(pidref_done) PidRef waiter = start_request("waiting", cached, /* new_session= */ false, USEC_PER_SEC, -EBADF, -EINTR);
        ASSERT_OK(pidref_kill(&waiter, SIGTERM));
        finish_request(&waiter);
        ASSERT_OK_ERRNO(sigprocmask(SIG_SETMASK, &oldmask, NULL));

        /* A cancellation pipe that hangs up after the worker starts must abort the waiting caller. */
        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC));
        waiter = start_request("waiting", cached, /* new_session= */ false, USEC_PER_SEC, pipefd[0], -ECONNRESET);
        (void) wait_lock_worker(&waiter);
        pipefd[1] = safe_close(pipefd[1]);
        finish_request(&waiter);
        safe_close_pair(pipefd);

        /* Killing a waiting requester must kill its worker while the original holder retains the lock. */
        int reaper = is_reaper_process();
        siginfo_t si;

        ASSERT_OK(reaper);
        waiter = start_request("waiting", cached, /* new_session= */ false, 10 * USEC_PER_SEC, -EBADF, /* expected= */ 0);
        pid_t worker = wait_lock_worker(&waiter);
        _cleanup_(pidref_done) PidRef worker_ref = PIDREF_NULL;
        if (worker > 0) {
                ASSERT_OK(make_reaper_process(true));
                ASSERT_OK(pidref_set_pid(&worker_ref, worker));
        }
        ASSERT_OK(pidref_kill(&waiter, SIGKILL));
        ASSERT_OK(pidref_wait_for_terminate(&waiter, &si));
        ASSERT_EQ(si.si_code, CLD_KILLED);
        ASSERT_EQ(si.si_status, SIGKILL);
        if (worker > 0) {
                ASSERT_OK(pidref_wait_for_terminate_full(&worker_ref, USEC_PER_SEC, &si));
                ASSERT_EQ(si.si_code, CLD_KILLED);
                ASSERT_EQ(si.si_status, SIGKILL);
        }
        ASSERT_OK(make_reaper_process(reaper));
        pidref_done(&waiter);
        pidref_done(&worker_ref);

        /* Attribute changes must preserve a TTY lock wait without a deadline. Removing the flag file
         * must interrupt the wait and reap the worker. */
        _cleanup_free_ char *flag_file = path_join(runtime, "flag");

        ASSERT_NOT_NULL(flag_file);
        ASSERT_OK(write_string_file(flag_file, "", WRITE_STRING_FILE_CREATE));
        int r = ASSERT_OK(pidref_safe_fork("(password-request)", FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL, &waiter));
        if (r == 0) {
                req = (AskPasswordRequest) {
                        .keyring = "waiting",
                        .flag_file = flag_file,
                        .tty_fd = -EBADF,
                        .hup_fd = -EBADF,
                };

                alarm(15);
                ASSERT_ERROR(ask_password_tty(&req, cached|ASK_PASSWORD_USER, &answer), ENOENT);
                ASSERT_ERROR_ERRNO(waitpid(-1, NULL, WNOHANG), ECHILD);
                _exit(EXIT_SUCCESS);
        }
        (void) wait_lock_worker(&waiter);
        ASSERT_OK_ERRNO(chmod(flag_file, 0600));
        ASSERT_OK(usleep_safe(100 * USEC_PER_MSEC));
        ASSERT_EQ(waitpid(waiter.pid, NULL, WNOHANG), 0);
        ASSERT_OK_ERRNO(unlink(flag_file));
        finish_request(&waiter);

        /* An agent cancellation must release the lock for a later request. */
        files = request_files(directory);
        ASSERT_EQ(strv_length(files), 1u);
        reply_request(files[0], "-");
        files = strv_free(files);
        finish_request(&children[0]);
        wait_requests(directory, /* count= */ 0);
        children[0] = start_request("waiting", cached, /* new_session= */ false, USEC_PER_SEC, -EBADF, /* expected= */ 0);
        wait_requests(directory, 1);
        reply_all(directory);
        finish_request(&children[0]);
        wait_requests(directory, /* count= */ 0);

        /* Killing a requester must release its lock even though its request file remains. */
        children[0] = start_request("killed", cached, /* new_session= */ false, 10 * USEC_PER_SEC, -EBADF, /* expected= */ 0);
        wait_requests(directory, 1);
        children[1] = start_request("killed", cached, /* new_session= */ false, 10 * USEC_PER_SEC, -EBADF, /* expected= */ 0);
        files = request_files(directory);

        ASSERT_OK(pidref_kill(&children[0], SIGKILL));
        ASSERT_OK(pidref_wait_for_terminate(&children[0], &si));
        ASSERT_EQ(si.si_code, CLD_KILLED);
        ASSERT_EQ(si.si_status, SIGKILL);
        pidref_done(&children[0]);
        ASSERT_OK_ERRNO(unlink(files[0]));
        files = strv_free(files);
        wait_requests(directory, 1);
        reply_all(directory);
        finish_request(&children[1]);
        wait_requests(directory, /* count= */ 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
