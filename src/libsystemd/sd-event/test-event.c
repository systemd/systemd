/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/wait.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidfd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"

static int prepare_handler(sd_event_source *s, void *userdata) {
        log_info("preparing %c", PTR_TO_INT(userdata));
        return 1;
}

static bool got_a, got_b, got_c, got_unref;
static unsigned got_d;

static int unref_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_event_source_unref(s);
        got_unref = true;
        return 0;
}

static int io_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {

        log_info("got IO on %c", PTR_TO_INT(userdata));

        if (userdata == INT_TO_PTR('a')) {
                ASSERT_OK(sd_event_source_set_enabled(s, SD_EVENT_OFF));
                ASSERT_FALSE(got_a);
                got_a = true;
        } else if (userdata == INT_TO_PTR('b')) {
                ASSERT_FALSE(got_b);
                got_b = true;
        } else if (userdata == INT_TO_PTR('d')) {
                got_d++;
                if (got_d < 2)
                        ASSERT_OK(sd_event_source_set_enabled(s, SD_EVENT_ONESHOT));
                else
                        ASSERT_OK(sd_event_source_set_enabled(s, SD_EVENT_OFF));
        } else
                assert_not_reached();

        return 1;
}

static int child_handler(sd_event_source *s, const siginfo_t *si, void *userdata) {

        ASSERT_NOT_NULL(s);
        ASSERT_NOT_NULL(si);

        ASSERT_EQ(si->si_uid, getuid());
        ASSERT_EQ(si->si_signo, SIGCHLD);
        ASSERT_EQ(si->si_code, CLD_EXITED);
        ASSERT_EQ(si->si_status, 78);

        log_info("got child on %c", PTR_TO_INT(userdata));

        ASSERT_PTR_EQ(userdata, INT_TO_PTR('f'));

        ASSERT_OK(sd_event_exit(sd_event_source_get_event(s), 0));
        sd_event_source_unref(s);

        return 1;
}

static int signal_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        sd_event_source *p = NULL;
        pid_t pid;
        siginfo_t plain_si;

        ASSERT_NOT_NULL(s);
        ASSERT_NOT_NULL(si);

        log_info("got signal on %c", PTR_TO_INT(userdata));

        ASSERT_PTR_EQ(userdata, INT_TO_PTR('e'));

        ASSERT_OK(sigprocmask_many(SIG_BLOCK, NULL, SIGUSR2));

        ASSERT_OK_ERRNO(pid = fork());

        if (pid == 0) {
                sigset_t ss;

                ASSERT_OK_ERRNO(sigemptyset(&ss));
                ASSERT_OK_ERRNO(sigaddset(&ss, SIGUSR2));

                zero(plain_si);
                ASSERT_OK_ERRNO(sigwaitinfo(&ss, &plain_si));

                ASSERT_EQ(plain_si.si_signo, SIGUSR2);
                ASSERT_EQ(plain_si.si_value.sival_int, 4711);

                _exit(78);
        }

        ASSERT_OK(sd_event_add_child(sd_event_source_get_event(s), &p, pid, WEXITED, child_handler, INT_TO_PTR('f')));
        ASSERT_OK(sd_event_source_set_enabled(p, SD_EVENT_ONESHOT));
        ASSERT_OK(sd_event_source_set_child_process_own(p, true));

        /* We can't use structured initialization here, since the structure contains various unions and these
         * fields lie in overlapping (carefully aligned) unions that LLVM is allergic to allow assignments
         * to */
        zero(plain_si);
        plain_si.si_signo = SIGUSR2;
        plain_si.si_code = SI_QUEUE;
        plain_si.si_pid = getpid_cached();
        plain_si.si_uid = getuid();
        plain_si.si_value.sival_int = 4711;

        ASSERT_OK(sd_event_source_send_child_signal(p, SIGUSR2, &plain_si, 0));

        sd_event_source_unref(s);

        return 1;
}

static int defer_handler(sd_event_source *s, void *userdata) {
        sd_event_source *p = NULL;

        ASSERT_NOT_NULL(s);

        log_info("got defer on %c", PTR_TO_INT(userdata));

        ASSERT_PTR_EQ(userdata, INT_TO_PTR('d'));

        ASSERT_OK(sigprocmask_many(SIG_BLOCK, NULL, SIGUSR1));

        ASSERT_OK(sd_event_add_signal(sd_event_source_get_event(s), &p, SIGUSR1, signal_handler, INT_TO_PTR('e')));
        ASSERT_OK(sd_event_source_set_enabled(p, SD_EVENT_ONESHOT));
        raise(SIGUSR1);

        sd_event_source_unref(s);

        return 1;
}

static bool do_quit;

static int time_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        log_info("got timer on %c", PTR_TO_INT(userdata));

        if (userdata == INT_TO_PTR('c')) {

                if (do_quit) {
                        sd_event_source *p;

                        ASSERT_OK(sd_event_add_defer(sd_event_source_get_event(s), &p, defer_handler, INT_TO_PTR('d')));
                        ASSERT_OK(sd_event_source_set_enabled(p, SD_EVENT_ONESHOT));
                } else {
                        ASSERT_FALSE(got_c);
                        got_c = true;
                }
        } else
                assert_not_reached();

        return 2;
}

static bool got_exit = false;

static int exit_handler(sd_event_source *s, void *userdata) {
        log_info("got quit handler on %c", PTR_TO_INT(userdata));

        got_exit = true;

        return 3;
}

static bool got_post = false;

static int post_handler(sd_event_source *s, void *userdata) {
        log_info("got post handler");

        got_post = true;

        return 2;
}

TEST(basic) {
        sd_event *e = NULL;
        sd_event_source *w = NULL, *x = NULL, *y = NULL, *z = NULL, *q = NULL, *t = NULL;
        static const char ch = 'x';
        int a[2] = EBADF_PAIR, b[2] = EBADF_PAIR,
            d[2] = EBADF_PAIR, k[2] = EBADF_PAIR;
        uint64_t event_now;
        int64_t priority;

        ASSERT_OK_ERRNO(pipe(a));
        ASSERT_OK_ERRNO(pipe(b));
        ASSERT_OK_ERRNO(pipe(d));
        ASSERT_OK_ERRNO(pipe(k));

        ASSERT_OK(sd_event_default(&e));
        ASSERT_OK_POSITIVE(sd_event_now(e, CLOCK_MONOTONIC, &event_now));

        ASSERT_OK(sd_event_set_watchdog(e, true));

        /* Test whether we cleanly can destroy an io event source from its own handler */
        got_unref = false;
        ASSERT_OK(sd_event_add_io(e, &t, k[0], EPOLLIN, unref_handler, NULL));
        ASSERT_OK_EQ_ERRNO(write(k[1], &ch, 1), 1);
        ASSERT_OK_POSITIVE(sd_event_run(e, UINT64_MAX));
        ASSERT_TRUE(got_unref);

        got_a = false, got_b = false, got_c = false, got_d = 0;

        /* Add a oneshot handler, trigger it, reenable it, and trigger it again. */
        ASSERT_OK(sd_event_add_io(e, &w, d[0], EPOLLIN, io_handler, INT_TO_PTR('d')));
        ASSERT_OK(sd_event_source_set_enabled(w, SD_EVENT_ONESHOT));
        ASSERT_OK_ERRNO(write(d[1], &ch, 1));
        ASSERT_OK_POSITIVE(sd_event_run(e, UINT64_MAX));
        ASSERT_EQ(got_d, 1U);
        ASSERT_OK_ERRNO(write(d[1], &ch, 1));
        ASSERT_OK_POSITIVE(sd_event_run(e, UINT64_MAX));
        ASSERT_EQ(got_d, 2U);

        ASSERT_OK(sd_event_add_io(e, &x, a[0], EPOLLIN, io_handler, INT_TO_PTR('a')));
        ASSERT_OK(sd_event_add_io(e, &y, b[0], EPOLLIN, io_handler, INT_TO_PTR('b')));

        do_quit = false;
        ASSERT_OK(sd_event_add_time(e, &z, CLOCK_MONOTONIC, 0, 0, time_handler, INT_TO_PTR('c')));
        ASSERT_OK(sd_event_add_exit(e, &q, exit_handler, INT_TO_PTR('g')));

        ASSERT_OK(sd_event_source_set_priority(x, 99));
        ASSERT_OK(sd_event_source_get_priority(x, &priority));
        ASSERT_EQ(priority, 99);
        ASSERT_OK(sd_event_source_set_enabled(y, SD_EVENT_ONESHOT));
        ASSERT_OK(sd_event_source_set_prepare(x, prepare_handler));
        ASSERT_OK(sd_event_source_set_priority(z, 50));
        ASSERT_OK(sd_event_source_set_enabled(z, SD_EVENT_ONESHOT));
        ASSERT_OK(sd_event_source_set_prepare(z, prepare_handler));

        /* Test for floating event sources */
        ASSERT_OK(sigprocmask_many(SIG_BLOCK, NULL, SIGRTMIN+1));
        ASSERT_OK(sd_event_add_signal(e, NULL, SIGRTMIN+1, NULL, NULL));

        ASSERT_OK_ERRNO(write(a[1], &ch, 1));
        ASSERT_OK_ERRNO(write(b[1], &ch, 1));

        ASSERT_FALSE(got_a);
        ASSERT_FALSE(got_b);
        ASSERT_FALSE(got_c);

        ASSERT_OK_POSITIVE(sd_event_run(e, UINT64_MAX));

        ASSERT_FALSE(got_a);
        ASSERT_TRUE(got_b);
        ASSERT_FALSE(got_c);

        ASSERT_OK_POSITIVE(sd_event_run(e, UINT64_MAX));

        ASSERT_FALSE(got_a);
        ASSERT_TRUE(got_b);
        ASSERT_TRUE(got_c);

        ASSERT_OK_POSITIVE(sd_event_run(e, UINT64_MAX));

        ASSERT_TRUE(got_a);
        ASSERT_TRUE(got_b);
        ASSERT_TRUE(got_c);

        sd_event_source_unref(x);
        sd_event_source_unref(y);

        do_quit = true;
        ASSERT_OK(sd_event_add_post(e, NULL, post_handler, NULL));
        ASSERT_OK_ZERO(sd_event_now(e, CLOCK_MONOTONIC, &event_now));
        ASSERT_OK(sd_event_source_set_time(z, event_now + 200 * USEC_PER_MSEC));
        ASSERT_OK(sd_event_source_set_enabled(z, SD_EVENT_ONESHOT));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_TRUE(got_post);
        ASSERT_TRUE(got_exit);

        sd_event_source_unref(z);
        sd_event_source_unref(q);

        sd_event_source_unref(w);

        sd_event_unref(e);

        safe_close_pair(a);
        safe_close_pair(b);
        safe_close_pair(d);
        safe_close_pair(k);
}

TEST(sd_event_now) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        uint64_t event_now;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK_POSITIVE(sd_event_now(e, CLOCK_MONOTONIC, &event_now));
        ASSERT_OK_POSITIVE(sd_event_now(e, CLOCK_REALTIME, &event_now));
        ASSERT_OK_POSITIVE(sd_event_now(e, CLOCK_REALTIME_ALARM, &event_now));
        ASSERT_OK_POSITIVE(sd_event_now(e, CLOCK_BOOTTIME, &event_now));
        ASSERT_OK_POSITIVE(sd_event_now(e, CLOCK_BOOTTIME_ALARM, &event_now));
        ASSERT_ERROR(sd_event_now(e, -1, &event_now), EOPNOTSUPP);
        ASSERT_ERROR(sd_event_now(e, 900 /* arbitrary big number */, &event_now), EOPNOTSUPP);

        ASSERT_OK_ZERO(sd_event_run(e, 0));

        ASSERT_OK_ZERO(sd_event_now(e, CLOCK_MONOTONIC, &event_now));
        ASSERT_OK_ZERO(sd_event_now(e, CLOCK_REALTIME, &event_now));
        ASSERT_OK_ZERO(sd_event_now(e, CLOCK_REALTIME_ALARM, &event_now));
        ASSERT_OK_ZERO(sd_event_now(e, CLOCK_BOOTTIME, &event_now));
        ASSERT_OK_ZERO(sd_event_now(e, CLOCK_BOOTTIME_ALARM, &event_now));
        ASSERT_ERROR(sd_event_now(e, -1, &event_now), EOPNOTSUPP);
        ASSERT_ERROR(sd_event_now(e, 900 /* arbitrary big number */, &event_now), EOPNOTSUPP);
}

static int last_rtqueue_sigval = 0;
static int n_rtqueue = 0;

static int rtqueue_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        last_rtqueue_sigval = si->ssi_int;
        n_rtqueue++;
        return 0;
}

TEST(rtqueue) {
        sd_event_source *u = NULL, *v = NULL, *s = NULL;
        sd_event *e = NULL;

        ASSERT_OK(sd_event_default(&e));

        ASSERT_OK(sigprocmask_many(SIG_BLOCK, NULL, SIGRTMIN+2, SIGRTMIN+3, SIGUSR2));
        ASSERT_OK(sd_event_add_signal(e, &u, SIGRTMIN+2, rtqueue_handler, NULL));
        ASSERT_OK(sd_event_add_signal(e, &v, SIGRTMIN+3, rtqueue_handler, NULL));
        ASSERT_OK(sd_event_add_signal(e, &s, SIGUSR2, rtqueue_handler, NULL));

        ASSERT_OK(sd_event_source_set_priority(v, -10));

        ASSERT_OK_ERRNO(sigqueue(getpid_cached(), SIGRTMIN+2, (union sigval) { .sival_int = 1 }));
        ASSERT_OK_ERRNO(sigqueue(getpid_cached(), SIGRTMIN+3, (union sigval) { .sival_int = 2 }));
        ASSERT_OK_ERRNO(sigqueue(getpid_cached(), SIGUSR2, (union sigval) { .sival_int = 3 }));
        ASSERT_OK_ERRNO(sigqueue(getpid_cached(), SIGRTMIN+3, (union sigval) { .sival_int = 4 }));
        ASSERT_OK_ERRNO(sigqueue(getpid_cached(), SIGUSR2, (union sigval) { .sival_int = 5 }));

        ASSERT_EQ(n_rtqueue, 0);
        ASSERT_EQ(last_rtqueue_sigval, 0);

        ASSERT_OK_EQ(sd_event_run(e, UINT64_MAX), 1);
        ASSERT_EQ(n_rtqueue, 1);
        ASSERT_EQ(last_rtqueue_sigval, 2); /* first SIGRTMIN+3 */

        ASSERT_OK_EQ(sd_event_run(e, UINT64_MAX), 1);
        ASSERT_EQ(n_rtqueue, 2);
        ASSERT_EQ(last_rtqueue_sigval, 4); /* second SIGRTMIN+3 */

        ASSERT_OK_EQ(sd_event_run(e, UINT64_MAX), 1);
        ASSERT_EQ(n_rtqueue, 3);
        ASSERT_EQ(last_rtqueue_sigval, 3); /* first SIGUSR2 */

        ASSERT_OK_EQ(sd_event_run(e, UINT64_MAX), 1);
        ASSERT_EQ(n_rtqueue, 4);
        ASSERT_EQ(last_rtqueue_sigval, 1); /* SIGRTMIN+2 */

        ASSERT_OK_ZERO(sd_event_run(e, 0)); /* the other SIGUSR2 is dropped, because the first one was still queued */
        ASSERT_EQ(n_rtqueue, 4);
        ASSERT_EQ(last_rtqueue_sigval, 1);

        sd_event_source_unref(u);
        sd_event_source_unref(v);
        sd_event_source_unref(s);

        sd_event_unref(e);
}

#define CREATE_EVENTS_MAX (70000U)

struct inotify_context {
        bool delete_self_handler_called;
        unsigned create_called[CREATE_EVENTS_MAX];
        unsigned create_overflow;
        unsigned n_create_events;
        const char *path;
};

static void maybe_exit(sd_event_source *s, struct inotify_context *c) {
        unsigned n;

        ASSERT_NOT_NULL(s);
        ASSERT_NOT_NULL(c);

        if (!c->delete_self_handler_called)
                return;

        for (n = 0; n < 3; n++) {
                unsigned i;

                if (c->create_overflow & (1U << n))
                        continue;

                for (i = 0; i < c->n_create_events; i++)
                        if (!(c->create_called[i] & (1U << n)))
                                return;
        }

        sd_event_exit(sd_event_source_get_event(s), 0);
}

static int inotify_handler(sd_event_source *s, const struct inotify_event *ev, void *userdata) {
        struct inotify_context *c = ASSERT_PTR(userdata);
        const char *path, *description;
        unsigned bit, n;

        ASSERT_OK(sd_event_source_get_inotify_path(s, &path));

        ASSERT_OK(sd_event_source_get_description(s, &description));
        ASSERT_OK(safe_atou(description, &n));

        ASSERT_LE(n, 3U);
        bit = 1U << n;

        if (ev->mask & IN_Q_OVERFLOW) {
                log_info("inotify-handler for %s <%s>: overflow", path, description);
                c->create_overflow |= bit;
        } else if (ev->mask & IN_CREATE) {
                ASSERT_TRUE(path_equal_or_inode_same(path, c->path, 0));
                if (streq(ev->name, "sub"))
                        log_debug("inotify-handler for %s <%s>: create on %s", path, description, ev->name);
                else {
                        unsigned i;

                        ASSERT_OK(safe_atou(ev->name, &i));
                        ASSERT_LT(i, c->n_create_events);
                        c->create_called[i] |= bit;
                }
        } else if (ev->mask & IN_DELETE) {
                log_info("inotify-handler for %s <%s>: delete of %s", path, description, ev->name);
                ASSERT_STREQ(ev->name, "sub");
        } else
                assert_not_reached();

        maybe_exit(s, c);
        return 1;
}

static int delete_self_handler(sd_event_source *s, const struct inotify_event *ev, void *userdata) {
        struct inotify_context *c = ASSERT_PTR(userdata);
        const char *path;

        ASSERT_OK(sd_event_source_get_inotify_path(s, &path));

        if (ev->mask & IN_Q_OVERFLOW) {
                log_info("delete-self-handler for %s: overflow", path);
                c->delete_self_handler_called = true;
        } else if (ev->mask & IN_DELETE_SELF) {
                log_info("delete-self-handler for %s: delete-self", path);
                c->delete_self_handler_called = true;
        } else if (ev->mask & IN_IGNORED) {
                log_info("delete-self-handler for %s: ignore", path);
        } else
                assert_not_reached();

        maybe_exit(s, c);
        return 1;
}

static void test_inotify_one(unsigned n_create_events) {
        _cleanup_(rm_rf_physical_and_freep) char *p = NULL;
        sd_event_source *a = NULL, *b = NULL, *c = NULL, *d = NULL;
        struct inotify_context context = {
                .n_create_events = n_create_events,
        };
        sd_event *e = NULL;
        const char *q, *pp;
        unsigned i;

        log_info("/* %s(%u) */", __func__, n_create_events);

        ASSERT_OK(sd_event_default(&e));

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inotify-XXXXXX", &p));
        context.path = p;

        ASSERT_OK(sd_event_add_inotify(e, &a, p, IN_CREATE|IN_ONLYDIR, inotify_handler, &context));
        ASSERT_OK(sd_event_add_inotify(e, &b, p, IN_CREATE|IN_DELETE|IN_DONT_FOLLOW, inotify_handler, &context));
        ASSERT_OK(sd_event_source_set_priority(b, SD_EVENT_PRIORITY_IDLE));
        ASSERT_OK(sd_event_source_set_priority(b, SD_EVENT_PRIORITY_NORMAL));
        ASSERT_OK(sd_event_add_inotify(e, &c, p, IN_CREATE|IN_DELETE|IN_EXCL_UNLINK, inotify_handler, &context));
        ASSERT_OK(sd_event_source_set_priority(c, SD_EVENT_PRIORITY_IDLE));

        ASSERT_OK(sd_event_source_set_description(a, "0"));
        ASSERT_OK(sd_event_source_set_description(b, "1"));
        ASSERT_OK(sd_event_source_set_description(c, "2"));

        ASSERT_OK(sd_event_source_get_inotify_path(a, &pp));
        ASSERT_TRUE(path_equal_or_inode_same(pp, p, 0));
        ASSERT_OK(sd_event_source_get_inotify_path(b, &pp));
        ASSERT_TRUE(path_equal_or_inode_same(pp, p, 0));
        ASSERT_OK(sd_event_source_get_inotify_path(b, &pp));
        ASSERT_TRUE(path_equal_or_inode_same(pp, p, 0));

        q = strjoina(p, "/sub");
        ASSERT_OK(touch(q));
        ASSERT_OK(sd_event_add_inotify(e, &d, q, IN_DELETE_SELF, delete_self_handler, &context));

        for (i = 0; i < n_create_events; i++) {
                char buf[DECIMAL_STR_MAX(unsigned)+1];
                _cleanup_free_ char *z = NULL;

                xsprintf(buf, "%u", i);
                ASSERT_NOT_NULL(z = path_join(p, buf));

                ASSERT_OK(touch(z));
        }

        ASSERT_OK_ERRNO(unlink(q));

        ASSERT_OK(sd_event_loop(e));

        sd_event_source_unref(a);
        sd_event_source_unref(b);
        sd_event_source_unref(c);
        sd_event_source_unref(d);

        sd_event_unref(e);
}

TEST(inotify) {
        test_inotify_one(100); /* should work without overflow */
        test_inotify_one(33000); /* should trigger a q overflow */
}

static int pidfd_handler(sd_event_source *s, const siginfo_t *si, void *userdata) {
        ASSERT_NOT_NULL(s);
        ASSERT_NOT_NULL(si);

        ASSERT_EQ(si->si_uid, getuid());
        ASSERT_EQ(si->si_signo, SIGCHLD);
        ASSERT_EQ(si->si_code, CLD_EXITED);
        ASSERT_EQ(si->si_status, 66);

        log_info("got pidfd on %c", PTR_TO_INT(userdata));

        ASSERT_PTR_EQ(userdata, INT_TO_PTR('p'));

        ASSERT_OK(sd_event_exit(sd_event_source_get_event(s), 0));
        sd_event_source_unref(s);

        return 0;
}

TEST(pidfd) {
        sd_event_source *s = NULL, *t = NULL;
        sd_event *e = NULL;
        int pidfd;
        pid_t pid, pid2;

        ASSERT_OK_ERRNO(pid = fork());
        if (pid == 0)
                /* child */
                _exit(66);

        ASSERT_OK(pidfd = pidfd_open(pid, 0));

        ASSERT_OK_ERRNO(pid2 = fork());
        if (pid2 == 0)
                freeze();

        ASSERT_OK(sd_event_default(&e));
        ASSERT_OK(sd_event_add_child_pidfd(e, &s, pidfd, WEXITED, pidfd_handler, INT_TO_PTR('p')));
        ASSERT_OK(sd_event_source_set_child_pidfd_own(s, true));

        /* This one should never trigger, since our second child lives forever */
        ASSERT_OK(sd_event_add_child(e, &t, pid2, WEXITED, pidfd_handler, INT_TO_PTR('q')));
        ASSERT_OK(sd_event_source_set_child_process_own(t, true));

        ASSERT_OK(sd_event_loop(e));

        /* Child should still be alive */
        ASSERT_OK_ERRNO(kill(pid2, 0));

        t = sd_event_source_unref(t);

        /* Child should now be dead, since we dropped the ref */
        ASSERT_ERROR_ERRNO(kill(pid2, 0), ESRCH);

        sd_event_unref(e);
}

static int ratelimit_io_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        unsigned *c = (unsigned*) userdata;
        *c += 1;
        return 0;
}

static int ratelimit_time_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        int r;

        r = sd_event_source_set_enabled(s, SD_EVENT_ON);
        if (r < 0)
                log_warning_errno(r, "Failed to turn on notify event source: %m");

        r = sd_event_source_set_time(s, usec + 1000);
        if (r < 0)
                log_error_errno(r, "Failed to restart watchdog event source: %m");

        unsigned *c = (unsigned*) userdata;
        *c += 1;

        return 0;
}

static int expired = -1;
static int ratelimit_expired(sd_event_source *s, void *userdata) {
        return ++expired;
}

TEST(ratelimit) {
        _cleanup_close_pair_ int p[2] = EBADF_PAIR;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        uint64_t interval;
        unsigned count, burst;

        ASSERT_OK(sd_event_default(&e));
        ASSERT_OK_ERRNO(pipe2(p, O_CLOEXEC|O_NONBLOCK));

        ASSERT_OK(sd_event_add_io(e, &s, p[0], EPOLLIN, ratelimit_io_handler, &count));
        ASSERT_OK(sd_event_source_set_description(s, "test-ratelimit-io"));
        ASSERT_OK(sd_event_source_set_ratelimit(s, 1 * USEC_PER_SEC, 5));
        ASSERT_OK(sd_event_source_get_ratelimit(s, &interval, &burst));
        ASSERT_EQ(interval, 1 * USEC_PER_SEC);
        ASSERT_EQ(burst, 5U);

        ASSERT_OK_EQ_ERRNO(write(p[1], "1", 1), 1);

        count = 0;
        for (unsigned i = 0; i < 10; i++) {
                log_debug("slow loop iteration %u", i);
                ASSERT_OK(sd_event_run(e, UINT64_MAX));
                ASSERT_OK(usleep_safe(250 * USEC_PER_MSEC));
        }

        ASSERT_OK_ZERO(sd_event_source_is_ratelimited(s));
        ASSERT_EQ(count, 10U);
        log_info("ratelimit_io_handler: called %u times, event source not ratelimited", count);

        ASSERT_OK(sd_event_source_set_ratelimit(s, 0, 0));
        ASSERT_OK(sd_event_source_set_ratelimit(s, 1 * USEC_PER_SEC, 5));

        count = 0;
        for (unsigned i = 0; i < 10; i++) {
                log_debug("fast event loop iteration %u", i);
                ASSERT_OK(sd_event_run(e, UINT64_MAX));
                ASSERT_OK(usleep_safe(10));
        }
        log_info("ratelimit_io_handler: called %u times, event source got ratelimited", count);
        ASSERT_LT(count, 10U);

        s = sd_event_source_unref(s);
        safe_close_pair(p);

        count = 0;
        ASSERT_OK(sd_event_add_time_relative(e, &s, CLOCK_MONOTONIC, 1000, 1, ratelimit_time_handler, &count));
        ASSERT_OK_ZERO(sd_event_source_set_ratelimit(s, 1 * USEC_PER_SEC, 10));

        do {
                ASSERT_OK(sd_event_run(e, UINT64_MAX));
        } while (!sd_event_source_is_ratelimited(s));

        log_info("ratelimit_time_handler: called %u times, event source got ratelimited", count);
        ASSERT_EQ(count, 10U);

        /* In order to get rid of active rate limit client needs to disable it explicitly */
        ASSERT_OK(sd_event_source_set_ratelimit(s, 0, 0));
        ASSERT_OK_ZERO(sd_event_source_is_ratelimited(s));

        ASSERT_OK(sd_event_source_set_ratelimit(s, 1 * USEC_PER_SEC, 10));

        /* Set callback that will be invoked when we leave rate limited state. */
        ASSERT_OK(sd_event_source_set_ratelimit_expire_callback(s, ratelimit_expired));

        do {
                ASSERT_OK(sd_event_run(e, UINT64_MAX));
        } while (!sd_event_source_is_ratelimited(s));

        log_info("ratelimit_time_handler: called 10 more times, event source got ratelimited");
        ASSERT_EQ(count, 20U);

        /* Dispatch the event loop once more and check that ratelimit expiration callback got called */
        ASSERT_OK(sd_event_run(e, UINT64_MAX));
        ASSERT_EQ(expired, 0);
}

TEST(simple_timeout) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        usec_t f, t, some_time;

        some_time = random_u64_range(2 * USEC_PER_SEC);

        ASSERT_OK(sd_event_default(&e));

        ASSERT_OK_ZERO(sd_event_prepare(e));

        f = now(CLOCK_MONOTONIC);
        ASSERT_OK(sd_event_wait(e, some_time));
        t = now(CLOCK_MONOTONIC);

        /* The event loop may sleep longer than the specified time (timer accuracy, scheduling latencies, …),
         * but never shorter. Let's check that. */
        ASSERT_GE(t, usec_add(f, some_time));
}

static int inotify_self_destroy_handler(sd_event_source *s, const struct inotify_event *ev, void *userdata) {
        sd_event_source **p = userdata;

        ASSERT_NOT_NULL(ev);
        ASSERT_NOT_NULL(p);
        ASSERT_PTR_EQ(*p, s);

        ASSERT_TRUE(FLAGS_SET(ev->mask, IN_ATTRIB));

        ASSERT_OK(sd_event_exit(sd_event_source_get_event(s), 0));

        *p = sd_event_source_unref(*p); /* here's what we actually intend to test: we destroy the event
                                         * source from inside the event source handler */
        return 1;
}

TEST(inotify_self_destroy) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        char path[] = "/tmp/inotifyXXXXXX";
        _cleanup_close_ int fd = -EBADF;

        /* Tests that destroying an inotify event source from its own handler is safe */

        ASSERT_OK(sd_event_default(&e));

        ASSERT_OK(fd = mkostemp_safe(path));
        ASSERT_OK(sd_event_add_inotify_fd(e, &s, fd, IN_ATTRIB, inotify_self_destroy_handler, &s));
        fd = safe_close(fd);
        ASSERT_OK_ERRNO(unlink(path)); /* This will trigger IN_ATTRIB because link count goes to zero */
        ASSERT_OK(sd_event_loop(e));
}

struct inotify_process_buffered_data_context {
        const char *path[2];
        unsigned i;
};

static int inotify_process_buffered_data_handler(sd_event_source *s, const struct inotify_event *ev, void *userdata) {
        struct inotify_process_buffered_data_context *c = ASSERT_PTR(userdata);
        const char *description;

        ASSERT_OK(sd_event_source_get_description(s, &description));

        ASSERT_LT(c->i, 2U);
        ASSERT_STREQ(c->path[c->i], description);
        c->i++;

        return 1;
}

TEST(inotify_process_buffered_data) {
        _cleanup_(rm_rf_physical_and_freep) char *p = NULL, *q = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *a = NULL, *b = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_free_ char *z = NULL;

        /* For issue #23826 */

        ASSERT_OK(sd_event_default(&e));

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inotify-XXXXXX", &p));
        ASSERT_OK(mkdtemp_malloc("/tmp/test-inotify-XXXXXX", &q));

        struct inotify_process_buffered_data_context context = {
                .path = { p, q },
        };

        ASSERT_OK(sd_event_add_inotify(e, &a, p, IN_CREATE, inotify_process_buffered_data_handler, &context));
        ASSERT_OK(sd_event_add_inotify(e, &b, q, IN_CREATE, inotify_process_buffered_data_handler, &context));

        ASSERT_NOT_NULL(z = path_join(p, "aaa"));
        ASSERT_OK(touch(z));
        z = mfree(z);
        ASSERT_NOT_NULL(z = path_join(q, "bbb"));
        ASSERT_OK(touch(z));
        z = mfree(z);

        ASSERT_OK_POSITIVE(sd_event_run(e, 10 * USEC_PER_SEC));
        ASSERT_OK_POSITIVE(sd_event_prepare(e)); /* issue #23826: this was 0. */
        ASSERT_OK_POSITIVE(sd_event_dispatch(e));
        ASSERT_OK_ZERO(sd_event_prepare(e));
        ASSERT_OK_ZERO(sd_event_wait(e, 0));
}

static int inotify_handler_issue_38265(sd_event_source *s, const struct inotify_event *event, void *userdata) {
        log_debug("Inotify event: mask=0x%x name=%s", event->mask, event->name);
        return 0;
}

TEST(inotify_issue_38265) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *a = NULL, *b = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_free_ char *p = NULL;

        /* For issue #38265. */

        ASSERT_OK(mkdtemp_malloc("/tmp/test-inotify-XXXXXX", &t));

        ASSERT_OK(sd_event_default(&e));

        /* Create inode data that watches IN_MODIFY */
        ASSERT_OK(sd_event_add_inotify(e, &a, t, IN_CREATE | IN_MODIFY, inotify_handler_issue_38265, NULL));
        ASSERT_OK(sd_event_add_inotify(e, &b, t, IN_CREATE, inotify_handler_issue_38265, NULL));

        /* Then drop the event source that is interested in IN_MODIFY */
        ASSERT_NULL(a = sd_event_source_unref(a));

        /* Trigger IN_MODIFY (of course with IN_CREATE) */
        ASSERT_NOT_NULL(p = path_join(t, "hoge"));
        ASSERT_OK(write_string_file(p, "aaa", WRITE_STRING_FILE_CREATE));

        for (unsigned i = 1; i < 5; i++) {
                log_debug("Running event loop cycle %u to process inotify events...", i);
                ASSERT_OK(sd_event_run(e, USEC_PER_MSEC));
        }
}

TEST(fork) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        int r;

        ASSERT_OK(sd_event_default(&e));
        ASSERT_OK_ZERO(sd_event_prepare(e));

        /* Check that after a fork the cleanup functions return NULL */
        r = pidref_safe_fork("(bus-fork-test)", FORK_WAIT|FORK_LOG, NULL);
        if (r == 0) {
                ASSERT_NOT_NULL(e);
                ASSERT_NULL(sd_event_ref(e));
                ASSERT_NULL(sd_event_unref(e));
                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(r);
}

TEST(sd_event_source_set_io_fd) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_close_pair_ int pfd_a[2] = EBADF_PAIR, pfd_b[2] = EBADF_PAIR;

        ASSERT_OK(sd_event_default(&e));

        ASSERT_OK_ERRNO(pipe2(pfd_a, O_CLOEXEC));
        ASSERT_OK_ERRNO(pipe2(pfd_b, O_CLOEXEC));

        ASSERT_OK(sd_event_add_io(e, &s, pfd_a[0], EPOLLIN, NULL, INT_TO_PTR(-ENOANO)));
        ASSERT_OK(sd_event_source_set_io_fd_own(s, true));
        TAKE_FD(pfd_a[0]);

        ASSERT_OK(sd_event_source_set_io_fd(s, pfd_b[0]));
        TAKE_FD(pfd_b[0]);
}

static int hup_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        unsigned *c = userdata;

        ASSERT_EQ(revents, (uint32_t) EPOLLHUP);

        (*c)++;
        return 0;
}

TEST(leave_ratelimit) {
        bool expect_ratelimit = false, manually_left_ratelimit = false;
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_close_pair_ int pfd[2] = EBADF_PAIR;
        unsigned c = 0;
        int r;

        ASSERT_OK(sd_event_default(&e));

        /* Create an event source that will continuously fire by creating a pipe whose write side is closed,
         * and which hence will only see EOF and constant EPOLLHUP */
        ASSERT_OK_ERRNO(pipe2(pfd, O_CLOEXEC));
        ASSERT_OK(sd_event_add_io(e, &s, pfd[0], EPOLLIN, hup_callback, &c));
        ASSERT_OK(sd_event_source_set_io_fd_own(s, true));
        ASSERT_OK(sd_event_source_set_ratelimit(s, 5*USEC_PER_MINUTE, 5));

        pfd[0] = -EBADF;
        pfd[1] = safe_close(pfd[1]); /* Trigger continuous EOF */

        for (;;) {
                ASSERT_OK(r = sd_event_prepare(e));

                if (r == 0)
                        ASSERT_OK_POSITIVE(sd_event_wait(e, UINT64_MAX));

                ASSERT_OK_POSITIVE(sd_event_dispatch(e));

                ASSERT_OK(r = sd_event_source_is_ratelimited(s));

                if (c < 5)
                        /* First four dispatches should just work */
                        ASSERT_FALSE(r);
                else if (c == 5) {
                        /* The fifth dispatch should still work, but we now expect the ratelimit to be hit subsequently */
                        if (!expect_ratelimit) {
                                ASSERT_FALSE(r);
                                ASSERT_OK_ZERO(sd_event_source_leave_ratelimit(s)); /* this should be a NOP, and return 0 hence */
                                expect_ratelimit = true;
                        } else {
                                /* We expected the ratelimit, let's leave it manually, and verify it */
                                ASSERT_TRUE(r);
                                ASSERT_OK_POSITIVE(sd_event_source_leave_ratelimit(s)); /* we are ratelimited, hence should return > 0 */
                                ASSERT_OK_ZERO(sd_event_source_is_ratelimited(s));

                                manually_left_ratelimit = true;
                        }

                } else if (c == 6)
                        /* On the sixth iteration let's just exit */
                        break;
        }

        /* Verify we definitely hit the ratelimit and left it manually again */
        ASSERT_TRUE(manually_left_ratelimit);
}

static int defer_post_handler(sd_event_source *s, void *userdata) {
        bool *dispatched_post = ASSERT_PTR(userdata);

        *dispatched_post = true;

        return 0;
}

static int defer_adds_post_handler(sd_event_source *s, void *userdata) {
        sd_event *e = sd_event_source_get_event(s);

        /* Add a post event source from within the defer handler */
        ASSERT_OK(sd_event_add_post(e, NULL, defer_post_handler, userdata));

        return 0;
}

TEST(defer_add_post) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        bool dispatched_post = false;

        ASSERT_OK(sd_event_default(&e));

        /* Add a oneshot defer event source that will add a post event source */
        ASSERT_OK(sd_event_add_defer(e, NULL, defer_adds_post_handler, &dispatched_post));

        /* Run one iteration - this should dispatch the defer handler */
        ASSERT_OK_POSITIVE(sd_event_run(e, UINT64_MAX));

        /* The post handler should have been added but not yet dispatched */
        ASSERT_FALSE(dispatched_post);

        /* Run another iteration - this should dispatch the post handler */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        /* Now the post handler should have been dispatched */
        ASSERT_TRUE(dispatched_post);
}

static int child_handler_wnowait(sd_event_source *s, const siginfo_t *si, void *userdata) {
        int *counter = ASSERT_PTR(userdata);

        (*counter)++;

        if (*counter == 5)
                ASSERT_OK(sd_event_exit(sd_event_source_get_event(s), 0));

        return 0;
}

TEST(child_wnowait) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;

        ASSERT_OK(sd_event_default(&e));

        /* Fork a subprocess */
        pid_t pid;
        ASSERT_OK_ERRNO(pid = fork());

        if (pid == 0)
                /* Child process - exit with a specific code */
                _exit(42);

        /* Add a child source with WNOWAIT flag */
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int counter = 0;
        ASSERT_OK(sd_event_add_child(e, &s, pid, WEXITED|WNOWAIT, child_handler_wnowait, &counter));
        ASSERT_OK(sd_event_source_set_enabled(s, SD_EVENT_ON));

        /* Run the event loop - this should call the handler */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(counter, 5);

        /* Since we used WNOWAIT, the child should still be waitable */
        siginfo_t si = {};
        ASSERT_OK_ERRNO(waitid(P_PID, pid, &si, WEXITED|WNOHANG));
        ASSERT_EQ(si.si_pid, pid);
        ASSERT_EQ(si.si_code, CLD_EXITED);
        ASSERT_EQ(si.si_status, 42);
}

TEST(child_pidfd_wnowait) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;

        ASSERT_OK(sd_event_default(&e));

        /* Fork a subprocess */
        pid_t pid;
        ASSERT_OK_ERRNO(pid = fork());

        if (pid == 0)
                /* Child process - exit with a specific code */
                _exit(42);

        _cleanup_close_ int pidfd = -EBADF;
        ASSERT_OK_ERRNO(pidfd = pidfd_open(pid, 0));

        /* Add a child source with WNOWAIT flag */
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int counter = 0;
        ASSERT_OK(sd_event_add_child_pidfd(e, &s, pidfd, WEXITED|WNOWAIT, child_handler_wnowait, &counter));
        ASSERT_OK(sd_event_source_set_enabled(s, SD_EVENT_ON));

        /* Run the event loop - this should call the handler */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(counter, 5);

        /* Since we used WNOWAIT, the child should still be waitable */
        siginfo_t si = {};
        ASSERT_OK_ERRNO(waitid(P_PIDFD, pidfd, &si, WEXITED|WNOHANG));
        ASSERT_EQ(si.si_pid, pid);
        ASSERT_EQ(si.si_code, CLD_EXITED);
        ASSERT_EQ(si.si_status, 42);
}

static int exit_on_idle_defer_handler(sd_event_source *s, void *userdata) {
        unsigned *c = ASSERT_PTR(userdata);

        /* Should not be reached on third call because the event loop should exit before */
        ASSERT_LT(*c, 2u);

        (*c)++;

        /* Disable ourselves, which should trigger exit-on-idle after the second iteration */
        if (*c == 2)
                ASSERT_OK(sd_event_source_set_enabled(s, SD_EVENT_OFF));

        return 0;
}

static int exit_on_idle_post_handler(sd_event_source *s, void *userdata) {
        unsigned *c = ASSERT_PTR(userdata);

        /* Should not be reached on third call because the event loop should exit before */
        ASSERT_LT(*c, 2u);

        (*c)++;
        return 0;
}

static int exit_on_idle_exit_handler(sd_event_source *s, void *userdata) {
        return 0;
}

TEST(exit_on_idle) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));
        ASSERT_OK_POSITIVE(sd_event_get_exit_on_idle(e));

        /* Create a recurring defer event source. */
        _cleanup_(sd_event_source_unrefp) sd_event_source *d = NULL;
        unsigned dc = 0;
        ASSERT_OK(sd_event_add_defer(e, &d, exit_on_idle_defer_handler, &dc));
        ASSERT_OK(sd_event_source_set_enabled(d, SD_EVENT_ON));

        /* This post event source should not keep the event loop running after the defer source is disabled. */
        _cleanup_(sd_event_source_unrefp) sd_event_source *p = NULL;
        unsigned pc = 0;
        ASSERT_OK(sd_event_add_post(e, &p, exit_on_idle_post_handler, &pc));
        ASSERT_OK(sd_event_source_set_enabled(p, SD_EVENT_ON));
        ASSERT_OK(sd_event_source_set_priority(p, SD_EVENT_PRIORITY_IMPORTANT));

        /* And neither should this exit event source. */
        ASSERT_OK(sd_event_add_exit(e, NULL, exit_on_idle_exit_handler, NULL));

        /* Run the event loop - it should exit after we disable the event source */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(dc, 2u);
        ASSERT_EQ(pc, 2u);
}

TEST(exit_on_idle_no_sources) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        /* Running loop with no sources should return immediately with success */
        ASSERT_OK(sd_event_loop(e));
}

static int defer_fair_handler(sd_event_source *s, void *userdata) {
        unsigned *counter = ASSERT_PTR(userdata);

        /* If we're about to increment above 5, exit the event loop */
        if (*counter >= 5)
                return sd_event_exit(sd_event_source_get_event(s), 0);

        (*counter)++;

        return 0;
}

TEST(defer_fair_scheduling) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        sd_event_source *sources[5] = {};
        unsigned counters[5] = {};

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        /* Create 5 defer sources with equal priority */
        for (unsigned i = 0; i < 5; i++) {
                ASSERT_OK(sd_event_add_defer(e, &sources[i], defer_fair_handler, &counters[i]));
                ASSERT_OK(sd_event_source_set_enabled(sources[i], SD_EVENT_ON));
        }

        /* Run the event loop until one of the handlers exits */
        ASSERT_OK(sd_event_loop(e));

        /* All counters should be equal to 5, demonstrating fair scheduling */
        for (unsigned i = 0; i < 5; i++) {
                ASSERT_EQ(counters[i], 5u);
                sd_event_source_unref(sources[i]);
        }
}

TEST(child_autoreap_ebusy) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;

        /* Test that sd_event_add_child() fails with EBUSY when kernel autoreaping is enabled
         * by setting SIGCHLD disposition to SIG_IGN */

        ASSERT_OK(sd_event_new(&e));

        /* First, verify that adding a child source works with default signal disposition */
        ASSERT_OK_POSITIVE(pidref_safe_fork("(child-autoreaping-ebusy)", FORK_DEATHSIG_SIGKILL|FORK_FREEZE, &pidref));

        ASSERT_OK(event_add_child_pidref(e, &s, &pidref, WEXITED, NULL, NULL));
        s = sd_event_source_unref(s);

        /* Now set SIGCHLD to SIG_IGN to enable kernel autoreaping */
        struct sigaction old_sa, new_sa = {};
        new_sa.sa_handler = SIG_IGN;
        ASSERT_OK_ERRNO(sigaction(SIGCHLD, &new_sa, &old_sa));

        ASSERT_ERROR(event_add_child_pidref(e, &s, &pidref, WEXITED, NULL, NULL), EBUSY);

        /* Restore original SIGCHLD disposition */
        ASSERT_OK_ERRNO(sigaction(SIGCHLD, &old_sa, NULL));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
