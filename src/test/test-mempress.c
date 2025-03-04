/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "bus-locator.h"
#include "bus-wait-for-jobs.h"
#include "fd-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "signal-util.h"
#include "socket-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "unit-def.h"

struct fake_pressure_context {
        int fifo_fd;
        int socket_fd;
};

static void *fake_pressure_thread(void *p) {
        _cleanup_free_ struct fake_pressure_context *c = ASSERT_PTR(p);
        _cleanup_close_ int cfd = -EBADF;

        usleep_safe(150);

        assert_se(write(c->fifo_fd, &(const char) { 'x' }, 1) == 1);

        usleep_safe(150);

        cfd = accept4(c->socket_fd, NULL, NULL, SOCK_CLOEXEC);
        assert_se(cfd >= 0);
        char buf[STRLEN("hello")+1] = {};
        assert_se(read(cfd, buf, sizeof(buf)-1) == sizeof(buf)-1);
        ASSERT_STREQ(buf, "hello");
        assert_se(write(cfd, &(const char) { 'z' }, 1) == 1);

        return NULL;
}

static int fake_pressure_callback(sd_event_source *s, void *userdata) {
        int *value = userdata;
        const char *d;

        assert_se(s);
        assert_se(sd_event_source_get_description(s, &d) >= 0);

        *value *= d[0];

        log_notice("memory pressure event: %s", d);

        if (*value == 7 * 'f' * 's')
                assert_se(sd_event_exit(sd_event_source_get_event(s), 0) >= 0);

        return 0;
}

TEST(fake_pressure) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *es = NULL, *ef = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_free_ char *j = NULL, *k = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_close_ int fifo_fd = -EBADF, socket_fd = -EBADF;
        union sockaddr_union sa;
        pthread_t th;
        int value = 7;

        assert_se(sd_event_default(&e) >= 0);

        assert_se(mkdtemp_malloc(NULL, &tmp) >= 0);

        assert_se(j = path_join(tmp, "fifo"));
        assert_se(mkfifo(j, 0600) >= 0);
        fifo_fd = open(j, O_CLOEXEC|O_RDWR|O_NONBLOCK);
        assert_se(fifo_fd >= 0);

        assert_se(k = path_join(tmp, "sock"));
        socket_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        assert_se(socket_fd >= 0);
        assert_se(sockaddr_un_set_path(&sa.un, k) >= 0);
        assert_se(bind(socket_fd, &sa.sa, SOCKADDR_UN_LEN(sa.un)) >= 0);
        assert_se(listen(socket_fd, 1) >= 0);

        /* Ideally we'd just allocate this on the stack, but AddressSanitizer doesn't like it if threads
         * access each other's stack */
        struct fake_pressure_context *fp = new(struct fake_pressure_context, 1);
        assert_se(fp);
        *fp = (struct fake_pressure_context) {
                .fifo_fd = fifo_fd,
                .socket_fd = socket_fd,
        };

        assert_se(pthread_create(&th, NULL, fake_pressure_thread, TAKE_PTR(fp)) == 0);

        assert_se(setenv("MEMORY_PRESSURE_WATCH", j, /* override= */ true) >= 0);
        assert_se(unsetenv("MEMORY_PRESSURE_WRITE") >= 0);

        assert_se(sd_event_add_memory_pressure(e, &es, fake_pressure_callback, &value) >= 0);
        assert_se(sd_event_source_set_description(es, "fifo event source") >= 0);

        assert_se(setenv("MEMORY_PRESSURE_WATCH", k, /* override= */ true) >= 0);
        assert_se(setenv("MEMORY_PRESSURE_WRITE", "aGVsbG8K", /* override= */ true) >= 0);

        assert_se(sd_event_add_memory_pressure(e, &ef, fake_pressure_callback, &value) >= 0);
        assert_se(sd_event_source_set_description(ef, "socket event source") >= 0);

        assert_se(sd_event_loop(e) >= 0);

        assert_se(value == 7 * 'f' * 's');

        assert_se(pthread_join(th, NULL) == 0);
}

struct real_pressure_context {
        sd_event_source *pid;
};

static int real_pressure_callback(sd_event_source *s, void *userdata) {
        struct real_pressure_context *c = ASSERT_PTR(userdata);
        const char *d;

        assert_se(s);
        assert_se(sd_event_source_get_description(s, &d) >= 0);

        log_notice("real_memory pressure event: %s", d);

        sd_event_trim_memory();

        assert_se(c->pid);
        assert_se(sd_event_source_send_child_signal(c->pid, SIGKILL, NULL, 0) >= 0);
        c->pid = NULL;

        return 0;
}

#define MMAP_SIZE (10 * 1024 * 1024)

_noreturn_ static void real_pressure_eat_memory(int pipe_fd) {
        size_t ate = 0;

        /* Allocates and touches 10M at a time, until runs out of memory */

        char x;
        assert_se(read(pipe_fd, &x, 1) == 1); /* Wait for the GO! */

        for (;;) {
                void *p;

                p = mmap(NULL, MMAP_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                assert_se(p != MAP_FAILED);

                log_info("Eating another %s.", FORMAT_BYTES(MMAP_SIZE));

                memset(p, random_u32() & 0xFF, MMAP_SIZE);
                ate += MMAP_SIZE;

                log_info("Ate %s in total.", FORMAT_BYTES(ate));

                usleep_safe(50 * USEC_PER_MSEC);
        }
}

static int real_pressure_child_callback(sd_event_source *s, const siginfo_t *si, void *userdata) {
        assert_se(s);
        assert_se(si);

        log_notice("child dead");

        assert_se(si->si_signo == SIGCHLD);
        assert_se(si->si_status == SIGKILL);
        assert_se(si->si_code == CLD_KILLED);

        assert_se(sd_event_exit(sd_event_source_get_event(s), 31) >= 0);
        return 0;
}

TEST(real_pressure) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *es = NULL, *cs = NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_close_pair_ int pipe_fd[2] = EBADF_PAIR;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_free_ char *scope = NULL;
        const char *object;
        int r;
        pid_t pid;

        r = sd_bus_open_system(&bus);
        if (r < 0) {
                log_notice_errno(r, "Can't connect to system bus, skipping test: %m");
                return;
        }

        assert_se(bus_wait_for_jobs_new(bus, &w) >= 0);

        assert_se(bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit") >= 0);
        assert_se(asprintf(&scope, "test-%" PRIu64 ".scope", random_u64()) >= 0);
        assert_se(sd_bus_message_append(m, "ss", scope, "fail") >= 0);
        assert_se(sd_bus_message_open_container(m, 'a', "(sv)") >= 0);
        assert_se(sd_bus_message_append(m, "(sv)", "PIDs", "au", 1, 0) >= 0);
        assert_se(sd_bus_message_append(m, "(sv)", "MemoryAccounting", "b", true) >= 0);
        assert_se(sd_bus_message_close_container(m) >= 0);
        assert_se(sd_bus_message_append(m, "a(sa(sv))", 0) >= 0);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0) {
                log_notice_errno(r, "Can't issue transient unit call, skipping test: %m");
                return;
        }

        assert_se(sd_bus_message_read(reply, "o", &object) >= 0);

        assert_se(bus_wait_for_jobs_one(w, object, /* flags= */ BUS_WAIT_JOBS_LOG_ERROR, /* extra_args= */ NULL) >= 0);

        assert_se(sd_event_default(&e) >= 0);

        assert_se(pipe2(pipe_fd, O_CLOEXEC) >= 0);

        r = safe_fork("(eat-memory)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM, &pid);
        assert_se(r >= 0);
        if (r == 0) {
                real_pressure_eat_memory(pipe_fd[0]);
                _exit(EXIT_SUCCESS);
        }

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD) >= 0);
        assert_se(sd_event_add_child(e, &cs, pid, WEXITED, real_pressure_child_callback, NULL) >= 0);
        assert_se(sd_event_source_set_child_process_own(cs, true) >= 0);

        assert_se(unsetenv("MEMORY_PRESSURE_WATCH") >= 0);
        assert_se(unsetenv("MEMORY_PRESSURE_WRITE") >= 0);

        struct real_pressure_context context = {
                .pid = cs,
        };

        r = sd_event_add_memory_pressure(e, &es, real_pressure_callback, &context);
        if (r < 0) {
                log_notice_errno(r, "Can't allocate memory pressure fd, skipping test: %m");
                return;
        }

        assert_se(sd_event_source_set_description(es, "real pressure event source") >= 0);
        assert_se(sd_event_source_set_memory_pressure_type(es, "some") == 0);
        assert_se(sd_event_source_set_memory_pressure_type(es, "full") > 0);
        assert_se(sd_event_source_set_memory_pressure_type(es, "full") == 0);
        assert_se(sd_event_source_set_memory_pressure_type(es, "some") > 0);
        assert_se(sd_event_source_set_memory_pressure_type(es, "some") == 0);
        assert_se(sd_event_source_set_memory_pressure_period(es, 70 * USEC_PER_MSEC, USEC_PER_SEC) > 0);
        assert_se(sd_event_source_set_memory_pressure_period(es, 70 * USEC_PER_MSEC, USEC_PER_SEC) == 0);
        assert_se(sd_event_source_set_enabled(es, SD_EVENT_ONESHOT) >= 0);

        _cleanup_free_ char *uo = NULL;
        assert_se(uo = unit_dbus_path_from_name(scope));

        uint64_t mcurrent = UINT64_MAX;
        assert_se(sd_bus_get_property_trivial(bus, "org.freedesktop.systemd1", uo, "org.freedesktop.systemd1.Scope", "MemoryCurrent", &error, 't', &mcurrent) >= 0);

        printf("current: %" PRIu64 "\n", mcurrent);
        if (mcurrent == UINT64_MAX) {
                log_notice_errno(r, "Memory accounting not available, skipping test: %m");
                return;
        }

        m = sd_bus_message_unref(m);

        assert_se(bus_message_new_method_call(bus, &m, bus_systemd_mgr, "SetUnitProperties") >= 0);
        assert_se(sd_bus_message_append(m, "sb", scope, true) >= 0);
        assert_se(sd_bus_message_open_container(m, 'a', "(sv)") >= 0);
        assert_se(sd_bus_message_append(m, "(sv)", "MemoryHigh", "t", mcurrent + (15 * 1024 * 1024)) >= 0);
        assert_se(sd_bus_message_append(m, "(sv)", "MemoryMax", "t", mcurrent + (50 * 1024 * 1024)) >= 0);
        assert_se(sd_bus_message_close_container(m) >= 0);

        assert_se(sd_bus_call(bus, m, 0, NULL, NULL) >= 0);

        /* Generate some memory allocations via mempool */
#define NN (1024)
        Hashmap **h = new(Hashmap*, NN);
        for (int i = 0; i < NN; i++)
                h[i] = hashmap_new(NULL);
        for (int i = 0; i < NN; i++)
                hashmap_free(h[i]);
        free(h);

        /* Now start eating memory */
        assert_se(write(pipe_fd[1], &(const char) { 'x' }, 1) == 1);

        assert_se(sd_event_loop(e) >= 0);
        int ex = 0;
        assert_se(sd_event_get_exit_code(e, &ex) >= 0);
        assert_se(ex == 31);
}

static int outro(void) {
        hashmap_trim_pools();
        return 0;
}

DEFINE_TEST_MAIN_FULL(LOG_DEBUG, NULL, outro);
