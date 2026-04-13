/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "bus-locator.h"
#include "bus-wait-for-jobs.h"
#include "event-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "hashmap.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "signal-util.h"
#include "socket-util.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "unit-def.h"

/* Shared infrastructure for fake pressure tests */

struct fake_pressure_context {
        int fifo_fd;
        int socket_fd;
};

static void *fake_pressure_thread(void *p) {
        _cleanup_free_ struct fake_pressure_context *c = ASSERT_PTR(p);
        _cleanup_close_ int cfd = -EBADF;

        usleep_safe(150);

        ASSERT_EQ(write(c->fifo_fd, &(const char) { 'x' }, 1), 1);

        usleep_safe(150);

        cfd = accept4(c->socket_fd, NULL, NULL, SOCK_CLOEXEC);
        ASSERT_OK_ERRNO(cfd);
        char buf[STRLEN("hello")+1] = {};
        ASSERT_EQ(read(cfd, buf, sizeof(buf)-1), (ssize_t) (sizeof(buf)-1));
        ASSERT_STREQ(buf, "hello");
        ASSERT_EQ(write(cfd, &(const char) { 'z' }, 1), 1);

        return NULL;
}

static int fake_pressure_callback(sd_event_source *s, void *userdata) {
        int *value = userdata;
        const char *d;

        ASSERT_NOT_NULL(s);
        ASSERT_OK(sd_event_source_get_description(s, &d));

        *value *= d[0];

        log_notice("pressure event: %s", d);

        if (*value == 7 * 'f' * 's')
                ASSERT_OK(sd_event_exit(sd_event_source_get_event(s), 0));

        return 0;
}

typedef int (*event_add_pressure_t)(sd_event *, sd_event_source **, sd_event_handler_t, void *);

static void test_fake_pressure(
                const char *resource,
                event_add_pressure_t add_pressure) {

        _cleanup_(sd_event_source_unrefp) sd_event_source *es = NULL, *ef = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_close_ int fifo_fd = -EBADF, socket_fd = -EBADF;
        union sockaddr_union sa;
        pthread_t th;
        int value = 7;

        _cleanup_free_ char *resource_upper = ASSERT_NOT_NULL(strdup(resource));
        ascii_strupper(resource_upper);

        _cleanup_free_ char *env_watch = ASSERT_NOT_NULL(strjoin(resource_upper, "_PRESSURE_WATCH")),
                            *env_write = ASSERT_NOT_NULL(strjoin(resource_upper, "_PRESSURE_WRITE"));

        ASSERT_OK(sd_event_default(&e));

        ASSERT_OK(mkdtemp_malloc(NULL, &tmp));

        _cleanup_free_ char *j = ASSERT_NOT_NULL(path_join(tmp, "fifo"));
        ASSERT_OK_ERRNO(mkfifo(j, 0600));
        fifo_fd = open(j, O_CLOEXEC|O_RDWR|O_NONBLOCK);
        ASSERT_OK_ERRNO(fifo_fd);

        _cleanup_free_ char *k = ASSERT_NOT_NULL(path_join(tmp, "sock"));
        socket_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        ASSERT_OK_ERRNO(socket_fd);
        ASSERT_OK(sockaddr_un_set_path(&sa.un, k));
        ASSERT_OK_ERRNO(bind(socket_fd, &sa.sa, sockaddr_un_len(&sa.un)));
        ASSERT_OK_ERRNO(listen(socket_fd, 1));

        /* Ideally we'd just allocate this on the stack, but AddressSanitizer doesn't like it if threads
         * access each other's stack */
        struct fake_pressure_context *fp = new(struct fake_pressure_context, 1);
        ASSERT_NOT_NULL(fp);
        *fp = (struct fake_pressure_context) {
                .fifo_fd = fifo_fd,
                .socket_fd = socket_fd,
        };

        ASSERT_EQ(pthread_create(&th, NULL, fake_pressure_thread, TAKE_PTR(fp)), 0);

        ASSERT_OK_ERRNO(setenv(env_watch, j, /* override= */ true));
        ASSERT_OK_ERRNO(unsetenv(env_write));

        ASSERT_OK(add_pressure(e, &es, fake_pressure_callback, &value));
        ASSERT_OK(sd_event_source_set_description(es, "fifo event source"));

        ASSERT_OK_ERRNO(setenv(env_watch, k, /* override= */ true));
        ASSERT_OK_ERRNO(setenv(env_write, "aGVsbG8K", /* override= */ true));

        ASSERT_OK(add_pressure(e, &ef, fake_pressure_callback, &value));
        ASSERT_OK(sd_event_source_set_description(ef, "socket event source"));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_EQ(value, 7 * 'f' * 's');

        ASSERT_EQ(pthread_join(th, NULL), 0);
}

static int fake_pressure_wrapper(sd_event *e, sd_event_source **ret, sd_event_handler_t callback, void *userdata) {
        return sd_event_add_memory_pressure(e, ret, callback, userdata);
}

TEST(fake_memory_pressure) {
        test_fake_pressure("memory", fake_pressure_wrapper);
}

static int fake_cpu_pressure_wrapper(sd_event *e, sd_event_source **ret, sd_event_handler_t callback, void *userdata) {
        return sd_event_add_cpu_pressure(e, ret, callback, userdata);
}

TEST(fake_cpu_pressure) {
        test_fake_pressure("cpu", fake_cpu_pressure_wrapper);
}

static int fake_io_pressure_wrapper(sd_event *e, sd_event_source **ret, sd_event_handler_t callback, void *userdata) {
        return sd_event_add_io_pressure(e, ret, callback, userdata);
}

TEST(fake_io_pressure) {
        test_fake_pressure("io", fake_io_pressure_wrapper);
}

/* Shared infrastructure for real pressure tests */

struct real_pressure_context {
        sd_event_source *pid;
};

static int real_pressure_child_callback(sd_event_source *s, const siginfo_t *si, void *userdata) {
        ASSERT_NOT_NULL(s);
        ASSERT_NOT_NULL(si);

        log_notice("child dead");

        ASSERT_EQ(si->si_signo, SIGCHLD);
        ASSERT_EQ(si->si_status, SIGKILL);
        ASSERT_EQ(si->si_code, CLD_KILLED);

        ASSERT_OK(sd_event_exit(sd_event_source_get_event(s), 31));
        return 0;
}

/* Memory pressure real test */

static int real_memory_pressure_callback(sd_event_source *s, void *userdata) {
        struct real_pressure_context *c = ASSERT_PTR(userdata);
        const char *d;

        ASSERT_NOT_NULL(s);
        ASSERT_OK(sd_event_source_get_description(s, &d));

        log_notice("real memory pressure event: %s", d);

        sd_event_trim_memory();

        ASSERT_NOT_NULL(c->pid);
        ASSERT_OK(sd_event_source_send_child_signal(c->pid, SIGKILL, NULL, 0));
        c->pid = NULL;

        return 0;
}

#define MMAP_SIZE (10 * 1024 * 1024)

_noreturn_ static void real_pressure_eat_memory(int pipe_fd) {
        size_t ate = 0;

        /* Allocates and touches 10M at a time, until runs out of memory */

        char x;
        ASSERT_EQ(read(pipe_fd, &x, 1), 1); /* Wait for the GO! */

        for (;;) {
                void *p;

                p = mmap(NULL, MMAP_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                ASSERT_TRUE(p != MAP_FAILED);

                log_info("Eating another %s.", FORMAT_BYTES(MMAP_SIZE));

                memset(p, random_u32() & 0xFF, MMAP_SIZE);
                ate += MMAP_SIZE;

                log_info("Ate %s in total.", FORMAT_BYTES(ate));

                usleep_safe(50 * USEC_PER_MSEC);
        }
}

TEST(real_memory_pressure) {
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

        if (getuid() == 0)
                r = sd_bus_open_system(&bus);
        else
                r = sd_bus_open_user(&bus);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "can't connect to bus");

        ASSERT_OK(bus_wait_for_jobs_new(bus, &w));

        ASSERT_OK(bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit"));
        ASSERT_OK(asprintf(&scope, "test-%" PRIu64 ".scope", random_u64()));
        ASSERT_OK(sd_bus_message_append(m, "ss", scope, "fail"));
        ASSERT_OK(sd_bus_message_open_container(m, 'a', "(sv)"));
        ASSERT_OK(sd_bus_message_append(m, "(sv)", "PIDs", "au", 1, 0));
        ASSERT_OK(sd_bus_message_append(m, "(sv)", "MemoryAccounting", "b", true));
        ASSERT_OK(sd_bus_message_close_container(m));
        ASSERT_OK(sd_bus_message_append(m, "a(sa(sv))", 0));

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "can't issue transient unit call");

        ASSERT_OK(sd_bus_message_read(reply, "o", &object));

        ASSERT_OK(bus_wait_for_jobs_one(w, object, /* flags= */ BUS_WAIT_JOBS_LOG_ERROR, /* extra_args= */ NULL));

        ASSERT_OK(sd_event_default(&e));

        ASSERT_OK_ERRNO(pipe2(pipe_fd, O_CLOEXEC));

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork("(eat-memory)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM, &pidref);
        ASSERT_OK(r);
        if (r == 0) {
                real_pressure_eat_memory(pipe_fd[0]);
                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(event_add_child_pidref(e, &cs, &pidref, WEXITED, real_pressure_child_callback, NULL));
        ASSERT_OK(sd_event_source_set_child_process_own(cs, true));

        ASSERT_OK_ERRNO(unsetenv("MEMORY_PRESSURE_WATCH"));
        ASSERT_OK_ERRNO(unsetenv("MEMORY_PRESSURE_WRITE"));

        struct real_pressure_context context = {
                .pid = cs,
        };

        r = sd_event_add_memory_pressure(e, &es, real_memory_pressure_callback, &context);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "can't allocate memory pressure fd");

        ASSERT_OK(sd_event_source_set_description(es, "real pressure event source"));
        ASSERT_OK_ZERO(sd_event_source_set_memory_pressure_type(es, "some"));
        ASSERT_OK_POSITIVE(sd_event_source_set_memory_pressure_type(es, "full"));
        ASSERT_OK_ZERO(sd_event_source_set_memory_pressure_type(es, "full"));
        ASSERT_OK_POSITIVE(sd_event_source_set_memory_pressure_type(es, "some"));
        ASSERT_OK_ZERO(sd_event_source_set_memory_pressure_type(es, "some"));
        /* Unprivileged writes require a minimum of 2s otherwise the kernel will refuse the write.  */
        ASSERT_OK_POSITIVE(sd_event_source_set_memory_pressure_period(es, 70 * USEC_PER_MSEC, 2 * USEC_PER_SEC));
        ASSERT_OK_ZERO(sd_event_source_set_memory_pressure_period(es, 70 * USEC_PER_MSEC, 2 * USEC_PER_SEC));
        ASSERT_OK(sd_event_source_set_enabled(es, SD_EVENT_ONESHOT));

        _cleanup_free_ char *uo = NULL;
        ASSERT_NOT_NULL(uo = unit_dbus_path_from_name(scope));

        uint64_t mcurrent = UINT64_MAX;
        ASSERT_OK(sd_bus_get_property_trivial(bus, "org.freedesktop.systemd1", uo, "org.freedesktop.systemd1.Scope", "MemoryCurrent", &error, 't', &mcurrent));

        printf("current: %" PRIu64 "\n", mcurrent);
        if (mcurrent == UINT64_MAX)
                return (void) log_tests_skipped_errno(r, "memory accounting not available");

        m = sd_bus_message_unref(m);

        ASSERT_OK(bus_message_new_method_call(bus, &m, bus_systemd_mgr, "SetUnitProperties"));
        ASSERT_OK(sd_bus_message_append(m, "sb", scope, true));
        ASSERT_OK(sd_bus_message_open_container(m, 'a', "(sv)"));
        ASSERT_OK(sd_bus_message_append(m, "(sv)", "MemoryHigh", "t", mcurrent + (15 * 1024 * 1024)));
        ASSERT_OK(sd_bus_message_append(m, "(sv)", "MemoryMax", "t", mcurrent + (50 * 1024 * 1024)));
        ASSERT_OK(sd_bus_message_close_container(m));

        ASSERT_OK(sd_bus_call(bus, m, 0, NULL, NULL));

        /* Generate some memory allocations via mempool */
#define NN (1024)
        Hashmap **h = new(Hashmap*, NN);
        for (int i = 0; i < NN; i++)
                h[i] = hashmap_new(NULL);
        for (int i = 0; i < NN; i++)
                hashmap_free(h[i]);
        free(h);

        /* Now start eating memory */
        ASSERT_EQ(write(pipe_fd[1], &(const char) { 'x' }, 1), 1);

        ASSERT_OK(sd_event_loop(e));
        int ex = 0;
        ASSERT_OK(sd_event_get_exit_code(e, &ex));
        ASSERT_EQ(ex, 31);
}

/* CPU pressure real test */

static int real_cpu_pressure_callback(sd_event_source *s, void *userdata) {
        struct real_pressure_context *c = ASSERT_PTR(userdata);
        const char *d;

        ASSERT_NOT_NULL(s);
        ASSERT_OK(sd_event_source_get_description(s, &d));

        log_notice("real cpu pressure event: %s", d);

        ASSERT_NOT_NULL(c->pid);
        ASSERT_OK(sd_event_source_send_child_signal(c->pid, SIGKILL, NULL, 0));
        c->pid = NULL;

        return 0;
}

_noreturn_ static void real_pressure_eat_cpu(int pipe_fd) {
        char x;
        ASSERT_EQ(read(pipe_fd, &x, 1), 1); /* Wait for the GO! */

        /* Busy-loop to generate CPU pressure */
        for (;;)
                __asm__ volatile("" ::: "memory"); /* Prevent optimization */
}

TEST(real_cpu_pressure) {
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

        if (getuid() == 0)
                r = sd_bus_open_system(&bus);
        else
                r = sd_bus_open_user(&bus);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "can't connect to bus");

        ASSERT_OK(bus_wait_for_jobs_new(bus, &w));

        ASSERT_OK(bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit"));
        ASSERT_OK(asprintf(&scope, "test-%" PRIu64 ".scope", random_u64()));
        ASSERT_OK(sd_bus_message_append(m, "ss", scope, "fail"));
        ASSERT_OK(sd_bus_message_open_container(m, 'a', "(sv)"));
        ASSERT_OK(sd_bus_message_append(m, "(sv)", "PIDs", "au", 1, 0));
        ASSERT_OK(sd_bus_message_append(m, "(sv)", "CPUAccounting", "b", true));
        ASSERT_OK(sd_bus_message_close_container(m));
        ASSERT_OK(sd_bus_message_append(m, "a(sa(sv))", 0));

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "can't issue transient unit call");

        ASSERT_OK(sd_bus_message_read(reply, "o", &object));

        ASSERT_OK(bus_wait_for_jobs_one(w, object, /* flags= */ BUS_WAIT_JOBS_LOG_ERROR, /* extra_args= */ NULL));

        ASSERT_OK(sd_event_default(&e));

        ASSERT_OK_ERRNO(pipe2(pipe_fd, O_CLOEXEC));

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork("(eat-cpu)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM, &pidref);
        ASSERT_OK(r);
        if (r == 0) {
                real_pressure_eat_cpu(pipe_fd[0]);
                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(event_add_child_pidref(e, &cs, &pidref, WEXITED, real_pressure_child_callback, NULL));
        ASSERT_OK(sd_event_source_set_child_process_own(cs, true));

        ASSERT_OK_ERRNO(unsetenv("CPU_PRESSURE_WATCH"));
        ASSERT_OK_ERRNO(unsetenv("CPU_PRESSURE_WRITE"));

        struct real_pressure_context context = {
                .pid = cs,
        };

        r = sd_event_add_cpu_pressure(e, &es, real_cpu_pressure_callback, &context);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "can't allocate cpu pressure fd");

        ASSERT_OK(sd_event_source_set_description(es, "real pressure event source"));
        ASSERT_OK_ZERO(sd_event_source_set_cpu_pressure_type(es, "some"));
        /* Unprivileged writes require a minimum of 2s otherwise the kernel will refuse the write. */
        ASSERT_OK_POSITIVE(sd_event_source_set_cpu_pressure_period(es, 70 * USEC_PER_MSEC, 2 * USEC_PER_SEC));
        ASSERT_OK_ZERO(sd_event_source_set_cpu_pressure_period(es, 70 * USEC_PER_MSEC, 2 * USEC_PER_SEC));
        ASSERT_OK(sd_event_source_set_enabled(es, SD_EVENT_ONESHOT));

        m = sd_bus_message_unref(m);

        ASSERT_OK(bus_message_new_method_call(bus, &m, bus_systemd_mgr, "SetUnitProperties"));
        ASSERT_OK(sd_bus_message_append(m, "sb", scope, true));
        ASSERT_OK(sd_bus_message_open_container(m, 'a', "(sv)"));
        ASSERT_OK(sd_bus_message_append(m, "(sv)", "CPUQuotaPerSecUSec", "t", (uint64_t) 1000)); /* 0.1% CPU */
        ASSERT_OK(sd_bus_message_close_container(m));

        ASSERT_OK(sd_bus_call(bus, m, 0, NULL, NULL));

        /* Now start eating CPU */
        ASSERT_EQ(write(pipe_fd[1], &(const char) { 'x' }, 1), 1);

        ASSERT_OK(sd_event_loop(e));
        int ex = 0;
        ASSERT_OK(sd_event_get_exit_code(e, &ex));
        ASSERT_EQ(ex, 31);
}

/* IO pressure real test */

static int real_io_pressure_callback(sd_event_source *s, void *userdata) {
        struct real_pressure_context *c = ASSERT_PTR(userdata);
        const char *d;

        ASSERT_NOT_NULL(s);
        ASSERT_OK(sd_event_source_get_description(s, &d));

        log_notice("real io pressure event: %s", d);

        ASSERT_NOT_NULL(c->pid);
        ASSERT_OK(sd_event_source_send_child_signal(c->pid, SIGKILL, NULL, 0));
        c->pid = NULL;

        return 0;
}

_noreturn_ static void real_pressure_eat_io(int pipe_fd) {
        char x;
        ASSERT_EQ(read(pipe_fd, &x, 1), 1); /* Wait for the GO! */

        /* Write and fsync in a loop to generate IO pressure */
        for (;;) {
                _cleanup_close_ int fd = -EBADF;

                fd = open("/var/tmp/.io-pressure-test", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);
                if (fd < 0)
                        continue;

                char buf[4096];
                memset(buf, 'x', sizeof(buf));
                for (int i = 0; i < 256; i++)
                        if (write(fd, buf, sizeof(buf)) < 0)
                                break;
                (void) fsync(fd);
        }
}

TEST(real_io_pressure) {
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

        if (getuid() == 0)
                r = sd_bus_open_system(&bus);
        else
                r = sd_bus_open_user(&bus);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "can't connect to bus");

        ASSERT_OK(bus_wait_for_jobs_new(bus, &w));

        ASSERT_OK(bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit"));
        ASSERT_OK(asprintf(&scope, "test-%" PRIu64 ".scope", random_u64()));
        ASSERT_OK(sd_bus_message_append(m, "ss", scope, "fail"));
        ASSERT_OK(sd_bus_message_open_container(m, 'a', "(sv)"));
        ASSERT_OK(sd_bus_message_append(m, "(sv)", "PIDs", "au", 1, 0));
        ASSERT_OK(sd_bus_message_append(m, "(sv)", "IOAccounting", "b", true));
        ASSERT_OK(sd_bus_message_close_container(m));
        ASSERT_OK(sd_bus_message_append(m, "a(sa(sv))", 0));

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "can't issue transient unit call");

        ASSERT_OK(sd_bus_message_read(reply, "o", &object));

        ASSERT_OK(bus_wait_for_jobs_one(w, object, /* flags= */ BUS_WAIT_JOBS_LOG_ERROR, /* extra_args= */ NULL));

        ASSERT_OK(sd_event_default(&e));

        ASSERT_OK_ERRNO(pipe2(pipe_fd, O_CLOEXEC));

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork("(eat-io)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM, &pidref);
        ASSERT_OK(r);
        if (r == 0) {
                real_pressure_eat_io(pipe_fd[0]);
                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(event_add_child_pidref(e, &cs, &pidref, WEXITED, real_pressure_child_callback, NULL));
        ASSERT_OK(sd_event_source_set_child_process_own(cs, true));

        ASSERT_OK_ERRNO(unsetenv("IO_PRESSURE_WATCH"));
        ASSERT_OK_ERRNO(unsetenv("IO_PRESSURE_WRITE"));

        struct real_pressure_context context = {
                .pid = cs,
        };

        r = sd_event_add_io_pressure(e, &es, real_io_pressure_callback, &context);
        if (r < 0)
                return (void) log_tests_skipped_errno(r, "can't allocate io pressure fd");

        ASSERT_OK(sd_event_source_set_description(es, "real pressure event source"));
        ASSERT_OK_ZERO(sd_event_source_set_io_pressure_type(es, "some"));
        /* Unprivileged writes require a minimum of 2s otherwise the kernel will refuse the write. */
        ASSERT_OK_POSITIVE(sd_event_source_set_io_pressure_period(es, 70 * USEC_PER_MSEC, 2 * USEC_PER_SEC));
        ASSERT_OK_ZERO(sd_event_source_set_io_pressure_period(es, 70 * USEC_PER_MSEC, 2 * USEC_PER_SEC));
        ASSERT_OK(sd_event_source_set_enabled(es, SD_EVENT_ONESHOT));

        m = sd_bus_message_unref(m);

        ASSERT_OK(bus_message_new_method_call(bus, &m, bus_systemd_mgr, "SetUnitProperties"));
        ASSERT_OK(sd_bus_message_append(m, "sb", scope, true));
        ASSERT_OK(sd_bus_message_open_container(m, 'a', "(sv)"));
        ASSERT_OK(sd_bus_message_open_container(m, 'r', "sv"));
        ASSERT_OK(sd_bus_message_append(m, "s", "IOWriteBandwidthMax"));
        ASSERT_OK(sd_bus_message_open_container(m, 'v', "a(st)"));
        ASSERT_OK(sd_bus_message_append(m, "a(st)", 1, "/var/tmp", (uint64_t) 1024*1024)); /* 1M/s */
        ASSERT_OK(sd_bus_message_close_container(m));
        ASSERT_OK(sd_bus_message_close_container(m));
        ASSERT_OK(sd_bus_message_close_container(m));

        ASSERT_OK(sd_bus_call(bus, m, 0, NULL, NULL));

        /* Now start eating IO */
        ASSERT_EQ(write(pipe_fd[1], &(const char) { 'x' }, 1), 1);

        ASSERT_OK(sd_event_loop(e));
        int ex = 0;
        ASSERT_OK(sd_event_get_exit_code(e, &ex));
        ASSERT_EQ(ex, 31);
}

static int outro(void) {
        (void) unlink("/var/tmp/.io-pressure-test");
        hashmap_trim_pools();
        return 0;
}

DEFINE_TEST_MAIN_FULL(LOG_DEBUG, NULL, outro);
