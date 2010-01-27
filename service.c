/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <errno.h>
#include <signal.h>

#include "unit.h"
#include "service.h"
#include "load-fragment.h"
#include "load-dropin.h"
#include "log.h"

static const UnitActiveState state_translation_table[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = UNIT_INACTIVE,
        [SERVICE_START_PRE] = UNIT_ACTIVATING,
        [SERVICE_START] = UNIT_ACTIVATING,
        [SERVICE_START_POST] = UNIT_ACTIVATING,
        [SERVICE_RUNNING] = UNIT_ACTIVE,
        [SERVICE_RELOAD] = UNIT_ACTIVE_RELOADING,
        [SERVICE_STOP] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_STOP_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_STOP_POST] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGTERM] = UNIT_DEACTIVATING,
        [SERVICE_FINAL_SIGKILL] = UNIT_DEACTIVATING,
        [SERVICE_MAINTAINANCE] = UNIT_INACTIVE,
        [SERVICE_AUTO_RESTART] = UNIT_ACTIVATING,
};

static const char* const state_string_table[_SERVICE_STATE_MAX] = {
        [SERVICE_DEAD] = "dead",
        [SERVICE_START_PRE] = "start-pre",
        [SERVICE_START] = "start",
        [SERVICE_START_POST] = "post",
        [SERVICE_RUNNING] = "running",
        [SERVICE_RELOAD] = "reload",
        [SERVICE_STOP] = "stop",
        [SERVICE_STOP_SIGTERM] = "stop-sigterm",
        [SERVICE_STOP_SIGKILL] = "stop-sigkill",
        [SERVICE_STOP_POST] = "stop-post",
        [SERVICE_FINAL_SIGTERM] = "final-sigterm",
        [SERVICE_FINAL_SIGKILL] = "final-sigkill",
        [SERVICE_MAINTAINANCE] = "maintainance",
        [SERVICE_AUTO_RESTART] = "auto-restart",
};

static void service_done(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        free(s->pid_file);
        s->pid_file = NULL;

        exec_context_done(&s->exec_context);
        exec_command_free_array(s->exec_command, _SERVICE_EXEC_MAX);
        s->control_command = NULL;

        /* This will leak a process, but at least no memory or any of
         * our resources */
        if (s->main_pid > 0) {
                unit_unwatch_pid(u, s->main_pid);
                s->main_pid = 0;
        }

        if (s->control_pid > 0) {
                unit_unwatch_pid(u, s->control_pid);
                s->control_pid = 0;
        }

        unit_unwatch_timer(u, &s->timer_watch);
}

static int service_load_sysv(Service *s) {
        assert(s);

        /* Load service data from SysV init scripts, preferably with
         * LSB headers ... */

        return -ENOENT;
}

static int service_init(Unit *u) {
        int r;
        Service *s = SERVICE(u);

        assert(s);

        /* First, reset everything to the defaults, in case this is a
         * reload */

        s->type = 0;
        s->restart = 0;

        s->timeout_usec = DEFAULT_TIMEOUT_USEC;
        s->restart_usec = DEFAULT_RESTART_USEC;

        exec_context_init(&s->exec_context);

        s->timer_watch.type = WATCH_INVALID;

        s->state = SERVICE_DEAD;

        /* Load a .service file */
        r = unit_load_fragment(u);

        /* Load a classic init script as a fallback */
        if (r == -ENOENT)
                r = service_load_sysv(s);

        if (r < 0) {
                service_done(u);
                return r;
        }

        /* Load dropin directory data */
        if ((r = unit_load_dropin(u)) < 0) {
                service_done(u);
                return r;
        }

        return 0;
}

static void service_dump(Unit *u, FILE *f, const char *prefix) {

        static const char* const command_table[_SERVICE_EXEC_MAX] = {
                [SERVICE_EXEC_START_PRE] = "ExecStartPre",
                [SERVICE_EXEC_START] = "ExecStart",
                [SERVICE_EXEC_START_POST] = "ExecStartPost",
                [SERVICE_EXEC_RELOAD] = "ExecReload",
                [SERVICE_EXEC_STOP] = "ExecStop",
                [SERVICE_EXEC_STOP_POST] = "ExecStopPost",
        };

        ServiceExecCommand c;
        Service *s = SERVICE(u);
        char *prefix2;

        assert(s);

        prefix2 = strappend(prefix, "\t");
        if (!prefix2)
                prefix2 = "";

        fprintf(f,
                "%sService State: %s\n",
                prefix, state_string_table[s->state]);

        if (s->pid_file)
                fprintf(f,
                        "%sPIDFile: %s\n",
                        prefix, s->pid_file);


        exec_context_dump(&s->exec_context, f, prefix);

        for (c = 0; c < _SERVICE_EXEC_MAX; c++) {

                if (!s->exec_command[c])
                        continue;

                fprintf(f, "%s→ %s:\n",
                        prefix, command_table[c]);

                exec_command_dump_list(s->exec_command[c], f, prefix2);
        }

        free(prefix2);
}

static int service_load_pid_file(Service *s) {
        char *k;
        unsigned long p;
        int r;

        assert(s);

        if (s->main_pid_known)
                return 0;

        if (!s->pid_file)
                return -ENOENT;

        if ((r = read_one_line_file(s->pid_file, &k)) < 0)
                return r;

        if ((r = safe_atolu(k, &p)) < 0) {
                free(k);
                return r;
        }

        if ((unsigned long) (pid_t) p != p)
                return -ERANGE;

        s->main_pid = p;
        s->main_pid_known = true;

        return 0;
}

static int service_notify_sockets(Service *s) {
        Iterator i;
        char *t;

        assert(s);

        SET_FOREACH(t, UNIT(s)->meta.names, i) {
                char *k;
                Unit *p;

                /* Look for all socket objects that go by any of our
                 * units and collect their fds */

                if (!(k = unit_name_change_suffix(t, ".socket")))
                        return -ENOMEM;

                p = manager_get_unit(UNIT(s)->meta.manager, k);
                free(k);

                if (!p)
                        continue;

                socket_notify_service_dead(SOCKET(p));
        }

        return 0;
}

static void service_set_state(Service *s, ServiceState state) {
        ServiceState old_state;
        assert(s);

        old_state = s->state;
        s->state = state;

        if (state != SERVICE_START_PRE &&
            state != SERVICE_START &&
            state != SERVICE_START_POST &&
            state != SERVICE_RELOAD &&
            state != SERVICE_STOP &&
            state != SERVICE_STOP_SIGTERM &&
            state != SERVICE_STOP_SIGKILL &&
            state != SERVICE_STOP_POST &&
            state != SERVICE_FINAL_SIGTERM &&
            state != SERVICE_FINAL_SIGKILL &&
            state != SERVICE_AUTO_RESTART)
                unit_unwatch_timer(UNIT(s), &s->timer_watch);

        if (state != SERVICE_START_POST &&
            state != SERVICE_RUNNING &&
            state != SERVICE_RELOAD &&
            state != SERVICE_STOP &&
            state != SERVICE_STOP_SIGTERM &&
            state != SERVICE_STOP_SIGKILL)
                if (s->main_pid > 0) {
                        unit_unwatch_pid(UNIT(s), s->main_pid);
                        s->main_pid = 0;
                }

        if (state != SERVICE_START_PRE &&
            state != SERVICE_START &&
            state != SERVICE_START_POST &&
            state != SERVICE_RELOAD &&
            state != SERVICE_STOP &&
            state != SERVICE_STOP_SIGTERM &&
            state != SERVICE_STOP_SIGKILL &&
            state != SERVICE_STOP_POST &&
            state != SERVICE_FINAL_SIGTERM &&
            state != SERVICE_FINAL_SIGKILL)
                if (s->control_pid > 0) {
                        unit_unwatch_pid(UNIT(s), s->control_pid);
                        s->control_pid = 0;
                }

        if (state != SERVICE_START_PRE &&
            state != SERVICE_START &&
            state != SERVICE_START_POST &&
            state != SERVICE_RELOAD &&
            state != SERVICE_STOP &&
            state != SERVICE_STOP_POST)
                s->control_command = NULL;

        if (state == SERVICE_DEAD ||
            state == SERVICE_STOP ||
            state == SERVICE_STOP_SIGTERM ||
            state == SERVICE_STOP_SIGKILL ||
            state == SERVICE_STOP_POST ||
            state == SERVICE_FINAL_SIGTERM ||
            state == SERVICE_FINAL_SIGKILL ||
            state == SERVICE_MAINTAINANCE ||
            state == SERVICE_AUTO_RESTART)
                service_notify_sockets(s);

        log_debug("%s changing %s → %s", unit_id(UNIT(s)), state_string_table[old_state], state_string_table[state]);

        unit_notify(UNIT(s), state_translation_table[old_state], state_translation_table[state]);
}

static int service_collect_fds(Service *s, int **fds, unsigned *n_fds) {
        Iterator i;
        int r;
        int *rfds = NULL;
        unsigned rn_fds = 0;
        char *t;

        assert(s);
        assert(fds);
        assert(n_fds);

        SET_FOREACH(t, UNIT(s)->meta.names, i) {
                char *k;
                Unit *p;
                int *cfds;
                unsigned cn_fds;

                /* Look for all socket objects that go by any of our
                 * units and collect their fds */

                if (!(k = unit_name_change_suffix(t, ".socket"))) {
                        r = -ENOMEM;
                        goto fail;
                }

                p = manager_get_unit(UNIT(s)->meta.manager, k);
                free(k);

                if (!p)
                        continue;

                if ((r = socket_collect_fds(SOCKET(p), &cfds, &cn_fds)) < 0)
                        goto fail;

                if (!cfds)
                        continue;

                if (!rfds) {
                        rfds = cfds;
                        rn_fds = cn_fds;
                } else {
                        int *t;

                        if (!(t = new(int, rn_fds+cn_fds))) {
                                free(cfds);
                                r = -ENOMEM;
                                goto fail;
                        }

                        memcpy(t, rfds, rn_fds);
                        memcpy(t+rn_fds, cfds, cn_fds);
                        free(rfds);
                        free(cfds);

                        rfds = t;
                        rn_fds = rn_fds+cn_fds;
                }
        }

        *fds = rfds;
        *n_fds = rn_fds;
        return 0;

fail:
        free(rfds);
        return r;
}

static int service_spawn(Service *s, ExecCommand *c, bool timeout, bool pass_fds, pid_t *_pid) {
        pid_t pid;
        int r;
        int *fds = NULL;
        unsigned n_fds = 0;

        assert(s);
        assert(c);
        assert(_pid);

        if (pass_fds)
                if ((r = service_collect_fds(s, &fds, &n_fds)) < 0)
                        goto fail;

        if (timeout) {
                if ((r = unit_watch_timer(UNIT(s), s->timeout_usec, &s->timer_watch)) < 0)
                        goto fail;
        } else
                unit_unwatch_timer(UNIT(s), &s->timer_watch);

        if ((r = exec_spawn(c, &s->exec_context, fds, n_fds, &pid)) < 0)
                goto fail;

        if ((r = unit_watch_pid(UNIT(s), pid)) < 0)
                /* FIXME: we need to do something here */
                goto fail;

        free(fds);
        *_pid = pid;

        return 0;

fail:
        free(fds);

        if (timeout)
                unit_unwatch_timer(UNIT(s), &s->timer_watch);

        return r;
}

static void service_enter_dead(Service *s, bool success, bool allow_restart) {
        int r;
        assert(s);

        if (!success)
                s->failure = true;

        if (allow_restart &&
            (s->restart == SERVICE_RESTART_ALWAYS ||
             (s->restart == SERVICE_RESTART_ON_SUCCESS && !s->failure))) {

                if ((r = unit_watch_timer(UNIT(s), s->restart_usec, &s->timer_watch)) < 0)
                        goto fail;

                service_set_state(s, SERVICE_AUTO_RESTART);
        } else
                service_set_state(s, s->failure ? SERVICE_MAINTAINANCE : SERVICE_DEAD);

        return;

fail:
        log_warning("%s failed to run install restart timer: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_dead(s, false, false);
}

static void service_enter_signal(Service *s, ServiceState state, bool success);

static void service_enter_stop_post(Service *s, bool success) {
        int r;
        assert(s);

        if (!success)
                s->failure = true;

        if ((s->control_command = s->exec_command[SERVICE_EXEC_STOP_POST])) {

                if ((r = service_spawn(s, s->control_command, true, false, &s->control_pid)) < 0)
                        goto fail;

                service_set_state(s, SERVICE_STOP_POST);
        } else
                service_enter_dead(s, true, true);

        return;

fail:
        log_warning("%s failed to run stop executable: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_signal(s, SERVICE_FINAL_SIGTERM, false);
}

static void service_enter_signal(Service *s, ServiceState state, bool success) {
        int r;
        bool sent = false;

        assert(s);

        if (!success)
                s->failure = true;

        if (s->main_pid > 0 || s->control_pid > 0) {
                int sig;

                sig = (state == SERVICE_STOP_SIGTERM || state == SERVICE_FINAL_SIGTERM) ? SIGTERM : SIGKILL;

                r = 0;
                if (s->main_pid > 0) {
                        if (kill(s->main_pid, sig) < 0 && errno != ESRCH)
                                r = -errno;
                        else
                                sent = true;
                }

                if (s->control_pid > 0) {
                        if (kill(s->control_pid, sig) < 0 && errno != ESRCH)
                                r = -errno;
                        else
                                sent = true;
                }

                if (r < 0)
                        goto fail;

                service_set_state(s, state);
        } else
                service_enter_dead(s, true, true);

        return;

fail:
        log_warning("%s failed to kill processes: %s", unit_id(UNIT(s)), strerror(-r));

        if (sent)  {
                s->failure = true;
                service_set_state(s, state);
        } else if (state == SERVICE_STOP_SIGTERM || state == SERVICE_STOP_SIGKILL)
                service_enter_stop_post(s, false);
        else
                service_enter_dead(s, false, true);
}

static void service_enter_stop(Service *s, bool success) {
        int r;
        assert(s);

        if (!success)
                s->failure = true;

        if ((s->control_command = s->exec_command[SERVICE_EXEC_STOP])) {

                if ((r = service_spawn(s, s->control_command, true, false, &s->control_pid)) < 0)
                        goto fail;

                service_set_state(s, SERVICE_STOP);
        } else
                service_enter_signal(s, SERVICE_STOP_SIGTERM, true);

        return;

fail:
        log_warning("%s failed to run stop executable: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_signal(s, SERVICE_STOP_SIGTERM, false);
}

static void service_enter_start_post(Service *s) {
        int r;
        assert(s);

        if ((s->control_command = s->exec_command[SERVICE_EXEC_START_POST])) {

                if ((r = service_spawn(s, s->control_command, true, false, &s->control_pid)) < 0)
                        goto fail;

                service_set_state(s, SERVICE_START_POST);
        } else
                service_set_state(s, SERVICE_RUNNING);

        return;

fail:
        log_warning("%s failed to run start-post executable: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_stop(s, false);
}

static void service_enter_start(Service *s) {
        pid_t pid;
        int r;

        assert(s);

        assert(s->exec_command[SERVICE_EXEC_START]);
        assert(!s->exec_command[SERVICE_EXEC_START]->command_next);

        if ((r = service_spawn(s, s->exec_command[SERVICE_EXEC_START], s->type == SERVICE_FORKING, true, &pid)) < 0)
                goto fail;

        if (s->type == SERVICE_SIMPLE) {
                /* For simple services we immediately start
                 * the START_POST binaries. */

                s->main_pid = pid;
                s->main_pid_known = true;
                service_enter_start_post(s);

        } else  if (s->type == SERVICE_FORKING) {

                /* For forking services we wait until the start
                 * process exited. */

                s->control_pid = pid;
                s->control_command = s->exec_command[SERVICE_EXEC_START];
                service_set_state(s, SERVICE_START);
        } else
                assert_not_reached("Unknown service type");

        return;

fail:
        log_warning("%s failed to run start exectuable: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_stop(s, false);
}

static void service_enter_start_pre(Service *s) {
        int r;

        assert(s);

        if ((s->control_command = s->exec_command[SERVICE_EXEC_START_PRE])) {

                if ((r = service_spawn(s, s->control_command, true, false, &s->control_pid)) < 0)
                        goto fail;

                service_set_state(s, SERVICE_START_PRE);
        } else
                service_enter_start(s);

        return;

fail:
        log_warning("%s failed to run start-pre executable: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_dead(s, false, true);
}

static void service_enter_restart(Service *s) {
        int r;
        assert(s);

        if ((r = manager_add_job(UNIT(s)->meta.manager, JOB_START, UNIT(s), JOB_FAIL, false, NULL)) < 0)
                goto fail;

        log_debug("%s scheduled restart job.", unit_id(UNIT(s)));
        service_enter_dead(s, true, false);
        return;

fail:

        log_warning("%s failed to schedule restart job: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_dead(s, false, false);
}

static void service_enter_reload(Service *s) {
        int r;

        assert(s);

        if ((s->control_command = s->exec_command[SERVICE_EXEC_RELOAD])) {

                if ((r = service_spawn(s, s->control_command, true, false, &s->control_pid)) < 0)
                        goto fail;

                service_set_state(s, SERVICE_RELOAD);
        } else
                service_set_state(s, SERVICE_RUNNING);

        return;

fail:
        log_warning("%s failed to run reload executable: %s", unit_id(UNIT(s)), strerror(-r));
        service_enter_stop(s, false);
}

static void service_run_next(Service *s, bool success) {
        int r;

        assert(s);
        assert(s->control_command);
        assert(s->control_command->command_next);

        if (!success)
                s->failure = true;

        s->control_command = s->control_command->command_next;

        if ((r = service_spawn(s, s->control_command, true, false, &s->control_pid)) < 0)
                goto fail;

        return;

fail:
        log_warning("%s failed to run spawn next executable: %s", unit_id(UNIT(s)), strerror(-r));

        if (s->state == SERVICE_STOP)
                service_enter_stop_post(s, false);
        else if (s->state == SERVICE_STOP_POST)
                service_enter_dead(s, false, true);
        else
                service_enter_stop(s, false);
}

static int service_start(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        /* We cannot fulfill this request right now, try again later
         * please! */
        if (s->state == SERVICE_STOP ||
            s->state == SERVICE_STOP_SIGTERM ||
            s->state == SERVICE_STOP_SIGKILL ||
            s->state == SERVICE_STOP_POST ||
            s->state == SERVICE_FINAL_SIGTERM ||
            s->state == SERVICE_FINAL_SIGKILL)
                return -EAGAIN;

        /* Already on it! */
        if (s->state == SERVICE_START_PRE ||
            s->state == SERVICE_START ||
            s->state == SERVICE_START_POST)
                return 0;

        assert(s->state == SERVICE_DEAD || s->state == SERVICE_MAINTAINANCE || s->state == SERVICE_AUTO_RESTART);

        s->failure = false;
        s->main_pid_known = false;

        service_enter_start_pre(s);
        return 0;
}

static int service_stop(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        if (s->state == SERVICE_START_PRE ||
            s->state == SERVICE_START ||
            s->state == SERVICE_START_POST ||
            s->state == SERVICE_RELOAD)
                return -EAGAIN;

        if (s->state == SERVICE_AUTO_RESTART) {
                service_set_state(s, SERVICE_DEAD);
                return 0;
        }

        assert(s->state == SERVICE_RUNNING);

        service_enter_stop(s, true);
        return 0;
}

static int service_reload(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        assert(s->state == SERVICE_RUNNING);

        service_enter_reload(s);
        return 0;
}

static bool service_can_reload(Unit *u) {
        Service *s = SERVICE(u);

        assert(s);

        return !!s->exec_command[SERVICE_EXEC_RELOAD];
}

static UnitActiveState service_active_state(Unit *u) {
        assert(u);

        return state_translation_table[SERVICE(u)->state];
}

static int main_pid_good(Service *s) {
        assert(s);

        /* Returns 0 if the pid is dead, 1 if it is good, -1 if we
         * don't know */

        /* If we know the pid file, then lets just check if it is
         * still valid */
        if (s->main_pid_known)
                return s->main_pid > 0;

        /* We don't know the pid */
        return -1;
}

static bool control_pid_good(Service *s) {
        assert(s);

        return s->control_pid > 0;
}

static void service_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        Service *s = SERVICE(u);
        bool success;

        assert(s);
        assert(pid >= 0);

        success = code == CLD_EXITED && status == 0;
        s->failure = s->failure || !success;

        if (s->main_pid == pid) {

                exec_status_fill(&s->main_exec_status, pid, code, status);
                s->main_pid = 0;

                if (s->type == SERVICE_SIMPLE) {
                        assert(s->exec_command[SERVICE_EXEC_START]);
                        s->exec_command[SERVICE_EXEC_START]->exec_status = s->main_exec_status;
                }

                log_debug("%s: main process exited, code=%s status=%i", unit_id(u), sigchld_code(code), status);

                /* The service exited, so the service is officially
                 * gone. */

                switch (s->state) {

                case SERVICE_START_POST:
                case SERVICE_RELOAD:
                case SERVICE_STOP:
                        /* Need to wait until the operation is
                         * done */
                        break;

                case SERVICE_RUNNING:
                        service_enter_stop(s, success);
                        break;

                case SERVICE_STOP_SIGTERM:
                case SERVICE_STOP_SIGKILL:

                        if (!control_pid_good(s))
                                service_enter_stop_post(s, success);

                        /* If there is still a control process, wait for that first */
                        break;

                default:
                        assert_not_reached("Uh, main process died at wrong time.");
                }

        } else if (s->control_pid == pid) {
                assert(s->control_command);

                exec_status_fill(&s->control_command->exec_status, pid, code, status);
                s->control_pid = 0;

                log_debug("%s: control process exited, code=%s status=%i", unit_id(u), sigchld_code(code), status);

                /* If we are shutting things down anyway we
                 * don't care about failing commands. */

                if (s->control_command->command_next &&
                    (success || (s->state == SERVICE_EXEC_STOP || s->state == SERVICE_EXEC_STOP_POST)))

                        /* There is another command to *
                         * execute, so let's do that. */

                        service_run_next(s, success);

                else {
                        /* No further commands for this step, so let's
                         * figure out what to do next */

                        log_debug("%s got final SIGCHLD for state %s", unit_id(u), state_string_table[s->state]);

                        switch (s->state) {

                        case SERVICE_START_PRE:
                                if (success)
                                        service_enter_start(s);
                                else
                                        service_enter_stop(s, false);
                                break;

                        case SERVICE_START:
                                assert(s->type == SERVICE_FORKING);

                                /* Let's try to load the pid
                                 * file here if we can. We
                                 * ignore the return value,
                                 * since the PID file might
                                 * actually be created by a
                                 * START_POST script */

                                if (success) {
                                        if (s->pid_file)
                                                service_load_pid_file(s);

                                        service_enter_start_post(s);
                                } else
                                        service_enter_stop(s, false);

                                break;

                        case SERVICE_START_POST:
                                if (success && s->pid_file && !s->main_pid_known) {
                                        int r;

                                        /* Hmm, let's see if we can
                                         * load the pid now after the
                                         * start-post scripts got
                                         * executed. */

                                        if ((r = service_load_pid_file(s)) < 0)
                                                log_warning("%s: failed to load PID file %s: %s", unit_id(UNIT(s)), s->pid_file, strerror(-r));
                                }

                                /* Fall through */

                        case SERVICE_RELOAD:
                                if (success) {
                                        if (main_pid_good(s) != 0)
                                                service_set_state(s, SERVICE_RUNNING);
                                        else
                                                service_enter_stop(s, true);
                                } else
                                        service_enter_stop(s, false);

                                break;

                        case SERVICE_STOP:
                                if (main_pid_good(s) > 0)
                                        /* Still not dead and we know the PID? Let's go hunting. */
                                        service_enter_signal(s, SERVICE_STOP_SIGTERM, success);
                                else
                                        service_enter_stop_post(s, success);
                                break;

                        case SERVICE_STOP_SIGTERM:
                        case SERVICE_STOP_SIGKILL:
                                if (main_pid_good(s) <= 0)
                                        service_enter_stop_post(s, success);

                                /* If there is still a service
                                 * process around, wait until
                                 * that one quit, too */
                                break;

                        case SERVICE_STOP_POST:
                        case SERVICE_FINAL_SIGTERM:
                        case SERVICE_FINAL_SIGKILL:
                                service_enter_dead(s, success, true);
                                break;

                        default:
                                assert_not_reached("Uh, control process died at wrong time.");
                        }
                }
        } else
                assert_not_reached("Got SIGCHLD for unkown PID");
}

static void service_timer_event(Unit *u, uint64_t elapsed, Watch* w) {
        Service *s = SERVICE(u);

        assert(s);
        assert(elapsed == 1);

        assert(w == &s->timer_watch);

        switch (s->state) {

        case SERVICE_START_PRE:
        case SERVICE_START:
        case SERVICE_START_POST:
        case SERVICE_RELOAD:
                log_warning("%s operation timed out. Stopping.", unit_id(u));
                service_enter_stop(s, false);
                break;

        case SERVICE_STOP:
                log_warning("%s stopping timed out. Terminating.", unit_id(u));
                service_enter_signal(s, SERVICE_STOP_SIGTERM, false);
                break;

        case SERVICE_STOP_SIGTERM:
                log_warning("%s stopping timed out. Killing.", unit_id(u));
                service_enter_signal(s, SERVICE_STOP_SIGKILL, false);
                break;

        case SERVICE_STOP_SIGKILL:
                /* Uh, wie sent a SIGKILL and it is still not gone?
                 * Must be something we cannot kill, so let's just be
                 * weirded out and continue */

                log_warning("%s still around after SIGKILL. Ignoring.", unit_id(u));
                service_enter_stop_post(s, false);
                break;

        case SERVICE_STOP_POST:
                log_warning("%s stopping timed out (2). Terminating.", unit_id(u));
                service_enter_signal(s, SERVICE_FINAL_SIGTERM, false);
                break;

        case SERVICE_FINAL_SIGTERM:
                log_warning("%s stopping timed out (2). Killing.", unit_id(u));
                service_enter_signal(s, SERVICE_FINAL_SIGKILL, false);
                break;

        case SERVICE_FINAL_SIGKILL:
                log_warning("%s still around after SIGKILL (2). Entering maintainance mode.", unit_id(u));
                service_enter_dead(s, false, true);
                break;

        case SERVICE_AUTO_RESTART:
                log_debug("%s holdoff time over, scheduling restart.", unit_id(u));
                service_enter_restart(s);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }
}

const UnitVTable service_vtable = {
        .suffix = ".service",

        .init = service_init,
        .done = service_done,

        .dump = service_dump,

        .start = service_start,
        .stop = service_stop,
        .reload = service_reload,

        .can_reload = service_can_reload,

        .active_state = service_active_state,

        .sigchld_event = service_sigchld_event,
        .timer_event = service_timer_event,
};
