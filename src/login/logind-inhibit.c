/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "env-file.h"
#include "errno-list.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "logind-dbus.h"
#include "logind-inhibit.h"
#include "missing_threads.h"
#include "mkdir-label.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-table.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "user-util.h"

static void inhibitor_remove_fifo(Inhibitor *i);

int inhibitor_new(Manager *m, const char* id, Inhibitor **ret) {
        _cleanup_(inhibitor_freep) Inhibitor *i = NULL;
        int r;

        assert(m);
        assert(id);
        assert(ret);

        i = new(Inhibitor, 1);
        if (!i)
                return -ENOMEM;

        *i = (Inhibitor) {
                .manager = m,
                .id = strdup(id),
                .state_file = path_join("/run/systemd/inhibit/", id),
                .what = _INHIBIT_WHAT_INVALID,
                .mode = _INHIBIT_MODE_INVALID,
                .uid = UID_INVALID,
                .fifo_fd = -EBADF,
                .pid = PIDREF_NULL,
        };

        if (!i->id || !i->state_file)
                return -ENOMEM;

        r = hashmap_put(m->inhibitors, i->id, i);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(i);
        return 0;
}

Inhibitor* inhibitor_free(Inhibitor *i) {

        if (!i)
                return NULL;

        free(i->who);
        free(i->why);

        sd_event_source_unref(i->event_source);
        safe_close(i->fifo_fd);

        hashmap_remove(i->manager->inhibitors, i->id);

        /* Note that we don't remove neither the state file nor the fifo path here, since we want both to
         * survive daemon restarts */
        free(i->fifo_path);
        free(i->state_file);
        free(i->id);

        pidref_done(&i->pid);

        return mfree(i);
}

static int inhibitor_save(Inhibitor *i) {
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(i);

        r = mkdir_safe_label("/run/systemd/inhibit", 0755, 0, 0, MKDIR_WARN_MODE);
        if (r < 0)
                goto fail;

        r = fopen_temporary(i->state_file, &f, &temp_path);
        if (r < 0)
                goto fail;

        (void) fchmod(fileno(f), 0644);

        fprintf(f,
                "# This is private data. Do not parse.\n"
                "WHAT=%s\n"
                "MODE=%s\n"
                "UID="UID_FMT"\n"
                "PID="PID_FMT"\n",
                inhibit_what_to_string(i->what),
                inhibit_mode_to_string(i->mode),
                i->uid,
                i->pid.pid);

        if (i->who) {
                _cleanup_free_ char *cc = NULL;

                cc = cescape(i->who);
                if (!cc) {
                        r = -ENOMEM;
                        goto fail;
                }

                fprintf(f, "WHO=%s\n", cc);
        }

        if (i->why) {
                _cleanup_free_ char *cc = NULL;

                cc = cescape(i->why);
                if (!cc) {
                        r = -ENOMEM;
                        goto fail;
                }

                fprintf(f, "WHY=%s\n", cc);
        }

        if (i->fifo_path)
                fprintf(f, "FIFO=%s\n", i->fifo_path);

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, i->state_file) < 0) {
                r = -errno;
                goto fail;
        }

        temp_path = mfree(temp_path);
        return 0;

fail:
        (void) unlink(i->state_file);

        return log_error_errno(r, "Failed to save inhibit data %s: %m", i->state_file);
}

static int bus_manager_send_inhibited_change(Inhibitor *i) {
        const char *property;

        assert(i);

        property = IN_SET(i->mode, INHIBIT_BLOCK, INHIBIT_BLOCK_WEAK) ? "BlockInhibited" : "DelayInhibited";

        return manager_send_changed(i->manager, property, NULL);
}

int inhibitor_start(Inhibitor *i) {
        assert(i);

        if (i->started)
                return 0;

        dual_timestamp_now(&i->since);

        log_debug("Inhibitor %s (%s) pid="PID_FMT" uid="UID_FMT" mode=%s started.",
                  strna(i->who), strna(i->why),
                  i->pid.pid, i->uid,
                  inhibit_mode_to_string(i->mode));

        i->started = true;

        inhibitor_save(i);

        bus_manager_send_inhibited_change(i);

        return 0;
}

void inhibitor_stop(Inhibitor *i) {
        assert(i);

        if (i->started)
                log_debug("Inhibitor %s (%s) pid="PID_FMT" uid="UID_FMT" mode=%s stopped.",
                          strna(i->who), strna(i->why),
                          i->pid.pid, i->uid,
                          inhibit_mode_to_string(i->mode));

        inhibitor_remove_fifo(i);

        if (i->state_file)
                (void) unlink(i->state_file);

        i->started = false;

        bus_manager_send_inhibited_change(i);
}

int inhibitor_load(Inhibitor *i) {
        _cleanup_free_ char *what = NULL, *uid = NULL, *pid = NULL, *who = NULL, *why = NULL, *mode = NULL;
        InhibitWhat w;
        InhibitMode mm;
        char *cc;
        ssize_t l;
        int r;

        r = parse_env_file(NULL, i->state_file,
                           "WHAT", &what,
                           "UID", &uid,
                           "PID", &pid,
                           "WHO", &who,
                           "WHY", &why,
                           "MODE", &mode,
                           "FIFO", &i->fifo_path);
        if (r < 0)
                return log_error_errno(r, "Failed to read %s: %m", i->state_file);

        w = what ? inhibit_what_from_string(what) : 0;
        if (w >= 0)
                i->what = w;

        mm = mode ? inhibit_mode_from_string(mode) : INHIBIT_BLOCK;
        if  (mm >= 0)
                i->mode = mm;

        if (uid) {
                r = parse_uid(uid, &i->uid);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse UID of inhibitor: %s", uid);
        }

        if (pid) {
                pidref_done(&i->pid);
                r = pidref_set_pidstr(&i->pid, pid);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse PID of inhibitor: %s", pid);
        }

        if (who) {
                l = cunescape(who, 0, &cc);
                if (l < 0)
                        return log_debug_errno(l, "Failed to unescape \"who\" of inhibitor: %m");

                free_and_replace(i->who, cc);
        }

        if (why) {
                l = cunescape(why, 0, &cc);
                if (l < 0)
                        return log_debug_errno(l, "Failed to unescape \"why\" of inhibitor: %m");

                free_and_replace(i->why, cc);
        }

        if (i->fifo_path) {
                _cleanup_close_ int fd = -EBADF;

                /* Let's reopen the FIFO on both sides, and close the writing side right away */
                fd = inhibitor_create_fifo(i);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to reopen FIFO: %m");
        }

        return 0;
}

static int inhibitor_dispatch_fifo(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Inhibitor *i = ASSERT_PTR(userdata);

        assert(s);
        assert(fd == i->fifo_fd);

        inhibitor_stop(i);
        inhibitor_free(i);

        return 0;
}

int inhibitor_create_fifo(Inhibitor *i) {
        int r;

        assert(i);

        /* Create FIFO */
        if (!i->fifo_path) {
                r = mkdir_safe_label("/run/systemd/inhibit", 0755, 0, 0, MKDIR_WARN_MODE);
                if (r < 0)
                        return r;

                i->fifo_path = strjoin("/run/systemd/inhibit/", i->id, ".ref");
                if (!i->fifo_path)
                        return -ENOMEM;

                if (mkfifo(i->fifo_path, 0600) < 0 && errno != EEXIST)
                        return -errno;
        }

        /* Open reading side */
        if (i->fifo_fd < 0) {
                i->fifo_fd = open(i->fifo_path, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
                if (i->fifo_fd < 0)
                        return -errno;
        }

        if (!i->event_source) {
                r = sd_event_add_io(i->manager->event, &i->event_source, i->fifo_fd, 0, inhibitor_dispatch_fifo, i);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(i->event_source, SD_EVENT_PRIORITY_IDLE-10);
                if (r < 0)
                        return r;

                (void) sd_event_source_set_description(i->event_source, "inhibitor-ref");
        }

        /* Open writing side */
        return RET_NERRNO(open(i->fifo_path, O_WRONLY|O_CLOEXEC|O_NONBLOCK));
}

static void inhibitor_remove_fifo(Inhibitor *i) {
        assert(i);

        i->event_source = sd_event_source_unref(i->event_source);
        i->fifo_fd = safe_close(i->fifo_fd);

        if (i->fifo_path) {
                (void) unlink(i->fifo_path);
                i->fifo_path = mfree(i->fifo_path);
        }
}

bool inhibitor_is_orphan(Inhibitor *i) {
        assert(i);

        if (!i->started)
                return true;

        if (!i->fifo_path)
                return true;

        if (i->fifo_fd < 0)
                return true;

        if (pipe_eof(i->fifo_fd) != 0)
                return true;

        return false;
}

InhibitWhat manager_inhibit_what(Manager *m, InhibitMode mode) {
        Inhibitor *i;
        InhibitWhat what = 0;

        assert(m);

        HASHMAP_FOREACH(i, m->inhibitors)
                if (i->started && i->mode == mode)
                        what |= i->what;

        return what;
}

static int pidref_is_active_session(Manager *m, const PidRef *pid) {
        Session *s;
        int r;

        assert(m);
        assert(pid);

        /* Get client session. This is not what you are looking for these days.
         * FIXME #6852 */
        r = manager_get_session_by_pidref(m, pid, &s);
        if (r < 0)
                return r;

        /* If there's no session assigned to it, then it's globally active on all ttys */
        if (r == 0)
                return 1;

        return session_is_active(s);
}

bool manager_is_inhibited(
                Manager *m,
                InhibitWhat w,
                dual_timestamp *since,
                ManagerIsInhibitedFlags flags,
                uid_t uid_to_ignore,
                Inhibitor **ret_offending) {

        Inhibitor *i, *offending = NULL;
        struct dual_timestamp ts = DUAL_TIMESTAMP_NULL;
        bool inhibited = false;

        assert(m);
        assert(w > 0);
        assert(w < _INHIBIT_WHAT_MAX);

        HASHMAP_FOREACH(i, m->inhibitors) {
                if (!i->started)
                        continue;

                if (!(i->what & w))
                        continue;

                if ((flags & MANAGER_IS_INHIBITED_CHECK_DELAY) != (i->mode == INHIBIT_DELAY))
                        continue;

                if ((flags & MANAGER_IS_INHIBITED_IGNORE_INACTIVE) &&
                    pidref_is_active_session(m, &i->pid) <= 0)
                        continue;

                if (i->mode == INHIBIT_BLOCK_WEAK &&
                    uid_is_valid(uid_to_ignore) &&
                    uid_to_ignore == i->uid)
                        continue;

                if (!inhibited || i->since.monotonic < ts.monotonic)
                        ts = i->since;

                inhibited = true;

                /* Stronger inhibitor wins */
                if (!offending || (i->mode < offending->mode))
                        offending = i;
        }

        if (since)
                *since = ts;

        if (ret_offending)
                *ret_offending = offending;

        return inhibited;
}

const char* inhibit_what_to_string(InhibitWhat w) {
        static thread_local char buffer[STRLEN(
            "shutdown:"
            "sleep:"
            "idle:"
            "handle-power-key:"
            "handle-suspend-key:"
            "handle-hibernate-key:"
            "handle-lid-switch:"
            "handle-reboot-key")+1];
        char *p;

        if (!inhibit_what_is_valid(w))
                return NULL;

        p = buffer;
        if (w & INHIBIT_SHUTDOWN)
                p = stpcpy(p, "shutdown:");
        if (w & INHIBIT_SLEEP)
                p = stpcpy(p, "sleep:");
        if (w & INHIBIT_IDLE)
                p = stpcpy(p, "idle:");
        if (w & INHIBIT_HANDLE_POWER_KEY)
                p = stpcpy(p, "handle-power-key:");
        if (w & INHIBIT_HANDLE_SUSPEND_KEY)
                p = stpcpy(p, "handle-suspend-key:");
        if (w & INHIBIT_HANDLE_HIBERNATE_KEY)
                p = stpcpy(p, "handle-hibernate-key:");
        if (w & INHIBIT_HANDLE_LID_SWITCH)
                p = stpcpy(p, "handle-lid-switch:");
        if (w & INHIBIT_HANDLE_REBOOT_KEY)
                p = stpcpy(p, "handle-reboot-key:");

        if (p > buffer)
                *(p-1) = 0;
        else
                *p = 0;

        return buffer;
}

int inhibit_what_from_string(const char *s) {
        InhibitWhat what = 0;

        for (const char *p = s;;) {
                _cleanup_free_ char *word = NULL;
                int r;

                /* A sanity check that our return values fit in an int */
                assert_cc((int) _INHIBIT_WHAT_MAX == _INHIBIT_WHAT_MAX);

                r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        return what;

                if (streq(word, "shutdown"))
                        what |= INHIBIT_SHUTDOWN;
                else if (streq(word, "sleep"))
                        what |= INHIBIT_SLEEP;
                else if (streq(word, "idle"))
                        what |= INHIBIT_IDLE;
                else if (streq(word, "handle-power-key"))
                        what |= INHIBIT_HANDLE_POWER_KEY;
                else if (streq(word, "handle-suspend-key"))
                        what |= INHIBIT_HANDLE_SUSPEND_KEY;
                else if (streq(word, "handle-hibernate-key"))
                        what |= INHIBIT_HANDLE_HIBERNATE_KEY;
                else if (streq(word, "handle-lid-switch"))
                        what |= INHIBIT_HANDLE_LID_SWITCH;
                else if (streq(word, "handle-reboot-key"))
                        what |= INHIBIT_HANDLE_REBOOT_KEY;
                else
                        return _INHIBIT_WHAT_INVALID;
        }
}

static const char* const inhibit_mode_table[_INHIBIT_MODE_MAX] = {
        [INHIBIT_BLOCK]      = "block",
        [INHIBIT_BLOCK_WEAK] = "block-weak",
        [INHIBIT_DELAY]      = "delay",
};

DEFINE_STRING_TABLE_LOOKUP(inhibit_mode, InhibitMode);
