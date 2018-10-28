/* SPDX-License-Identifier: GPL-2.0+ */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "device-private.h"
#include "device-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "libudev-device-internal.h"
#include "netlink-util.h"
#include "path-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "udev-builtin.h"
#include "udev-node.h"
#include "udev-watch.h"
#include "udev.h"

typedef struct Spawn {
        const char *cmd;
        pid_t pid;
        usec_t timeout_warn_usec;
        usec_t timeout_usec;
        usec_t event_birth_usec;
        bool accept_failure;
        int fd_stdout;
        int fd_stderr;
        char *result;
        size_t result_size;
        size_t result_len;
} Spawn;

struct udev_event *udev_event_new(struct udev_device *dev) {
        struct udev_event *event;

        assert(dev);

        event = new(struct udev_event, 1);
        if (!event)
                return NULL;

        *event = (struct udev_event) {
                .dev = dev,
                .birth_usec = now(CLOCK_MONOTONIC),
        };

        return event;
}

struct udev_event *udev_event_free(struct udev_event *event) {
        void *p;

        if (!event)
                return NULL;

        sd_netlink_unref(event->rtnl);
        while ((p = hashmap_steal_first_key(event->run_list)))
                free(p);
        hashmap_free(event->run_list);
        hashmap_free_free_free(event->seclabel_list);
        free(event->program_result);
        free(event->name);

        return mfree(event);
}

enum subst_type {
        SUBST_DEVNODE,
        SUBST_ATTR,
        SUBST_ENV,
        SUBST_KERNEL,
        SUBST_KERNEL_NUMBER,
        SUBST_DRIVER,
        SUBST_DEVPATH,
        SUBST_ID,
        SUBST_MAJOR,
        SUBST_MINOR,
        SUBST_RESULT,
        SUBST_PARENT,
        SUBST_NAME,
        SUBST_LINKS,
        SUBST_ROOT,
        SUBST_SYS,
};

struct subst_map_entry {
        const char *name;
        const char fmt;
        enum subst_type type;
};

static const struct subst_map_entry map[] = {
           { .name = "devnode",  .fmt = 'N', .type = SUBST_DEVNODE },
           { .name = "tempnode", .fmt = 'N', .type = SUBST_DEVNODE },
           { .name = "attr",     .fmt = 's', .type = SUBST_ATTR },
           { .name = "sysfs",    .fmt = 's', .type = SUBST_ATTR },
           { .name = "env",      .fmt = 'E', .type = SUBST_ENV },
           { .name = "kernel",   .fmt = 'k', .type = SUBST_KERNEL },
           { .name = "number",   .fmt = 'n', .type = SUBST_KERNEL_NUMBER },
           { .name = "driver",   .fmt = 'd', .type = SUBST_DRIVER },
           { .name = "devpath",  .fmt = 'p', .type = SUBST_DEVPATH },
           { .name = "id",       .fmt = 'b', .type = SUBST_ID },
           { .name = "major",    .fmt = 'M', .type = SUBST_MAJOR },
           { .name = "minor",    .fmt = 'm', .type = SUBST_MINOR },
           { .name = "result",   .fmt = 'c', .type = SUBST_RESULT },
           { .name = "parent",   .fmt = 'P', .type = SUBST_PARENT },
           { .name = "name",     .fmt = 'D', .type = SUBST_NAME },
           { .name = "links",    .fmt = 'L', .type = SUBST_LINKS },
           { .name = "root",     .fmt = 'r', .type = SUBST_ROOT },
           { .name = "sys",      .fmt = 'S', .type = SUBST_SYS },
};

static ssize_t subst_format_var(struct udev_event *event,
                                const struct subst_map_entry *entry, char *attr,
                                char *dest, size_t l) {
        sd_device *parent, *dev = event->dev->device;
        const char *val = NULL;
        char *s = dest;
        dev_t devnum;
        int r;

        assert(entry);

        switch (entry->type) {
        case SUBST_DEVPATH:
                r = sd_device_get_devpath(dev, &val);
                if (r < 0)
                        return r;
                l = strpcpy(&s, l, val);
                break;
        case SUBST_KERNEL:
                r = sd_device_get_sysname(dev, &val);
                if (r < 0)
                        return r;
                l = strpcpy(&s, l, val);
                break;
        case SUBST_KERNEL_NUMBER:
                r = sd_device_get_sysnum(dev, &val);
                if (r < 0)
                        return r == -ENOENT ? 0 : r;
                l = strpcpy(&s, l, val);
                break;
        case SUBST_ID:
                if (!event->dev_parent)
                        return 0;
                r = sd_device_get_sysname(event->dev_parent->device, &val);
                if (r < 0)
                        return r;
                l = strpcpy(&s, l, val);
                break;
        case SUBST_DRIVER:
                if (!event->dev_parent)
                        return 0;
                r = sd_device_get_driver(event->dev_parent->device, &val);
                if (r < 0)
                        return r == -ENOENT ? 0 : r;
                l = strpcpy(&s, l, val);
                break;
        case SUBST_MAJOR:
        case SUBST_MINOR: {
                char buf[DECIMAL_STR_MAX(unsigned)];

                r = sd_device_get_devnum(dev, &devnum);
                if (r < 0 && r != -ENOENT)
                        return r;
                xsprintf(buf, "%u", r < 0 ? 0 : entry->type == SUBST_MAJOR ? major(devnum) : minor(devnum));
                l = strpcpy(&s, l, buf);
                break;
        }
        case SUBST_RESULT: {
                char *rest;
                int i;

                if (!event->program_result)
                        return 0;

                /* get part of the result string */
                i = 0;
                if (attr)
                        i = strtoul(attr, &rest, 10);
                if (i > 0) {
                        char result[UTIL_PATH_SIZE], tmp[UTIL_PATH_SIZE], *cpos;

                        strscpy(result, sizeof(result), event->program_result);
                        cpos = result;
                        while (--i) {
                                while (cpos[0] != '\0' && !isspace(cpos[0]))
                                        cpos++;
                                while (isspace(cpos[0]))
                                        cpos++;
                                if (cpos[0] == '\0')
                                        break;
                        }
                        if (i > 0) {
                                log_error("requested part of result string not found");
                                break;
                        }
                        strscpy(tmp, sizeof(tmp), cpos);
                        /* %{2+}c copies the whole string from the second part on */
                        if (rest[0] != '+') {
                                cpos = strchr(tmp, ' ');
                                if (cpos)
                                        cpos[0] = '\0';
                        }
                        l = strpcpy(&s, l, tmp);
                } else
                        l = strpcpy(&s, l, event->program_result);
                break;
        }
        case SUBST_ATTR: {
                char vbuf[UTIL_NAME_SIZE];
                size_t len;
                int count;

                if (!attr)
                        return -EINVAL;

                /* try to read the value specified by "[dmi/id]product_name" */
                if (util_resolve_subsys_kernel(attr, vbuf, sizeof(vbuf), 1) == 0)
                        val = vbuf;

                /* try to read the attribute the device */
                if (!val)
                        (void) sd_device_get_sysattr_value(dev, attr, &val);

                /* try to read the attribute of the parent device, other matches have selected */
                if (!val && event->dev_parent && event->dev_parent->device != dev)
                        (void) sd_device_get_sysattr_value(event->dev_parent->device, attr, &val);

                if (!val)
                        return 0;

                /* strip trailing whitespace, and replace unwanted characters */
                if (val != vbuf)
                        strscpy(vbuf, sizeof(vbuf), val);
                len = strlen(vbuf);
                while (len > 0 && isspace(vbuf[--len]))
                        vbuf[len] = '\0';
                count = util_replace_chars(vbuf, UDEV_ALLOWED_CHARS_INPUT);
                if (count > 0)
                        log_device_debug(dev, "%i character(s) replaced", count);
                l = strpcpy(&s, l, vbuf);
                break;
        }
        case SUBST_PARENT:
                r = sd_device_get_parent(dev, &parent);
                if (r < 0)
                        return r == -ENODEV ? 0 : r;
                r = sd_device_get_devname(parent, &val);
                if (r < 0)
                        return r == -ENOENT ? 0 : r;
                l = strpcpy(&s, l, val + STRLEN("/dev/"));
                break;
        case SUBST_DEVNODE:
                r = sd_device_get_devname(dev, &val);
                if (r < 0)
                        return r == -ENOENT ? 0 : r;
                l = strpcpy(&s, l, val);
                break;
        case SUBST_NAME:
                if (event->name)
                        l = strpcpy(&s, l, event->name);
                else if (sd_device_get_devname(dev, &val) >= 0)
                        l = strpcpy(&s, l, val + STRLEN("/dev/"));
                else {
                        r = sd_device_get_sysname(dev, &val);
                        if (r < 0)
                                return r;
                        l = strpcpy(&s, l, val);
                }
                break;
        case SUBST_LINKS:
                FOREACH_DEVICE_DEVLINK(dev, val)
                        if (s == dest)
                                l = strpcpy(&s, l, val + STRLEN("/dev/"));
                        else
                                l = strpcpyl(&s, l, " ", val + STRLEN("/dev/"), NULL);
                break;
        case SUBST_ROOT:
                l = strpcpy(&s, l, "/dev");
                break;
        case SUBST_SYS:
                l = strpcpy(&s, l, "/sys");
                break;
        case SUBST_ENV:
                if (!attr)
                        return 0;
                r = sd_device_get_property_value(dev, attr, &val);
                if (r < 0)
                        return r == -ENOENT ? 0 : r;
                l = strpcpy(&s, l, val);
                break;
        default:
                assert_not_reached("Unknown format substitution type");
        }

        return s - dest;
}

ssize_t udev_event_apply_format(struct udev_event *event,
                                const char *src, char *dest, size_t size,
                                bool replace_whitespace) {
        const char *from;
        char *s;
        size_t l;

        assert(event);
        assert(event->dev);
        assert(src);
        assert(dest);
        assert(size > 0);

        from = src;
        s = dest;
        l = size;

        for (;;) {
                const struct subst_map_entry *entry = NULL;
                char attrbuf[UTIL_PATH_SIZE], *attr;
                bool format_dollar = false;
                ssize_t subst_len;

                while (from[0] != '\0') {
                        if (from[0] == '$') {
                                /* substitute named variable */
                                unsigned i;

                                if (from[1] == '$') {
                                        from++;
                                        goto copy;
                                }

                                for (i = 0; i < ELEMENTSOF(map); i++) {
                                        if (startswith(&from[1], map[i].name)) {
                                                entry = &map[i];
                                                from += strlen(map[i].name)+1;
                                                format_dollar = true;
                                                goto subst;
                                        }
                                }
                        } else if (from[0] == '%') {
                                /* substitute format char */
                                unsigned i;

                                if (from[1] == '%') {
                                        from++;
                                        goto copy;
                                }

                                for (i = 0; i < ELEMENTSOF(map); i++) {
                                        if (from[1] == map[i].fmt) {
                                                entry = &map[i];
                                                from += 2;
                                                goto subst;
                                        }
                                }
                        }
copy:
                        /* copy char */
                        if (l < 2) /* need space for this char and the terminating NUL */
                                goto out;
                        s[0] = from[0];
                        from++;
                        s++;
                        l--;
                }

                goto out;
subst:
                /* extract possible $format{attr} */
                if (from[0] == '{') {
                        unsigned i;

                        from++;
                        for (i = 0; from[i] != '}'; i++)
                                if (from[i] == '\0') {
                                        log_error("missing closing brace for format '%s'", src);
                                        goto out;
                                }

                        if (i >= sizeof(attrbuf))
                                goto out;
                        memcpy(attrbuf, from, i);
                        attrbuf[i] = '\0';
                        from += i+1;
                        attr = attrbuf;
                } else
                        attr = NULL;

                subst_len = subst_format_var(event, entry, attr, s, l);
                if (subst_len < 0) {
                        if (format_dollar)
                                log_device_warning_errno(event->dev->device, subst_len, "Failed to substitute variable '$%s', ignoring: %m", entry->name);
                        else
                                log_device_warning_errno(event->dev->device, subst_len, "Failed to apply format '%%%c', ignoring: %m", entry->fmt);

                        continue;
                }

                /* SUBST_RESULT handles spaces itself */
                if (replace_whitespace && entry->type != SUBST_RESULT)
                        /* util_replace_whitespace can replace in-place,
                         * and does nothing if subst_len == 0
                         */
                        subst_len = util_replace_whitespace(s, s, subst_len);

                s += subst_len;
                l -= subst_len;
        }

out:
        assert(l >= 1);
        s[0] = '\0';
        return l;
}

static int on_spawn_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Spawn *spawn = userdata;
        char buf[4096], *p;
        size_t size;
        ssize_t l;

        assert(spawn);
        assert(fd == spawn->fd_stdout || fd == spawn->fd_stderr);
        assert(!spawn->result || spawn->result_len < spawn->result_size);

        if (fd == spawn->fd_stdout && spawn->result) {
                p = spawn->result + spawn->result_len;
                size = spawn->result_size - spawn->result_len;
        } else {
                p = buf;
                size = sizeof(buf);
        }

        l = read(fd, p, size - 1);
        if (l < 0) {
                if (errno != EAGAIN)
                        log_error_errno(errno, "Failed to read stdout of '%s': %m", spawn->cmd);

                return 0;
        }

        p[l] = '\0';
        if (fd == spawn->fd_stdout && spawn->result)
                spawn->result_len += l;

        /* Log output only if we watch stderr. */
        if (l > 0 && spawn->fd_stderr >= 0) {
                _cleanup_strv_free_ char **v = NULL;
                char **q;

                v = strv_split_newlines(p);
                if (!v)
                        return 0;

                STRV_FOREACH(q, v)
                        log_debug("'%s'(%s) '%s'", spawn->cmd,
                                  fd == spawn->fd_stdout ? "out" : "err", *q);
        }

        return 0;
}

static int on_spawn_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        Spawn *spawn = userdata;
        char timeout[FORMAT_TIMESTAMP_RELATIVE_MAX];

        assert(spawn);

        kill_and_sigcont(spawn->pid, SIGKILL);

        log_error("Spawned process '%s' ["PID_FMT"] timed out after %s, killing", spawn->cmd, spawn->pid,
                  format_timestamp_relative(timeout, sizeof(timeout), spawn->timeout_usec));

        return 1;
}

static int on_spawn_timeout_warning(sd_event_source *s, uint64_t usec, void *userdata) {
        Spawn *spawn = userdata;
        char timeout[FORMAT_TIMESTAMP_RELATIVE_MAX];

        assert(spawn);

        log_warning("Spawned process '%s' ["PID_FMT"] is taking longer than %s to complete", spawn->cmd, spawn->pid,
                    format_timestamp_relative(timeout, sizeof(timeout), spawn->timeout_warn_usec));

        return 1;
}

static int on_spawn_sigchld(sd_event_source *s, const siginfo_t *si, void *userdata) {
        Spawn *spawn = userdata;

        assert(spawn);

        switch (si->si_code) {
        case CLD_EXITED:
                if (si->si_status == 0) {
                        log_debug("Process '%s' succeeded.", spawn->cmd);
                        sd_event_exit(sd_event_source_get_event(s), 0);

                        return 1;
                }

                log_full(spawn->accept_failure ? LOG_DEBUG : LOG_WARNING,
                         "Process '%s' failed with exit code %i.", spawn->cmd, si->si_status);
                break;
        case CLD_KILLED:
        case CLD_DUMPED:
                log_warning("Process '%s' terminated by signal %s.", spawn->cmd, signal_to_string(si->si_status));

                break;
        default:
                log_error("Process '%s' failed due to unknown reason.", spawn->cmd);
        }

        sd_event_exit(sd_event_source_get_event(s), -EIO);

        return 1;
}

static int spawn_wait(Spawn *spawn) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        int r, ret;

        assert(spawn);

        r = sd_event_new(&e);
        if (r < 0)
                return r;

        if (spawn->timeout_usec > 0) {
                usec_t usec, age_usec;

                usec = now(CLOCK_MONOTONIC);
                age_usec = usec - spawn->event_birth_usec;
                if (age_usec < spawn->timeout_usec) {
                        if (spawn->timeout_warn_usec > 0 &&
                            spawn->timeout_warn_usec < spawn->timeout_usec &&
                            spawn->timeout_warn_usec > age_usec) {
                                spawn->timeout_warn_usec -= age_usec;

                                r = sd_event_add_time(e, NULL, CLOCK_MONOTONIC,
                                                      usec + spawn->timeout_warn_usec, USEC_PER_SEC,
                                                      on_spawn_timeout_warning, spawn);
                                if (r < 0)
                                        return r;
                        }

                        spawn->timeout_usec -= age_usec;

                        r = sd_event_add_time(e, NULL, CLOCK_MONOTONIC,
                                              usec + spawn->timeout_usec, USEC_PER_SEC, on_spawn_timeout, spawn);
                        if (r < 0)
                                return r;
                }
        }

        r = sd_event_add_io(e, NULL, spawn->fd_stdout, EPOLLIN, on_spawn_io, spawn);
        if (r < 0)
                return r;

        r = sd_event_add_io(e, NULL, spawn->fd_stderr, EPOLLIN, on_spawn_io, spawn);
        if (r < 0)
                return r;

        r = sd_event_add_child(e, NULL, spawn->pid, WEXITED, on_spawn_sigchld, spawn);
        if (r < 0)
                return r;

        r = sd_event_loop(e);
        if (r < 0)
                return r;

        r = sd_event_get_exit_code(e, &ret);
        if (r < 0)
                return r;

        return ret;
}

int udev_event_spawn(struct udev_event *event,
                     usec_t timeout_usec,
                     usec_t timeout_warn_usec,
                     bool accept_failure,
                     const char *cmd,
                     char *result, size_t ressize) {
        _cleanup_close_pair_ int outpipe[2] = {-1, -1}, errpipe[2] = {-1, -1};
        _cleanup_strv_free_ char **argv = NULL;
        char **envp = NULL;
        Spawn spawn;
        pid_t pid;
        int r;

        assert(event);
        assert(event->dev);
        assert(result || ressize == 0);

        /* pipes from child to parent */
        if (result || log_get_max_level() >= LOG_INFO)
                if (pipe2(outpipe, O_NONBLOCK|O_CLOEXEC) != 0)
                        return log_error_errno(errno, "Failed to create pipe for command '%s': %m", cmd);

        if (log_get_max_level() >= LOG_INFO)
                if (pipe2(errpipe, O_NONBLOCK|O_CLOEXEC) != 0)
                        return log_error_errno(errno, "Failed to create pipe for command '%s': %m", cmd);

        argv = strv_split_full(cmd, NULL, SPLIT_QUOTES|SPLIT_RELAX);
        if (!argv)
                return log_oom();

        if (isempty(argv[0])) {
                log_error("Invalid command '%s'", cmd);
                return -EINVAL;
        }

        /* allow programs in /usr/lib/udev/ to be called without the path */
        if (!path_is_absolute(argv[0])) {
                char *program;

                program = path_join(NULL, UDEVLIBEXECDIR, argv[0]);
                if (!program)
                        return log_oom();

                free_and_replace(argv[0], program);
        }

        r = device_get_properties_strv(event->dev->device, &envp);
        if (r < 0)
                return log_device_error_errno(event->dev->device, r, "Failed to get device properties");

        log_debug("Starting '%s'", cmd);

        r = safe_fork("(spawn)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG, &pid);
        if (r < 0)
                return log_error_errno(r, "Failed to fork() to execute command '%s': %m", cmd);
        if (r == 0) {
                if (rearrange_stdio(-1, outpipe[WRITE_END], errpipe[WRITE_END]) < 0)
                        _exit(EXIT_FAILURE);

                (void) close_all_fds(NULL, 0);

                execve(argv[0], argv, envp);
                _exit(EXIT_FAILURE);
        }

        /* parent closed child's ends of pipes */
        outpipe[WRITE_END] = safe_close(outpipe[WRITE_END]);
        errpipe[WRITE_END] = safe_close(errpipe[WRITE_END]);

        spawn = (Spawn) {
                .cmd = cmd,
                .pid = pid,
                .accept_failure = accept_failure,
                .timeout_warn_usec = timeout_warn_usec,
                .timeout_usec = timeout_usec,
                .event_birth_usec = event->birth_usec,
                .fd_stdout = outpipe[READ_END],
                .fd_stderr = errpipe[READ_END],
                .result = result,
                .result_size = ressize,
        };
        r = spawn_wait(&spawn);
        if (r < 0)
                return log_error_errno(r, "Failed to wait spawned command '%s': %m", cmd);

        if (result)
                result[spawn.result_len] = '\0';

        return r;
}

static int rename_netif(struct udev_event *event) {
        sd_device *dev = event->dev->device;
        const char *action, *oldname;
        char name[IFNAMSIZ];
        int ifindex, r;

        if (!event->name)
                return 0; /* No new name is requested. */

        r = sd_device_get_sysname(dev, &oldname);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get sysname: %m");

        if (streq(event->name, oldname))
                return 0; /* The interface name is already requested name. */

        r = sd_device_get_property_value(dev, "ACTION", &action);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get property 'ACTION': %m");

        if (!streq(action, "add"))
                return 0; /* Rename the interface only when it is added. */

        r = sd_device_get_ifindex(dev, &ifindex);
        if (r == -ENOENT)
                return 0; /* Device is not a network interface. */
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get ifindex: %m");

        strscpy(name, IFNAMSIZ, event->name);
        r = rtnl_set_link_name(&event->rtnl, ifindex, name);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to rename network interface %i from '%s' to '%s': %m", ifindex, oldname, name);

        r = device_rename(dev, event->name);
        if (r < 0)
                return log_warning_errno(r, "Network interface %i is renamed from '%s' to '%s', but could not update sd_device object: %m", ifindex, oldname, name);

        log_device_debug(dev, "Network interface %i is renamed from '%s' to '%s'", ifindex, oldname, name);

        return 1;
}

static int update_devnode(struct udev_event *event) {
        sd_device *dev = event->dev->device;
        const char *action;
        dev_t devnum;
        bool apply;
        int r;

        r = sd_device_get_devnum(dev, &devnum);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get devnum: %m");

        /* remove/update possible left-over symlinks from old database entry */
        if (event->dev_db)
                (void) udev_node_update_old_links(dev, event->dev_db->device);

        if (!event->owner_set) {
                r = device_get_devnode_uid(dev, &event->uid);
                if (r < 0 && r != -ENOENT)
                        return log_device_error_errno(dev, r, "Failed to get devnode UID: %m");
        }

        if (!event->group_set) {
                r = device_get_devnode_gid(dev, &event->gid);
                if (r < 0 && r != -ENOENT)
                        return log_device_error_errno(dev, r, "Failed to get devnode GID: %m");
        }

        if (!event->mode_set) {
                r = device_get_devnode_mode(dev, &event->mode);
                if (r < 0 && r != -ENOENT)
                        return log_device_error_errno(dev, r, "Failed to get devnode mode: %m");
                if (r == -ENOENT) {
                        if (event->gid > 0)
                                /* default 0660 if a group is assigned */
                                event->mode = 0660;
                        else
                                /* default 0600 */
                                event->mode = 0600;
                }
        }

        r = sd_device_get_property_value(dev, "ACTION", &action);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get property 'ACTION': %m");

        apply = streq(action, "add") || event->owner_set || event->group_set || event->mode_set;
        return udev_node_add(dev, apply, event->mode, event->uid, event->gid, event->seclabel_list);
}

static void event_execute_rules_on_remove(
                struct udev_event *event,
                usec_t timeout_usec, usec_t timeout_warn_usec,
                Hashmap *properties_list,
                struct udev_rules *rules) {

        sd_device *dev = event->dev->device;
        dev_t devnum;
        int r;

        r = device_read_db_force(dev);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to read database under /run/udev/data/: %m");

        r = device_tag_index(dev, NULL, false);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to remove corresponding tag files under /run/udev/tag/, ignoring: %m");

        r = device_delete_db(dev);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to delete database under /run/udev/data/, ignoring: %m");

        r = sd_device_get_devnum(dev, &devnum);
        if (r < 0) {
                if (r != -ENOENT)
                        log_device_debug_errno(dev, r, "Failed to get devnum, ignoring: %m");
        } else
                (void) udev_watch_end(dev);

        (void) udev_rules_apply_to_event(rules, event,
                                         timeout_usec, timeout_warn_usec,
                                         properties_list);

        if (major(devnum) > 0)
                (void) udev_node_remove(dev);
}

int udev_event_execute_rules(struct udev_event *event,
                             usec_t timeout_usec, usec_t timeout_warn_usec,
                             Hashmap *properties_list,
                             struct udev_rules *rules) {
        _cleanup_(sd_device_unrefp) sd_device *clone = NULL;
        sd_device *dev = event->dev->device;
        const char *subsystem, *action;
        dev_t devnum;
        int r;

        assert(event);
        assert(rules);

        r = sd_device_get_subsystem(dev, &subsystem);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get subsystem: %m");

        r = sd_device_get_property_value(dev, "ACTION", &action);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get property 'ACTION': %m");

        if (streq(action, "remove")) {
                event_execute_rules_on_remove(event, timeout_usec, timeout_warn_usec, properties_list, rules);
                return 0;
        }

        r = device_clone_with_db(dev, &clone);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to clone sd_device object, ignoring: %m");

        if (clone) {
                event->dev_db = udev_device_new(NULL, clone);
                if (!event->dev_db)
                        return -ENOMEM;

                r = sd_device_get_devnum(dev, &devnum);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_device_debug_errno(dev, r, "Failed to get devnum, ignoring: %m");

                        if (streq(action, "move")) {
                                r = device_copy_properties(dev, clone);
                                if (r < 0)
                                        log_device_debug_errno(dev, r, "Failed to copy properties from cloned device, ignoring: %m");
                        }
                } else
                        /* Disable watch during event processing. */
                        (void) udev_watch_end(clone);
        }

        (void) udev_rules_apply_to_event(rules, event,
                                         timeout_usec, timeout_warn_usec,
                                         properties_list);

        (void) rename_netif(event);
        (void) update_devnode(event);

        /* preserve old, or get new initialization timestamp */
        r = device_ensure_usec_initialized(dev, clone);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to set initialization timestamp, ignoring: %m");

        /* (re)write database file */
        r = device_tag_index(dev, clone, true);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to update tags under /run/udev/tag/, ignoring: %m");

        r = device_update_db(dev);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to update database under /run/udev/data/, ignoring: %m");

        device_set_is_initialized(dev);

        event->dev_db = udev_device_unref(event->dev_db);

        return 0;
}

void udev_event_execute_run(struct udev_event *event, usec_t timeout_usec, usec_t timeout_warn_usec) {
        const char *cmd;
        void *val;
        Iterator i;

        HASHMAP_FOREACH_KEY(val, cmd, event->run_list, i) {
                enum udev_builtin_cmd builtin_cmd = PTR_TO_INT(val);
                char command[UTIL_PATH_SIZE];

                udev_event_apply_format(event, cmd, command, sizeof(command), false);

                if (builtin_cmd >= 0 && builtin_cmd < _UDEV_BUILTIN_MAX)
                        udev_builtin_run(event->dev->device, builtin_cmd, command, false);
                else {
                        if (event->exec_delay > 0) {
                                log_debug("delay execution of '%s'", command);
                                sleep(event->exec_delay);
                        }

                        udev_event_spawn(event, timeout_usec, timeout_warn_usec, false, command, NULL, 0);
                }
        }
}
