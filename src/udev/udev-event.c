/* SPDX-License-Identifier: GPL-2.0+ */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "device-private.h"
#include "device-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "format-util.h"
#include "libudev-util.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "udev-builtin.h"
#include "udev-event.h"
#include "udev-node.h"
#include "udev-util.h"
#include "udev-watch.h"
#include "user-util.h"

typedef struct Spawn {
        sd_device *device;
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

UdevEvent *udev_event_new(sd_device *dev, usec_t exec_delay_usec, sd_netlink *rtnl) {
        UdevEvent *event;

        assert(dev);

        event = new(UdevEvent, 1);
        if (!event)
                return NULL;

        *event = (UdevEvent) {
                .dev = sd_device_ref(dev),
                .birth_usec = now(CLOCK_MONOTONIC),
                .exec_delay_usec = exec_delay_usec,
                .rtnl = sd_netlink_ref(rtnl),
                .uid = UID_INVALID,
                .gid = GID_INVALID,
                .mode = MODE_INVALID,
        };

        return event;
}

UdevEvent *udev_event_free(UdevEvent *event) {
        if (!event)
                return NULL;

        sd_device_unref(event->dev);
        sd_device_unref(event->dev_db_clone);
        sd_netlink_unref(event->rtnl);
        ordered_hashmap_free_free_key(event->run_list);
        ordered_hashmap_free_free_free(event->seclabel_list);
        free(event->program_result);
        free(event->name);

        return mfree(event);
}

typedef enum {
        FORMAT_SUBST_DEVNODE,
        FORMAT_SUBST_ATTR,
        FORMAT_SUBST_ENV,
        FORMAT_SUBST_KERNEL,
        FORMAT_SUBST_KERNEL_NUMBER,
        FORMAT_SUBST_DRIVER,
        FORMAT_SUBST_DEVPATH,
        FORMAT_SUBST_ID,
        FORMAT_SUBST_MAJOR,
        FORMAT_SUBST_MINOR,
        FORMAT_SUBST_RESULT,
        FORMAT_SUBST_PARENT,
        FORMAT_SUBST_NAME,
        FORMAT_SUBST_LINKS,
        FORMAT_SUBST_ROOT,
        FORMAT_SUBST_SYS,
        _FORMAT_SUBST_TYPE_MAX,
        _FORMAT_SUBST_TYPE_INVALID = -1
} FormatSubstitutionType;

struct subst_map_entry {
        const char *name;
        const char fmt;
        FormatSubstitutionType type;
};

static const struct subst_map_entry map[] = {
           { .name = "devnode",  .fmt = 'N', .type = FORMAT_SUBST_DEVNODE },
           { .name = "tempnode", .fmt = 'N', .type = FORMAT_SUBST_DEVNODE }, /* deprecated */
           { .name = "attr",     .fmt = 's', .type = FORMAT_SUBST_ATTR },
           { .name = "sysfs",    .fmt = 's', .type = FORMAT_SUBST_ATTR }, /* deprecated */
           { .name = "env",      .fmt = 'E', .type = FORMAT_SUBST_ENV },
           { .name = "kernel",   .fmt = 'k', .type = FORMAT_SUBST_KERNEL },
           { .name = "number",   .fmt = 'n', .type = FORMAT_SUBST_KERNEL_NUMBER },
           { .name = "driver",   .fmt = 'd', .type = FORMAT_SUBST_DRIVER },
           { .name = "devpath",  .fmt = 'p', .type = FORMAT_SUBST_DEVPATH },
           { .name = "id",       .fmt = 'b', .type = FORMAT_SUBST_ID },
           { .name = "major",    .fmt = 'M', .type = FORMAT_SUBST_MAJOR },
           { .name = "minor",    .fmt = 'm', .type = FORMAT_SUBST_MINOR },
           { .name = "result",   .fmt = 'c', .type = FORMAT_SUBST_RESULT },
           { .name = "parent",   .fmt = 'P', .type = FORMAT_SUBST_PARENT },
           { .name = "name",     .fmt = 'D', .type = FORMAT_SUBST_NAME },
           { .name = "links",    .fmt = 'L', .type = FORMAT_SUBST_LINKS },
           { .name = "root",     .fmt = 'r', .type = FORMAT_SUBST_ROOT },
           { .name = "sys",      .fmt = 'S', .type = FORMAT_SUBST_SYS },
};

static const char *format_type_to_string(FormatSubstitutionType t) {
        for (size_t i = 0; i < ELEMENTSOF(map); i++)
                if (map[i].type == t)
                        return map[i].name;
        return NULL;
}

static char format_type_to_char(FormatSubstitutionType t) {
        for (size_t i = 0; i < ELEMENTSOF(map); i++)
                if (map[i].type == t)
                        return map[i].fmt;
        return '\0';
}

static int get_subst_type(const char **str, bool strict, FormatSubstitutionType *ret_type, char ret_attr[static UTIL_PATH_SIZE]) {
        const char *p = *str, *q = NULL;
        size_t i;

        assert(str);
        assert(*str);
        assert(ret_type);
        assert(ret_attr);

        if (*p == '$') {
                p++;
                if (*p == '$') {
                        *str = p;
                        return 0;
                }
                for (i = 0; i < ELEMENTSOF(map); i++)
                        if ((q = startswith(p, map[i].name)))
                                break;
        } else if (*p == '%') {
                p++;
                if (*p == '%') {
                        *str = p;
                        return 0;
                }

                for (i = 0; i < ELEMENTSOF(map); i++)
                        if (*p == map[i].fmt) {
                                q = p + 1;
                                break;
                        }
        } else
                return 0;
        if (!q)
                /* When 'strict' flag is set, then '$' and '%' must be escaped. */
                return strict ? -EINVAL : 0;

        if (*q == '{') {
                const char *start, *end;
                size_t len;

                start = q + 1;
                end = strchr(start, '}');
                if (!end)
                        return -EINVAL;

                len = end - start;
                if (len == 0 || len >= UTIL_PATH_SIZE)
                        return -EINVAL;

                strnscpy(ret_attr, UTIL_PATH_SIZE, start, len);
                q = end + 1;
        } else
                *ret_attr = '\0';

        *str = q;
        *ret_type = map[i].type;
        return 1;
}

static int safe_atou_optional_plus(const char *s, unsigned *ret) {
        const char *p;
        int r;

        assert(s);
        assert(ret);

        /* Returns 1 if plus, 0 if no plus, negative on error */

        p = endswith(s, "+");
        if (p)
                s = strndupa(s, p - s);

        r = safe_atou(s, ret);
        if (r < 0)
                return r;

        return !!p;
}

static ssize_t udev_event_subst_format(
                UdevEvent *event,
                FormatSubstitutionType type,
                const char *attr,
                char *dest,
                size_t l) {
        sd_device *parent, *dev = event->dev;
        const char *val = NULL;
        char *s = dest;
        int r;

        switch (type) {
        case FORMAT_SUBST_DEVPATH:
                r = sd_device_get_devpath(dev, &val);
                if (r < 0)
                        return r;
                l = strpcpy(&s, l, val);
                break;
        case FORMAT_SUBST_KERNEL:
                r = sd_device_get_sysname(dev, &val);
                if (r < 0)
                        return r;
                l = strpcpy(&s, l, val);
                break;
        case FORMAT_SUBST_KERNEL_NUMBER:
                r = sd_device_get_sysnum(dev, &val);
                if (r == -ENOENT)
                        goto null_terminate;
                if (r < 0)
                        return r;
                l = strpcpy(&s, l, val);
                break;
        case FORMAT_SUBST_ID:
                if (!event->dev_parent)
                        goto null_terminate;
                r = sd_device_get_sysname(event->dev_parent, &val);
                if (r < 0)
                        return r;
                l = strpcpy(&s, l, val);
                break;
        case FORMAT_SUBST_DRIVER:
                if (!event->dev_parent)
                        goto null_terminate;
                r = sd_device_get_driver(event->dev_parent, &val);
                if (r == -ENOENT)
                        goto null_terminate;
                if (r < 0)
                        return r;
                l = strpcpy(&s, l, val);
                break;
        case FORMAT_SUBST_MAJOR:
        case FORMAT_SUBST_MINOR: {
                dev_t devnum;

                r = sd_device_get_devnum(dev, &devnum);
                if (r < 0 && r != -ENOENT)
                        return r;
                l = strpcpyf(&s, l, "%u", r < 0 ? 0 : type == FORMAT_SUBST_MAJOR ? major(devnum) : minor(devnum));
                break;
        }
        case FORMAT_SUBST_RESULT: {
                unsigned index = 0; /* 0 means whole string */
                bool has_plus;

                if (!event->program_result)
                        goto null_terminate;

                if (!isempty(attr)) {
                        r = safe_atou_optional_plus(attr, &index);
                        if (r < 0)
                                return r;

                        has_plus = r;
                }

                if (index == 0)
                        l = strpcpy(&s, l, event->program_result);
                else {
                        const char *start, *p;
                        unsigned i;

                        p = skip_leading_chars(event->program_result, NULL);

                        for (i = 1; i < index; i++) {
                                while (*p && !strchr(WHITESPACE, *p))
                                        p++;
                                p = skip_leading_chars(p, NULL);
                                if (*p == '\0')
                                        break;
                        }
                        if (i != index) {
                                log_device_debug(dev, "requested part of result string not found");
                                goto null_terminate;
                        }

                        start = p;
                        /* %c{2+} copies the whole string from the second part on */
                        if (has_plus)
                                l = strpcpy(&s, l, start);
                        else {
                                while (*p && !strchr(WHITESPACE, *p))
                                        p++;
                                l = strnpcpy(&s, l, start, p - start);
                        }
                }
                break;
        }
        case FORMAT_SUBST_ATTR: {
                char vbuf[UTIL_NAME_SIZE];
                int count;

                if (isempty(attr))
                        return -EINVAL;

                /* try to read the value specified by "[dmi/id]product_name" */
                if (util_resolve_subsys_kernel(attr, vbuf, sizeof(vbuf), true) == 0)
                        val = vbuf;

                /* try to read the attribute the device */
                if (!val)
                        (void) sd_device_get_sysattr_value(dev, attr, &val);

                /* try to read the attribute of the parent device, other matches have selected */
                if (!val && event->dev_parent && event->dev_parent != dev)
                        (void) sd_device_get_sysattr_value(event->dev_parent, attr, &val);

                if (!val)
                        goto null_terminate;

                /* strip trailing whitespace, and replace unwanted characters */
                if (val != vbuf)
                        strscpy(vbuf, sizeof(vbuf), val);
                delete_trailing_chars(vbuf, NULL);
                count = util_replace_chars(vbuf, UDEV_ALLOWED_CHARS_INPUT);
                if (count > 0)
                        log_device_debug(dev, "%i character(s) replaced", count);
                l = strpcpy(&s, l, vbuf);
                break;
        }
        case FORMAT_SUBST_PARENT:
                r = sd_device_get_parent(dev, &parent);
                if (r == -ENODEV)
                        goto null_terminate;
                if (r < 0)
                        return r;
                r = sd_device_get_devname(parent, &val);
                if (r == -ENOENT)
                        goto null_terminate;
                if (r < 0)
                        return r;
                l = strpcpy(&s, l, val + STRLEN("/dev/"));
                break;
        case FORMAT_SUBST_DEVNODE:
                r = sd_device_get_devname(dev, &val);
                if (r == -ENOENT)
                        goto null_terminate;
                if (r < 0)
                        return r;
                l = strpcpy(&s, l, val);
                break;
        case FORMAT_SUBST_NAME:
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
        case FORMAT_SUBST_LINKS:
                FOREACH_DEVICE_DEVLINK(dev, val)
                        if (s == dest)
                                l = strpcpy(&s, l, val + STRLEN("/dev/"));
                        else
                                l = strpcpyl(&s, l, " ", val + STRLEN("/dev/"), NULL);
                if (s == dest)
                        goto null_terminate;
                break;
        case FORMAT_SUBST_ROOT:
                l = strpcpy(&s, l, "/dev");
                break;
        case FORMAT_SUBST_SYS:
                l = strpcpy(&s, l, "/sys");
                break;
        case FORMAT_SUBST_ENV:
                if (isempty(attr))
                        return -EINVAL;
                r = sd_device_get_property_value(dev, attr, &val);
                if (r == -ENOENT)
                        goto null_terminate;
                if (r < 0)
                        return r;
                l = strpcpy(&s, l, val);
                break;
        default:
                assert_not_reached("Unknown format substitution type");
        }

        return s - dest;

null_terminate:
        *s = '\0';
        return 0;
}

ssize_t udev_event_apply_format(UdevEvent *event,
                                const char *src, char *dest, size_t size,
                                bool replace_whitespace) {
        const char *s = src;
        int r;

        assert(event);
        assert(event->dev);
        assert(src);
        assert(dest);
        assert(size > 0);

        while (*s) {
                FormatSubstitutionType type;
                char attr[UTIL_PATH_SIZE];
                ssize_t subst_len;

                r = get_subst_type(&s, false, &type, attr);
                if (r < 0)
                        return log_device_warning_errno(event->dev, r, "Invalid format string, ignoring: %s", src);
                if (r == 0) {
                        if (size < 2) /* need space for this char and the terminating NUL */
                                break;
                        *dest++ = *s++;
                        size--;
                        continue;
                }

                subst_len = udev_event_subst_format(event, type, attr, dest, size);
                if (subst_len < 0)
                        return log_device_warning_errno(event->dev, subst_len,
                                                        "Failed to substitute variable '$%s' or apply format '%%%c', ignoring: %m",
                                                        format_type_to_string(type), format_type_to_char(type));

                /* FORMAT_SUBST_RESULT handles spaces itself */
                if (replace_whitespace && type != FORMAT_SUBST_RESULT)
                        /* util_replace_whitespace can replace in-place,
                         * and does nothing if subst_len == 0 */
                        subst_len = util_replace_whitespace(dest, dest, subst_len);

                dest += subst_len;
                size -= subst_len;
        }

        assert(size >= 1);
        *dest = '\0';
        return size;
}

int udev_check_format(const char *value, size_t *offset, const char **hint) {
        FormatSubstitutionType type;
        const char *s = value;
        char attr[UTIL_PATH_SIZE];
        int r;

        while (*s) {
                r = get_subst_type(&s, true, &type, attr);
                if (r < 0) {
                        if (offset)
                                *offset = s - value;
                        if (hint)
                                *hint = "invalid substitution type";
                        return r;
                } else if (r == 0) {
                        s++;
                        continue;
                }

                if (IN_SET(type, FORMAT_SUBST_ATTR, FORMAT_SUBST_ENV) && isempty(attr)) {
                        if (offset)
                                *offset = s - value;
                        if (hint)
                                *hint = "attribute value missing";
                        return -EINVAL;
                }

                if (type == FORMAT_SUBST_RESULT && !isempty(attr)) {
                        unsigned i;

                        r = safe_atou_optional_plus(attr, &i);
                        if (r < 0) {
                                if (offset)
                                        *offset = s - value;
                                if (hint)
                                        *hint = "attribute value not a valid number";
                                return r;
                        }
                }
        }

        return 0;
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
                        log_device_error_errno(spawn->device, errno,
                                               "Failed to read stdout of '%s': %m", spawn->cmd);

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
                        log_device_debug(spawn->device, "'%s'(%s) '%s'", spawn->cmd,
                                         fd == spawn->fd_stdout ? "out" : "err", *q);
        }

        return 0;
}

static int on_spawn_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        Spawn *spawn = userdata;
        char timeout[FORMAT_TIMESPAN_MAX];

        assert(spawn);

        kill_and_sigcont(spawn->pid, SIGKILL);

        log_device_error(spawn->device, "Spawned process '%s' ["PID_FMT"] timed out after %s, killing",
                         spawn->cmd, spawn->pid,
                         format_timespan(timeout, sizeof(timeout), spawn->timeout_usec, USEC_PER_SEC));

        return 1;
}

static int on_spawn_timeout_warning(sd_event_source *s, uint64_t usec, void *userdata) {
        Spawn *spawn = userdata;
        char timeout[FORMAT_TIMESPAN_MAX];

        assert(spawn);

        log_device_warning(spawn->device, "Spawned process '%s' ["PID_FMT"] is taking longer than %s to complete",
                           spawn->cmd, spawn->pid,
                           format_timespan(timeout, sizeof(timeout), spawn->timeout_warn_usec, USEC_PER_SEC));

        return 1;
}

static int on_spawn_sigchld(sd_event_source *s, const siginfo_t *si, void *userdata) {
        Spawn *spawn = userdata;
        int ret = -EIO;

        assert(spawn);

        switch (si->si_code) {
        case CLD_EXITED:
                if (si->si_status == 0)
                        log_device_debug(spawn->device, "Process '%s' succeeded.", spawn->cmd);
                else
                        log_device_full(spawn->device, spawn->accept_failure ? LOG_DEBUG : LOG_WARNING, 0,
                                        "Process '%s' failed with exit code %i.", spawn->cmd, si->si_status);
                ret = si->si_status;
                break;
        case CLD_KILLED:
        case CLD_DUMPED:
                log_device_error(spawn->device, "Process '%s' terminated by signal %s.", spawn->cmd, signal_to_string(si->si_status));
                break;
        default:
                log_device_error(spawn->device, "Process '%s' failed due to unknown reason.", spawn->cmd);
        }

        sd_event_exit(sd_event_source_get_event(s), ret);
        return 1;
}

static int spawn_wait(Spawn *spawn) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        int r;

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

        if (spawn->fd_stdout >= 0) {
                r = sd_event_add_io(e, NULL, spawn->fd_stdout, EPOLLIN, on_spawn_io, spawn);
                if (r < 0)
                        return r;
        }

        if (spawn->fd_stderr >= 0) {
                r = sd_event_add_io(e, NULL, spawn->fd_stderr, EPOLLIN, on_spawn_io, spawn);
                if (r < 0)
                        return r;
        }

        r = sd_event_add_child(e, NULL, spawn->pid, WEXITED, on_spawn_sigchld, spawn);
        if (r < 0)
                return r;

        return sd_event_loop(e);
}

int udev_event_spawn(UdevEvent *event,
                     usec_t timeout_usec,
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
                        return log_device_error_errno(event->dev, errno,
                                                      "Failed to create pipe for command '%s': %m", cmd);

        if (log_get_max_level() >= LOG_INFO)
                if (pipe2(errpipe, O_NONBLOCK|O_CLOEXEC) != 0)
                        return log_device_error_errno(event->dev, errno,
                                                      "Failed to create pipe for command '%s': %m", cmd);

        argv = strv_split_full(cmd, NULL, SPLIT_QUOTES|SPLIT_RELAX);
        if (!argv)
                return log_oom();

        if (isempty(argv[0]))
                return log_device_error_errno(event->dev, SYNTHETIC_ERRNO(EINVAL),
                                              "Invalid command '%s'", cmd);

        /* allow programs in /usr/lib/udev/ to be called without the path */
        if (!path_is_absolute(argv[0])) {
                char *program;

                program = path_join(UDEVLIBEXECDIR, argv[0]);
                if (!program)
                        return log_oom();

                free_and_replace(argv[0], program);
        }

        r = device_get_properties_strv(event->dev, &envp);
        if (r < 0)
                return log_device_error_errno(event->dev, r, "Failed to get device properties");

        log_device_debug(event->dev, "Starting '%s'", cmd);

        r = safe_fork("(spawn)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG, &pid);
        if (r < 0)
                return log_device_error_errno(event->dev, r,
                                              "Failed to fork() to execute command '%s': %m", cmd);
        if (r == 0) {
                if (rearrange_stdio(-1, outpipe[WRITE_END], errpipe[WRITE_END]) < 0)
                        _exit(EXIT_FAILURE);

                (void) close_all_fds(NULL, 0);
                (void) rlimit_nofile_safe();

                execve(argv[0], argv, envp);
                _exit(EXIT_FAILURE);
        }

        /* parent closed child's ends of pipes */
        outpipe[WRITE_END] = safe_close(outpipe[WRITE_END]);
        errpipe[WRITE_END] = safe_close(errpipe[WRITE_END]);

        spawn = (Spawn) {
                .device = event->dev,
                .cmd = cmd,
                .pid = pid,
                .accept_failure = accept_failure,
                .timeout_warn_usec = udev_warn_timeout(timeout_usec),
                .timeout_usec = timeout_usec,
                .event_birth_usec = event->birth_usec,
                .fd_stdout = outpipe[READ_END],
                .fd_stderr = errpipe[READ_END],
                .result = result,
                .result_size = ressize,
        };
        r = spawn_wait(&spawn);
        if (r < 0)
                return log_device_error_errno(event->dev, r,
                                              "Failed to wait for spawned command '%s': %m", cmd);

        if (result)
                result[spawn.result_len] = '\0';

        return r; /* 0 for success, and positive if the program failed */
}

static int rename_netif(UdevEvent *event) {
        sd_device *dev = event->dev;
        const char *oldname;
        int ifindex, r;

        if (!event->name)
                return 0; /* No new name is requested. */

        r = sd_device_get_sysname(dev, &oldname);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get sysname: %m");

        if (streq(event->name, oldname))
                return 0; /* The interface name is already requested name. */

        if (!device_for_action(dev, DEVICE_ACTION_ADD))
                return 0; /* Rename the interface only when it is added. */

        r = sd_device_get_ifindex(dev, &ifindex);
        if (r == -ENOENT)
                return 0; /* Device is not a network interface. */
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get ifindex: %m");

        r = rtnl_set_link_name(&event->rtnl, ifindex, event->name);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to rename network interface %i from '%s' to '%s': %m",
                                              ifindex, oldname, event->name);

        /* Set ID_RENAMING boolean property here, and drop it in the corresponding move uevent later. */
        r = device_add_property(dev, "ID_RENAMING", "1");
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to add 'ID_RENAMING' property: %m");

        r = device_rename(dev, event->name);
        if (r < 0)
                return log_device_warning_errno(dev, r, "Failed to update properties with new name '%s': %m", event->name);

        log_device_debug(dev, "Network interface %i is renamed from '%s' to '%s'", ifindex, oldname, event->name);

        return 1;
}

static int update_devnode(UdevEvent *event) {
        sd_device *dev = event->dev;
        int r;

        r = sd_device_get_devnum(dev, NULL);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get devnum: %m");

        /* remove/update possible left-over symlinks from old database entry */
        if (event->dev_db_clone)
                (void) udev_node_update_old_links(dev, event->dev_db_clone);

        if (!uid_is_valid(event->uid)) {
                r = device_get_devnode_uid(dev, &event->uid);
                if (r < 0 && r != -ENOENT)
                        return log_device_error_errno(dev, r, "Failed to get devnode UID: %m");
        }

        if (!gid_is_valid(event->gid)) {
                r = device_get_devnode_gid(dev, &event->gid);
                if (r < 0 && r != -ENOENT)
                        return log_device_error_errno(dev, r, "Failed to get devnode GID: %m");
        }

        if (event->mode == MODE_INVALID) {
                r = device_get_devnode_mode(dev, &event->mode);
                if (r < 0 && r != -ENOENT)
                        return log_device_error_errno(dev, r, "Failed to get devnode mode: %m");
        }
        if (event->mode == MODE_INVALID && gid_is_valid(event->gid) && event->gid > 0)
                /* If group is set, but mode is not set, "upgrade" mode for the group. */
                event->mode = 0660;

        bool apply_mac = device_for_action(dev, DEVICE_ACTION_ADD);

        return udev_node_add(dev, apply_mac, event->mode, event->uid, event->gid, event->seclabel_list);
}

static void event_execute_rules_on_remove(
                UdevEvent *event,
                usec_t timeout_usec,
                Hashmap *properties_list,
                UdevRules *rules) {

        sd_device *dev = event->dev;
        int r;

        r = device_read_db_internal(dev, true);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to read database under /run/udev/data/: %m");

        r = device_tag_index(dev, NULL, false);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to remove corresponding tag files under /run/udev/tag/, ignoring: %m");

        r = device_delete_db(dev);
        if (r < 0)
                log_device_debug_errno(dev, r, "Failed to delete database under /run/udev/data/, ignoring: %m");

        if (sd_device_get_devnum(dev, NULL) >= 0)
                (void) udev_watch_end(dev);

        (void) udev_rules_apply_to_event(rules, event, timeout_usec, properties_list);

        if (sd_device_get_devnum(dev, NULL) >= 0)
                (void) udev_node_remove(dev);
}

static int udev_event_on_move(UdevEvent *event) {
        sd_device *dev = event->dev;
        int r;

        if (event->dev_db_clone &&
            sd_device_get_devnum(dev, NULL) < 0) {
                r = device_copy_properties(dev, event->dev_db_clone);
                if (r < 0)
                        log_device_debug_errno(dev, r, "Failed to copy properties from cloned sd_device object, ignoring: %m");
        }

        /* Drop previously added property */
        r = device_add_property(dev, "ID_RENAMING", NULL);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to remove 'ID_RENAMING' property: %m");

        return 0;
}

int udev_event_execute_rules(UdevEvent *event,
                             usec_t timeout_usec,
                             Hashmap *properties_list,
                             UdevRules *rules) {
        const char *subsystem;
        DeviceAction action;
        sd_device *dev;
        int r;

        assert(event);
        assert(rules);

        dev = event->dev;

        r = sd_device_get_subsystem(dev, &subsystem);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get subsystem: %m");

        r = device_get_action(dev, &action);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get ACTION: %m");

        if (action == DEVICE_ACTION_REMOVE) {
                event_execute_rules_on_remove(event, timeout_usec, properties_list, rules);
                return 0;
        }

        r = device_clone_with_db(dev, &event->dev_db_clone);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to clone sd_device object: %m");

        if (event->dev_db_clone && sd_device_get_devnum(dev, NULL) >= 0)
                /* Disable watch during event processing. */
                (void) udev_watch_end(event->dev_db_clone);

        if (action == DEVICE_ACTION_MOVE) {
                r = udev_event_on_move(event);
                if (r < 0)
                        return r;
        }

        r = udev_rules_apply_to_event(rules, event, timeout_usec, properties_list);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to apply udev rules: %m");

        r = rename_netif(event);
        if (r < 0)
                return r;

        r = update_devnode(event);
        if (r < 0)
                return r;

        /* preserve old, or get new initialization timestamp */
        r = device_ensure_usec_initialized(dev, event->dev_db_clone);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to set initialization timestamp: %m");

        /* (re)write database file */
        r = device_tag_index(dev, event->dev_db_clone, true);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to update tags under /run/udev/tag/: %m");

        r = device_update_db(dev);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to update database under /run/udev/data/: %m");

        device_set_is_initialized(dev);

        event->dev_db_clone = sd_device_unref(event->dev_db_clone);

        return 0;
}

void udev_event_execute_run(UdevEvent *event, usec_t timeout_usec) {
        const char *command;
        void *val;
        Iterator i;
        int r;

        ORDERED_HASHMAP_FOREACH_KEY(val, command, event->run_list, i) {
                UdevBuiltinCommand builtin_cmd = PTR_TO_UDEV_BUILTIN_CMD(val);

                if (builtin_cmd != _UDEV_BUILTIN_INVALID) {
                        log_device_debug(event->dev, "Running built-in command \"%s\"", command);
                        r = udev_builtin_run(event->dev, builtin_cmd, command, false);
                        if (r < 0)
                                log_device_debug_errno(event->dev, r, "Failed to run built-in command \"%s\", ignoring: %m", command);
                } else {
                        if (event->exec_delay_usec > 0) {
                                char buf[FORMAT_TIMESPAN_MAX];

                                log_device_debug(event->dev, "Delaying execution of \"%s\" for %s.",
                                                 command, format_timespan(buf, sizeof(buf), event->exec_delay_usec, USEC_PER_SEC));
                                (void) usleep(event->exec_delay_usec);
                        }

                        log_device_debug(event->dev, "Running command \"%s\"", command);
                        r = udev_event_spawn(event, timeout_usec, false, command, NULL, 0);
                        if (r > 0) /* returned value is positive when program fails */
                                log_device_debug(event->dev, "Command \"%s\" returned %d (error), ignoring.", command, r);
                }
        }
}
