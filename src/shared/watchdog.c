/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <linux/watchdog.h>

#include "fd-util.h"
#include "log.h"
#include "string-util.h"
#include "time-util.h"
#include "sd-id128.h"
#include "watchdog.h"

#define WATCHDOG_MSG_BUF_MAX 128

enum wd_type {
        WATCHDOG_TYPE_NULL,
        WATCHDOG_TYPE_DEVICE,
        WATCHDOG_TYPE_FIFO
};

static int update_timeout_device(void);
static int update_timeout_fifo(void);
static int update_timeout(void);
static int open_watchdog_device(void);
static int open_watchdog_fifo(void);
static int open_watchdog(void);
static int watchdog_ping_device(void);
static int watchdog_ping_fifo(void);
static void watchdog_close_device(bool disarm);
static void watchdog_close_fifo(bool disarm);
static int watchdog_set_message(char *buf, size_t bsz, const char *cmd, int val);

static int watchdog_fd = -1;
static char *watchdog_device = NULL;
static enum wd_type watchdog_type = WATCHDOG_TYPE_NULL;
static usec_t watchdog_timeout = USEC_INFINITY;

static enum wd_type get_watchdog_type(void) {
        if (watchdog_type != WATCHDOG_TYPE_NULL) {
                return watchdog_type;
        } else {
                struct stat wdf;

                if (lstat(watchdog_device ? watchdog_device: "/dev/watchdog", &wdf) == -1) {
                        log_warning_errno(errno, "Failed to stat watchdog file: %m");
                } else {
                        switch (wdf.st_mode & S_IFMT) {
                        case S_IFCHR:  return WATCHDOG_TYPE_DEVICE;
                        case S_IFIFO:  return WATCHDOG_TYPE_FIFO;
                        default:       return WATCHDOG_TYPE_NULL;
                        }
                }
        }

        return WATCHDOG_TYPE_NULL;
}

static int watchdog_set_message(char *buf, size_t bsz, const char *cmd, int val) {
        char mid[SD_ID128_STRING_MAX];
        char hnm[HOST_NAME_MAX];
        sd_id128_t sid;
        int r;

        assert(buf);
        assert(cmd);

        r = gethostname(hnm, sizeof(hnm));
        if (r < 0)
                return log_error_errno(r, "Failed to get host name: %m");

        r = sd_id128_get_machine(&sid);
        if (r < 0)
                return log_error_errno(r, "Failed to get machine id: %m");

        sd_id128_to_string(sid, mid);

        r = snprintf(buf, bsz, "MACHINE=%s,HOSTNAME=%s,%s=%d;", mid, hnm, cmd, val);
        if (r < 0 || r > (int)bsz) {
                log_full(LOG_ERR, "Watchdog message buffer too small");
                r = -1;
        }

        return (r >= 0) ? (0) : (-1);
}

static int update_timeout_device(void) {
        int r;

        if (watchdog_fd < 0)
                return 0;

        if (watchdog_timeout == USEC_INFINITY)
                return 0;
        else if (watchdog_timeout == 0) {
                int flags;

                flags = WDIOS_DISABLECARD;
                r = ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags);
                if (r < 0)
                        return log_warning_errno(errno, "Failed to disable hardware watchdog: %m");
        } else {
                int sec, flags;
                char buf[FORMAT_TIMESPAN_MAX];

                sec = (int) DIV_ROUND_UP(watchdog_timeout, USEC_PER_SEC);
                r = ioctl(watchdog_fd, WDIOC_SETTIMEOUT, &sec);
                if (r < 0)
                        return log_warning_errno(errno, "Failed to set timeout to %is: %m", sec);

                watchdog_timeout = (usec_t) sec * USEC_PER_SEC;
                log_info("Set hardware watchdog to %s.", format_timespan(buf, sizeof(buf), watchdog_timeout, 0));

                flags = WDIOS_ENABLECARD;
                r = ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags);
                if (r < 0) {
                        /* ENOTTY means the watchdog is always enabled so we're fine */
                        log_full(errno == ENOTTY ? LOG_DEBUG : LOG_WARNING,
                                 "Failed to enable hardware watchdog: %m");
                        if (errno != ENOTTY)
                                return -errno;
                }

                r = ioctl(watchdog_fd, WDIOC_KEEPALIVE, 0);
                if (r < 0)
                        return log_warning_errno(errno, "Failed to ping hardware watchdog: %m");
        }

        return 0;
}

static int update_timeout_fifo(void) {
        if (watchdog_fd < 0)
                return 0;

        if (watchdog_timeout == USEC_INFINITY) {
                return 0;
        } else {
                char msg[WATCHDOG_MSG_BUF_MAX];
                unsigned int sz;
                int r, sec;

                sec = (int) ((watchdog_timeout + USEC_PER_SEC - 1) / USEC_PER_SEC);

                r = watchdog_set_message(msg, sizeof(msg), "SET_TIMEOUT", sec);
                if (r < 0)
                        return r;

                sz = write(watchdog_fd, msg, strlen(msg));
                if (sz != strlen(msg))
                        return log_error_errno(r, "Failed to write update timeout: %m");
        }

        return 0;
}

static int open_watchdog_device(void) {
        struct watchdog_info ident;

        if (watchdog_fd >= 0)
                return 0;

        watchdog_fd = open(watchdog_device ?: "/dev/watchdog",
                           O_WRONLY|O_CLOEXEC);
        if (watchdog_fd < 0)
                return -errno;

        if (ioctl(watchdog_fd, WDIOC_GETSUPPORT, &ident) >= 0)
                log_info("Hardware watchdog '%s', version %x",
                         ident.identity,
                         ident.firmware_version);

        return update_timeout();
}

static int open_watchdog_fifo(void) {
        if (watchdog_fd >= 0)
                return 0;

        watchdog_fd = open(watchdog_device ?: "/dev/watchdog",
                           O_WRONLY|O_CLOEXEC|O_NONBLOCK);
        if (watchdog_fd < 0)
                return -errno;

        return update_timeout();
}

static int watchdog_ping_device(void) {
        int r;

        if (watchdog_fd < 0) {
                r = open_watchdog();
                if (r < 0)
                        return r;
        }

        r = ioctl(watchdog_fd, WDIOC_KEEPALIVE, 0);
        if (r < 0)
                return log_warning_errno(errno, "Failed to ping hardware watchdog: %m");

        return 0;
}

static int watchdog_ping_fifo(void) {
        char msg[WATCHDOG_MSG_BUF_MAX];
        unsigned int sz;
        int r;

        if (watchdog_fd < 0) {
                r = open_watchdog();
                if (r < 0)
                        return r;
        }

        r = watchdog_set_message(msg, sizeof(msg), "KEEPALIVE", 1);
        if (r < 0)
                return r;

        sz = write(watchdog_fd, msg, strlen(msg));
        if (sz != strlen(msg))
                return log_error_errno(r, "Failed to ping watchdog: %m");

        return 0;
}


static void watchdog_close_device(bool disarm) {
        int r;

        if (watchdog_fd < 0)
                return;

        if (disarm) {
                int flags;

                /* Explicitly disarm it */
                flags = WDIOS_DISABLECARD;
                r = ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags);
                if (r < 0)
                        log_warning_errno(errno, "Failed to disable hardware watchdog: %m");

                /* To be sure, use magic close logic, too */
                for (;;) {
                        static const char v = 'V';

                        if (write(watchdog_fd, &v, 1) > 0)
                                break;

                        if (errno != EINTR) {
                                log_error_errno(errno, "Failed to disarm watchdog timer: %m");
                                break;
                        }
                }
        }

        watchdog_fd = safe_close(watchdog_fd);
}

static void watchdog_close_fifo(bool disarm) {
        if (watchdog_fd < 0)
                return;

        if (disarm) {
                char msg[WATCHDOG_MSG_BUF_MAX];
                unsigned int sz;
                int r;

                r = watchdog_set_message(msg, sizeof(msg), "DISARM", 1);

                if (r < 0) {
                        log_full(LOG_ERR, "Watchdog message buffer too small");
                } else {
                        sz = write(watchdog_fd, msg, strlen(msg));
                        if (sz != strlen(msg))
                                log_error_errno(r, "Failed to disarm watchdog timer: %m");
                }
        }

        watchdog_fd = safe_close(watchdog_fd);
}

static int open_watchdog(void) {
        int r = 0;

        switch(get_watchdog_type()) {
        case WATCHDOG_TYPE_DEVICE:
                r = open_watchdog_device();
                break;
        case WATCHDOG_TYPE_FIFO:
                r = open_watchdog_fifo();
                break;
        default:
                break;
        }

        return r;
}

static int update_timeout(void) {
        int r = 0;

        switch(get_watchdog_type()) {
        case WATCHDOG_TYPE_DEVICE:
                r = update_timeout_device();
                break;
        case WATCHDOG_TYPE_FIFO:
                r = update_timeout_fifo();
                break;
        default:
                break;
        }

        return r;
}

int watchdog_set_device(char *path) {
        int r;

        r = free_and_strdup(&watchdog_device, path);
        if (r < 0)
                return r;

        if (r > 0) /* watchdog_device changed */
                watchdog_fd = safe_close(watchdog_fd);

        return r;
}

int watchdog_set_timeout(usec_t *usec) {
        int r;

        watchdog_timeout = *usec;

        /* If we didn't open the watchdog yet and didn't get any
         * explicit timeout value set, don't do anything */
        if (watchdog_fd < 0 && watchdog_timeout == USEC_INFINITY)
                return 0;

        if (watchdog_fd < 0)
                r = open_watchdog();
        else
                r = update_timeout();

        *usec = watchdog_timeout;

        return r;
}

int watchdog_ping(void) {
        int r = 0;

        switch(get_watchdog_type()) {
        case WATCHDOG_TYPE_DEVICE:
                r = watchdog_ping_device();
                break;
        case WATCHDOG_TYPE_FIFO:
                r = watchdog_ping_fifo();
                break;
        default:
                break;
        }

        return r;
}

void watchdog_close(bool disarm) {
        switch(get_watchdog_type()) {
        case WATCHDOG_TYPE_DEVICE:
                watchdog_close_device(disarm);
                break;
        case WATCHDOG_TYPE_FIFO:
                watchdog_close_fifo(disarm);
                break;
        default:
                break;
        }
}
