/* SPDX-License-Identifier: LGPL-2.1+
 *
 * libudev - interface to udev device information
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "io-util.h"
#include "socket-util.h"
#include "strxcpyx.h"
#include "udev-ctrl.h"
#include "util.h"

/* wire protocol magic must match */
#define UDEV_CTRL_MAGIC                                0xdead1dea

struct udev_ctrl_msg_wire {
        char version[16];
        unsigned magic;
        enum udev_ctrl_msg_type type;
        union udev_ctrl_msg_value value;
};

struct udev_ctrl {
        unsigned n_ref;
        int sock;
        int sock_connect;
        union sockaddr_union saddr;
        socklen_t addrlen;
        bool bound:1;
        bool cleanup_socket:1;
        bool connected:1;
        sd_event *event;
        sd_event_source *event_source;
        sd_event_source *event_source_connect;
        udev_ctrl_handler_t callback;
        void *userdata;
};

int udev_ctrl_new_from_fd(struct udev_ctrl **ret, int fd) {
        _cleanup_close_ int sock = -1;
        struct udev_ctrl *uctrl;
        int r;

        assert(ret);

        if (fd < 0) {
                sock = socket(AF_LOCAL, SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
                if (sock < 0)
                        return log_error_errno(errno, "Failed to create socket: %m");
        }

        uctrl = new(struct udev_ctrl, 1);
        if (!uctrl)
                return -ENOMEM;

        *uctrl = (struct udev_ctrl) {
                .n_ref = 1,
                .sock = fd >= 0 ? fd : TAKE_FD(sock),
                .bound = fd >= 0,
        };

        /*
         * FIXME: remove it as soon as we can depend on this:
         *   http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=90c6bd34f884cd9cee21f1d152baf6c18bcac949
         */
        r = setsockopt_int(uctrl->sock, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                log_warning_errno(r, "Failed to set SO_PASSCRED: %m");

        uctrl->saddr.un = (struct sockaddr_un) {
                .sun_family = AF_UNIX,
                .sun_path = "/run/udev/control",
        };

        uctrl->addrlen = SOCKADDR_UN_LEN(uctrl->saddr.un);

        *ret = TAKE_PTR(uctrl);
        return 0;
}

int udev_ctrl_enable_receiving(struct udev_ctrl *uctrl) {
        int r;

        assert(uctrl);

        if (uctrl->bound)
                return 0;

        r = bind(uctrl->sock, &uctrl->saddr.sa, uctrl->addrlen);
        if (r < 0 && errno == EADDRINUSE) {
                (void) sockaddr_un_unlink(&uctrl->saddr.un);
                r = bind(uctrl->sock, &uctrl->saddr.sa, uctrl->addrlen);
        }

        if (r < 0)
                return log_error_errno(errno, "Failed to bind udev control socket: %m");

        if (listen(uctrl->sock, 0) < 0)
                return log_error_errno(errno, "Failed to listen udev control socket: %m");

        uctrl->bound = true;
        uctrl->cleanup_socket = true;

        return 0;
}

static void udev_ctrl_disconnect(struct udev_ctrl *uctrl) {
        if (!uctrl)
                return;

        uctrl->event_source_connect = sd_event_source_unref(uctrl->event_source_connect);
        uctrl->sock_connect = safe_close(uctrl->sock_connect);
}

static struct udev_ctrl *udev_ctrl_free(struct udev_ctrl *uctrl) {
        assert(uctrl);

        udev_ctrl_disconnect(uctrl);

        sd_event_source_unref(uctrl->event_source);
        safe_close(uctrl->sock);

        sd_event_unref(uctrl->event);
        return mfree(uctrl);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(struct udev_ctrl, udev_ctrl, udev_ctrl_free);

int udev_ctrl_cleanup(struct udev_ctrl *uctrl) {
        if (!uctrl)
                return 0;
        if (uctrl->cleanup_socket)
                sockaddr_un_unlink(&uctrl->saddr.un);
        return 0;
}

int udev_ctrl_attach_event(struct udev_ctrl *uctrl, sd_event *event) {
        int r;

        assert_return(uctrl, -EINVAL);
        assert_return(!uctrl->event, -EBUSY);

        if (event)
                uctrl->event = sd_event_ref(event);
        else {
                r = sd_event_default(&uctrl->event);
                if (r < 0)
                        return r;
        }

        return 0;
}

sd_event_source *udev_ctrl_get_event_source(struct udev_ctrl *uctrl) {
        assert(uctrl);

        return uctrl->event_source;
}

static void udev_ctrl_disconnect_and_listen_again(struct udev_ctrl *uctrl) {
        udev_ctrl_disconnect(uctrl);
        udev_ctrl_unref(uctrl);
        (void) sd_event_source_set_enabled(uctrl->event_source, SD_EVENT_ON);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_ctrl *, udev_ctrl_disconnect_and_listen_again);

static int udev_ctrl_connection_event_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(udev_ctrl_disconnect_and_listen_againp) struct udev_ctrl *uctrl = NULL;
        struct udev_ctrl_msg_wire msg_wire;
        struct iovec iov = IOVEC_MAKE(&msg_wire, sizeof(struct udev_ctrl_msg_wire));
        char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
        struct msghdr smsg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = cred_msg,
                .msg_controllen = sizeof(cred_msg),
        };
        struct cmsghdr *cmsg;
        struct ucred *cred;
        ssize_t size;

        assert(userdata);

        /* When UDEV_CTRL_EXIT is received, manager unref udev_ctrl object.
         * To avoid the object freed, let's increment the refcount. */
        uctrl = udev_ctrl_ref(userdata);

        size = next_datagram_size_fd(fd);
        if (size < 0)
                return log_error_errno(size, "Failed to get size of message: %m");
        if (size == 0)
                return 0; /* Client disconnects? */

        size = recvmsg(fd, &smsg, 0);
        if (size < 0) {
                if (errno != EINTR)
                        return log_error_errno(errno, "Failed to receive ctrl message: %m");

                return 0;
        }

        cmsg_close_all(&smsg);

        cmsg = CMSG_FIRSTHDR(&smsg);

        if (!cmsg || cmsg->cmsg_type != SCM_CREDENTIALS) {
                log_error("No sender credentials received, ignoring message");
                return 0;
        }

        cred = (struct ucred *) CMSG_DATA(cmsg);

        if (cred->uid != 0) {
                log_error("Invalid sender uid "UID_FMT", ignoring message", cred->uid);
                return 0;
        }

        if (msg_wire.magic != UDEV_CTRL_MAGIC) {
                log_error("Message magic 0x%08x doesn't match, ignoring message", msg_wire.magic);
                return 0;
        }

        if (uctrl->callback)
                (void) uctrl->callback(uctrl, msg_wire.type, &msg_wire.value, uctrl->userdata);

        return 0;
}

static int udev_ctrl_event_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        struct udev_ctrl *uctrl = userdata;
        _cleanup_close_ int sock = -1;
        struct ucred ucred;
        int r;

        assert(uctrl);

        sock = accept4(fd, NULL, NULL, SOCK_CLOEXEC|SOCK_NONBLOCK);
        if (sock < 0) {
                if (errno != EINTR)
                        log_error_errno(errno, "Failed to accept ctrl connection: %m");
                return 0;
        }

        /* check peer credential of connection */
        r = getpeercred(sock, &ucred);
        if (r < 0) {
                log_error_errno(r, "Failed to receive credentials of ctrl connection: %m");
                return 0;
        }

        if (ucred.uid > 0) {
                log_error("Invalid sender uid "UID_FMT", closing connection", ucred.uid);
                return 0;
        }

        /* enable receiving of the sender credentials in the messages */
        r = setsockopt_int(sock, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                log_warning_errno(r, "Failed to set SO_PASSCRED, ignoring: %m");

        r = sd_event_add_io(uctrl->event, &uctrl->event_source_connect, sock, EPOLLIN, udev_ctrl_connection_event_handler, uctrl);
        if (r < 0) {
                log_error_errno(r, "Failed to create event source for udev control connection: %m");
                return 0;
        }

        (void) sd_event_source_set_description(uctrl->event_source_connect, "udev-ctrl-connection");

        /* Do not accept multiple connection. */
        (void) sd_event_source_set_enabled(uctrl->event_source, SD_EVENT_OFF);

        uctrl->sock_connect = TAKE_FD(sock);
        return 0;
}

int udev_ctrl_start(struct udev_ctrl *uctrl, udev_ctrl_handler_t callback, void *userdata) {
        int r;

        assert(uctrl);

        if (!uctrl->event) {
                r = udev_ctrl_attach_event(uctrl, NULL);
                if (r < 0)
                        return r;
        }

        r = udev_ctrl_enable_receiving(uctrl);
        if (r < 0)
                return r;

        uctrl->callback = callback;
        uctrl->userdata = userdata;

        r = sd_event_add_io(uctrl->event, &uctrl->event_source, uctrl->sock, EPOLLIN, udev_ctrl_event_handler, uctrl);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(uctrl->event_source, "udev-ctrl");

        return 0;
}

static int ctrl_send(struct udev_ctrl *uctrl, enum udev_ctrl_msg_type type, int intval, const char *buf, usec_t timeout) {
        struct udev_ctrl_msg_wire ctrl_msg_wire = {
                .version = "udev-" STRINGIFY(PROJECT_VERSION),
                .magic = UDEV_CTRL_MAGIC,
                .type = type,
        };

        if (buf)
                strscpy(ctrl_msg_wire.value.buf, sizeof(ctrl_msg_wire.value.buf), buf);
        else
                ctrl_msg_wire.value.intval = intval;

        if (!uctrl->connected) {
                if (connect(uctrl->sock, &uctrl->saddr.sa, uctrl->addrlen) < 0)
                        return -errno;
                uctrl->connected = true;
        }
        if (send(uctrl->sock, &ctrl_msg_wire, sizeof(ctrl_msg_wire), 0) < 0)
                return -errno;

        /* wait for peer message handling or disconnect */
        for (;;) {
                struct pollfd pfd = {
                        .fd = uctrl->sock,
                        .events = POLLIN,
                };
                int r;

                r = poll(&pfd, 1, DIV_ROUND_UP(timeout, USEC_PER_MSEC));
                if (r < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                if (r == 0)
                        return -ETIMEDOUT;
                if (pfd.revents & POLLERR)
                        return -EIO;
                return 0;
        }
}

int udev_ctrl_send_set_log_level(struct udev_ctrl *uctrl, int priority, usec_t timeout) {
        return ctrl_send(uctrl, UDEV_CTRL_SET_LOG_LEVEL, priority, NULL, timeout);
}

int udev_ctrl_send_stop_exec_queue(struct udev_ctrl *uctrl, usec_t timeout) {
        return ctrl_send(uctrl, UDEV_CTRL_STOP_EXEC_QUEUE, 0, NULL, timeout);
}

int udev_ctrl_send_start_exec_queue(struct udev_ctrl *uctrl, usec_t timeout) {
        return ctrl_send(uctrl, UDEV_CTRL_START_EXEC_QUEUE, 0, NULL, timeout);
}

int udev_ctrl_send_reload(struct udev_ctrl *uctrl, usec_t timeout) {
        return ctrl_send(uctrl, UDEV_CTRL_RELOAD, 0, NULL, timeout);
}

int udev_ctrl_send_set_env(struct udev_ctrl *uctrl, const char *key, usec_t timeout) {
        return ctrl_send(uctrl, UDEV_CTRL_SET_ENV, 0, key, timeout);
}

int udev_ctrl_send_set_children_max(struct udev_ctrl *uctrl, int count, usec_t timeout) {
        return ctrl_send(uctrl, UDEV_CTRL_SET_CHILDREN_MAX, count, NULL, timeout);
}

int udev_ctrl_send_ping(struct udev_ctrl *uctrl, usec_t timeout) {
        return ctrl_send(uctrl, UDEV_CTRL_PING, 0, NULL, timeout);
}

int udev_ctrl_send_exit(struct udev_ctrl *uctrl, usec_t timeout) {
        return ctrl_send(uctrl, UDEV_CTRL_EXIT, 0, NULL, timeout);
}
