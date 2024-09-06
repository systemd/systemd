/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "iovec-util.h"
#include "socket-util.h"
#include "strxcpyx.h"
#include "udev-ctrl.h"

/* wire protocol magic must match */
#define UDEV_CTRL_MAGIC                                0xdead1dea

typedef struct UdevCtrlMessageWire {
        char version[16];
        unsigned magic;
        UdevCtrlMessageType type;
        UdevCtrlMessageValue value;
} UdevCtrlMessageWire;

struct UdevCtrl {
        unsigned n_ref;
        int sock;
        int sock_connect;
        union sockaddr_union saddr;
        socklen_t addrlen;
        bool bound;
        bool connected;
        sd_event *event;
        sd_event_source *event_source;
        sd_event_source *event_source_connect;
        udev_ctrl_handler_t callback;
        void *userdata;
};

int udev_ctrl_new_from_fd(UdevCtrl **ret, int fd) {
        _cleanup_close_ int sock = -EBADF;
        UdevCtrl *uctrl;

        assert(ret);

        if (fd < 0) {
                sock = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
                if (sock < 0)
                        return log_error_errno(errno, "Failed to create socket: %m");
        }

        uctrl = new(UdevCtrl, 1);
        if (!uctrl)
                return -ENOMEM;

        *uctrl = (UdevCtrl) {
                .n_ref = 1,
                .sock = fd >= 0 ? fd : TAKE_FD(sock),
                .sock_connect = -EBADF,
                .bound = fd >= 0,
        };

        uctrl->saddr.un = (struct sockaddr_un) {
                .sun_family = AF_UNIX,
                .sun_path = "/run/udev/control",
        };

        uctrl->addrlen = SOCKADDR_UN_LEN(uctrl->saddr.un);

        *ret = TAKE_PTR(uctrl);
        return 0;
}

int udev_ctrl_enable_receiving(UdevCtrl *uctrl) {
        assert(uctrl);

        if (uctrl->bound)
                return 0;

        (void) sockaddr_un_unlink(&uctrl->saddr.un);
        if (bind(uctrl->sock, &uctrl->saddr.sa, uctrl->addrlen) < 0)
                return log_error_errno(errno, "Failed to bind udev control socket: %m");

        if (listen(uctrl->sock, 0) < 0)
                return log_error_errno(errno, "Failed to listen udev control socket: %m");

        uctrl->bound = true;
        return 0;
}

static void udev_ctrl_disconnect(UdevCtrl *uctrl) {
        if (!uctrl)
                return;

        uctrl->event_source_connect = sd_event_source_unref(uctrl->event_source_connect);
        uctrl->sock_connect = safe_close(uctrl->sock_connect);
}

static UdevCtrl *udev_ctrl_free(UdevCtrl *uctrl) {
        assert(uctrl);

        udev_ctrl_disconnect(uctrl);

        sd_event_source_unref(uctrl->event_source);
        safe_close(uctrl->sock);

        sd_event_unref(uctrl->event);
        return mfree(uctrl);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(UdevCtrl, udev_ctrl, udev_ctrl_free);

int udev_ctrl_attach_event(UdevCtrl *uctrl, sd_event *event) {
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

sd_event_source *udev_ctrl_get_event_source(UdevCtrl *uctrl) {
        assert(uctrl);

        return uctrl->event_source;
}

static void udev_ctrl_disconnect_and_listen_again(UdevCtrl *uctrl) {
        udev_ctrl_disconnect(uctrl);
        udev_ctrl_unref(uctrl);
        (void) sd_event_source_set_enabled(uctrl->event_source, SD_EVENT_ON);
        /* We don't return NULL here because uctrl is not freed */
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(UdevCtrl*, udev_ctrl_disconnect_and_listen_again, NULL);

static int udev_ctrl_connection_event_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(udev_ctrl_disconnect_and_listen_againp) UdevCtrl *uctrl = NULL;
        UdevCtrlMessageWire msg_wire;
        struct iovec iov = IOVEC_MAKE(&msg_wire, sizeof(UdevCtrlMessageWire));
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred))) control;
        struct msghdr smsg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct ucred *cred;
        ssize_t size;

        assert(userdata);

        /* When UDEV_CTRL_EXIT is received, manager unref udev_ctrl object.
         * To avoid the object freed, let's increment the refcount. */
        uctrl = udev_ctrl_ref(userdata);

        size = recvmsg_safe(fd, &smsg, 0);
        if (ERRNO_IS_NEG_TRANSIENT(size))
                return 0;
        if (size == -ECHRNG) {
                log_warning_errno(size, "Got message with truncated control data (unexpected fds sent?), ignoring.");
                return 0;
        }
        if (size == -EXFULL) {
                log_warning_errno(size, "Got message with truncated payload data, ignoring.");
                return 0;
        }
        if (size < 0)
                return log_error_errno(size, "Failed to receive ctrl message: %m");

        cmsg_close_all(&smsg);

        if (size != sizeof(msg_wire)) {
                log_warning("Received message with invalid length, ignoring");
                return 0;
        }

        cred = CMSG_FIND_DATA(&smsg, SOL_SOCKET, SCM_CREDENTIALS, struct ucred);
        if (!cred) {
                log_warning("No sender credentials received, ignoring message");
                return 0;
        }

        if (cred->uid != 0) {
                log_warning("Invalid sender uid "UID_FMT", ignoring message", cred->uid);
                return 0;
        }

        if (msg_wire.magic != UDEV_CTRL_MAGIC) {
                log_warning("Message magic 0x%08x doesn't match, ignoring message", msg_wire.magic);
                return 0;
        }

        if (msg_wire.type == _UDEV_CTRL_END_MESSAGES)
                return 0;

        if (uctrl->callback)
                (void) uctrl->callback(uctrl, msg_wire.type, &msg_wire.value, uctrl->userdata);

        /* Do not disconnect and wait for next message. */
        uctrl = udev_ctrl_unref(uctrl);
        return 0;
}

static int udev_ctrl_event_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        UdevCtrl *uctrl = ASSERT_PTR(userdata);
        _cleanup_close_ int sock = -EBADF;
        struct ucred ucred;
        int r;

        sock = accept4(fd, NULL, NULL, SOCK_CLOEXEC|SOCK_NONBLOCK);
        if (sock < 0) {
                if (ERRNO_IS_ACCEPT_AGAIN(errno))
                        return 0;

                return log_error_errno(errno, "Failed to accept ctrl connection: %m");
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

int udev_ctrl_start(UdevCtrl *uctrl, udev_ctrl_handler_t callback, void *userdata) {
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

int udev_ctrl_send(UdevCtrl *uctrl, UdevCtrlMessageType type, const void *data) {
        UdevCtrlMessageWire ctrl_msg_wire = {
                .version = "udev-" STRINGIFY(PROJECT_VERSION),
                .magic = UDEV_CTRL_MAGIC,
                .type = type,
        };

        if (type == UDEV_CTRL_SET_ENV) {
                assert(data);
                strscpy(ctrl_msg_wire.value.buf, sizeof(ctrl_msg_wire.value.buf), data);
        } else if (IN_SET(type, UDEV_CTRL_SET_LOG_LEVEL, UDEV_CTRL_SET_CHILDREN_MAX))
                ctrl_msg_wire.value.intval = PTR_TO_INT(data);

        if (!uctrl->connected) {
                if (connect(uctrl->sock, &uctrl->saddr.sa, uctrl->addrlen) < 0)
                        return -errno;
                uctrl->connected = true;
        }

        if (send(uctrl->sock, &ctrl_msg_wire, sizeof(ctrl_msg_wire), 0) < 0)
                return -errno;

        return 0;
}

int udev_ctrl_wait(UdevCtrl *uctrl, usec_t timeout) {
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *source_io = NULL, *source_timeout = NULL;
        int r;

        assert(uctrl);

        if (uctrl->sock < 0)
                return 0;
        if (!uctrl->connected)
                return 0;

        r = udev_ctrl_send(uctrl, _UDEV_CTRL_END_MESSAGES, NULL);
        if (r < 0)
                return r;

        if (timeout == 0)
                return 0;

        if (!uctrl->event) {
                r = udev_ctrl_attach_event(uctrl, NULL);
                if (r < 0)
                        return r;
        }

        r = sd_event_add_io(uctrl->event, &source_io, uctrl->sock, EPOLLIN, NULL, INT_TO_PTR(0));
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(source_io, "udev-ctrl-wait-io");

        if (timeout != USEC_INFINITY) {
                r = sd_event_add_time_relative(
                                uctrl->event, &source_timeout, CLOCK_BOOTTIME,
                                timeout,
                                0, NULL, INT_TO_PTR(-ETIMEDOUT));
                if (r < 0)
                        return r;

                (void) sd_event_source_set_description(source_timeout, "udev-ctrl-wait-timeout");
        }

        return sd_event_loop(uctrl->event);
}
