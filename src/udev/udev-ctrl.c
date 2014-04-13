/*
 * libudev - interface to udev device information
 *
 * Copyright (C) 2008 Kay Sievers <kay@vrfy.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "udev.h"

/* wire protocol magic must match */
#define UDEV_CTRL_MAGIC                                0xdead1dea

enum udev_ctrl_msg_type {
        UDEV_CTRL_UNKNOWN,
        UDEV_CTRL_SET_LOG_LEVEL,
        UDEV_CTRL_STOP_EXEC_QUEUE,
        UDEV_CTRL_START_EXEC_QUEUE,
        UDEV_CTRL_RELOAD,
        UDEV_CTRL_SET_ENV,
        UDEV_CTRL_SET_CHILDREN_MAX,
        UDEV_CTRL_PING,
        UDEV_CTRL_EXIT,
};

struct udev_ctrl_msg_wire {
        char version[16];
        unsigned int magic;
        enum udev_ctrl_msg_type type;
        union {
                int intval;
                char buf[256];
        };
};

struct udev_ctrl_msg {
        int refcount;
        struct udev_ctrl_connection *conn;
        struct udev_ctrl_msg_wire ctrl_msg_wire;
};

struct udev_ctrl {
        int refcount;
        struct udev *udev;
        int sock;
        struct sockaddr_un saddr;
        socklen_t addrlen;
        bool bound;
        bool cleanup_socket;
        bool connected;
};

struct udev_ctrl_connection {
        int refcount;
        struct udev_ctrl *uctrl;
        int sock;
};

struct udev_ctrl *udev_ctrl_new_from_fd(struct udev *udev, int fd)
{
        struct udev_ctrl *uctrl;
        const int on = 1;

        uctrl = new0(struct udev_ctrl, 1);
        if (uctrl == NULL)
                return NULL;
        uctrl->refcount = 1;
        uctrl->udev = udev;

        if (fd < 0) {
                uctrl->sock = socket(AF_LOCAL, SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
                if (uctrl->sock < 0) {
                        log_error("error getting socket: %m");
                        udev_ctrl_unref(uctrl);
                        return NULL;
                }
        } else {
                uctrl->bound = true;
                uctrl->sock = fd;
        }
        setsockopt(uctrl->sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));

        uctrl->saddr.sun_family = AF_LOCAL;
        strscpy(uctrl->saddr.sun_path, sizeof(uctrl->saddr.sun_path), "/run/udev/control");
        uctrl->addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(uctrl->saddr.sun_path);
        return uctrl;
}

struct udev_ctrl *udev_ctrl_new(struct udev *udev)
{
        return udev_ctrl_new_from_fd(udev, -1);
}

int udev_ctrl_enable_receiving(struct udev_ctrl *uctrl)
{
        int err;

        if (!uctrl->bound) {
                err = bind(uctrl->sock, (struct sockaddr *)&uctrl->saddr, uctrl->addrlen);
                if (err < 0 && errno == EADDRINUSE) {
                        unlink(uctrl->saddr.sun_path);
                        err = bind(uctrl->sock, (struct sockaddr *)&uctrl->saddr, uctrl->addrlen);
                }

                if (err < 0) {
                        err = -errno;
                        log_error("bind failed: %m");
                        return err;
                }

                err = listen(uctrl->sock, 0);
                if (err < 0) {
                        err = -errno;
                        log_error("listen failed: %m");
                        return err;
                }

                uctrl->bound = true;
                uctrl->cleanup_socket = true;
        }
        return 0;
}

struct udev *udev_ctrl_get_udev(struct udev_ctrl *uctrl)
{
        return uctrl->udev;
}

static struct udev_ctrl *udev_ctrl_ref(struct udev_ctrl *uctrl)
{
        if (uctrl == NULL)
                return NULL;
        uctrl->refcount++;
        return uctrl;
}

struct udev_ctrl *udev_ctrl_unref(struct udev_ctrl *uctrl)
{
        if (uctrl == NULL)
                return NULL;
        uctrl->refcount--;
        if (uctrl->refcount > 0)
                return uctrl;
        if (uctrl->sock >= 0)
                close(uctrl->sock);
        free(uctrl);
        return NULL;
}

int udev_ctrl_cleanup(struct udev_ctrl *uctrl)
{
        if (uctrl == NULL)
                return 0;
        if (uctrl->cleanup_socket)
                unlink(uctrl->saddr.sun_path);
        return 0;
}

int udev_ctrl_get_fd(struct udev_ctrl *uctrl)
{
        if (uctrl == NULL)
                return -EINVAL;
        return uctrl->sock;
}

struct udev_ctrl_connection *udev_ctrl_get_connection(struct udev_ctrl *uctrl)
{
        struct udev_ctrl_connection *conn;
        struct ucred ucred = {};
        const int on = 1;
        int r;

        conn = new(struct udev_ctrl_connection, 1);
        if (conn == NULL)
                return NULL;
        conn->refcount = 1;
        conn->uctrl = uctrl;

        conn->sock = accept4(uctrl->sock, NULL, NULL, SOCK_CLOEXEC|SOCK_NONBLOCK);
        if (conn->sock < 0) {
                if (errno != EINTR)
                        log_error("unable to receive ctrl connection: %m");
                goto err;
        }

        /* check peer credential of connection */
        r = getpeercred(conn->sock, &ucred);
        if (r < 0) {
                log_error("unable to receive credentials of ctrl connection: %s", strerror(-r));
                goto err;
        }
        if (ucred.uid > 0) {
                log_error("sender uid=%i, message ignored", ucred.uid);
                goto err;
        }

        /* enable receiving of the sender credentials in the messages */
        setsockopt(conn->sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));
        udev_ctrl_ref(uctrl);
        return conn;
err:
        if (conn->sock >= 0)
                close(conn->sock);
        free(conn);
        return NULL;
}

struct udev_ctrl_connection *udev_ctrl_connection_ref(struct udev_ctrl_connection *conn)
{
        if (conn == NULL)
                return NULL;
        conn->refcount++;
        return conn;
}

struct udev_ctrl_connection *udev_ctrl_connection_unref(struct udev_ctrl_connection *conn)
{
        if (conn == NULL)
                return NULL;
        conn->refcount--;
        if (conn->refcount > 0)
                return conn;
        if (conn->sock >= 0)
                close(conn->sock);
        udev_ctrl_unref(conn->uctrl);
        free(conn);
        return NULL;
}

static int ctrl_send(struct udev_ctrl *uctrl, enum udev_ctrl_msg_type type, int intval, const char *buf, int timeout)
{
        struct udev_ctrl_msg_wire ctrl_msg_wire;
        int err = 0;

        memzero(&ctrl_msg_wire, sizeof(struct udev_ctrl_msg_wire));
        strcpy(ctrl_msg_wire.version, "udev-" VERSION);
        ctrl_msg_wire.magic = UDEV_CTRL_MAGIC;
        ctrl_msg_wire.type = type;

        if (buf != NULL)
                strscpy(ctrl_msg_wire.buf, sizeof(ctrl_msg_wire.buf), buf);
        else
                ctrl_msg_wire.intval = intval;

        if (!uctrl->connected) {
                if (connect(uctrl->sock, (struct sockaddr *)&uctrl->saddr, uctrl->addrlen) < 0) {
                        err = -errno;
                        goto out;
                }
                uctrl->connected = true;
        }
        if (send(uctrl->sock, &ctrl_msg_wire, sizeof(ctrl_msg_wire), 0) < 0) {
                err = -errno;
                goto out;
        }

        /* wait for peer message handling or disconnect */
        for (;;) {
                struct pollfd pfd[1];
                int r;

                pfd[0].fd = uctrl->sock;
                pfd[0].events = POLLIN;
                r = poll(pfd, 1, timeout * MSEC_PER_SEC);
                if (r  < 0) {
                        if (errno == EINTR)
                                continue;
                        err = -errno;
                        break;
                }

                if (r > 0 && pfd[0].revents & POLLERR) {
                        err = -EIO;
                        break;
                }

                if (r == 0)
                        err = -ETIMEDOUT;
                break;
        }
out:
        return err;
}

int udev_ctrl_send_set_log_level(struct udev_ctrl *uctrl, int priority, int timeout)
{
        return ctrl_send(uctrl, UDEV_CTRL_SET_LOG_LEVEL, priority, NULL, timeout);
}

int udev_ctrl_send_stop_exec_queue(struct udev_ctrl *uctrl, int timeout)
{
        return ctrl_send(uctrl, UDEV_CTRL_STOP_EXEC_QUEUE, 0, NULL, timeout);
}

int udev_ctrl_send_start_exec_queue(struct udev_ctrl *uctrl, int timeout)
{
        return ctrl_send(uctrl, UDEV_CTRL_START_EXEC_QUEUE, 0, NULL, timeout);
}

int udev_ctrl_send_reload(struct udev_ctrl *uctrl, int timeout)
{
        return ctrl_send(uctrl, UDEV_CTRL_RELOAD, 0, NULL, timeout);
}

int udev_ctrl_send_set_env(struct udev_ctrl *uctrl, const char *key, int timeout)
{
        return ctrl_send(uctrl, UDEV_CTRL_SET_ENV, 0, key, timeout);
}

int udev_ctrl_send_set_children_max(struct udev_ctrl *uctrl, int count, int timeout)
{
        return ctrl_send(uctrl, UDEV_CTRL_SET_CHILDREN_MAX, count, NULL, timeout);
}

int udev_ctrl_send_ping(struct udev_ctrl *uctrl, int timeout)
{
        return ctrl_send(uctrl, UDEV_CTRL_PING, 0, NULL, timeout);
}

int udev_ctrl_send_exit(struct udev_ctrl *uctrl, int timeout)
{
        return ctrl_send(uctrl, UDEV_CTRL_EXIT, 0, NULL, timeout);
}

struct udev_ctrl_msg *udev_ctrl_receive_msg(struct udev_ctrl_connection *conn)
{
        struct udev_ctrl_msg *uctrl_msg;
        ssize_t size;
        struct cmsghdr *cmsg;
        struct iovec iov;
        char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
        struct msghdr smsg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = cred_msg,
                .msg_controllen = sizeof(cred_msg),
        };
        struct ucred *cred;

        uctrl_msg = new0(struct udev_ctrl_msg, 1);
        if (uctrl_msg == NULL)
                return NULL;
        uctrl_msg->refcount = 1;
        uctrl_msg->conn = conn;
        udev_ctrl_connection_ref(conn);

        /* wait for the incoming message */
        for (;;) {
                struct pollfd pfd[1];
                int r;

                pfd[0].fd = conn->sock;
                pfd[0].events = POLLIN;

                r = poll(pfd, 1, 10000);
                if (r  < 0) {
                        if (errno == EINTR)
                                continue;
                        goto err;
                } else if (r == 0) {
                        log_error("timeout waiting for ctrl message");
                        goto err;
                } else {
                        if (!(pfd[0].revents & POLLIN)) {
                                log_error("ctrl connection error: %m");
                                goto err;
                        }
                }

                break;
        }

        iov.iov_base = &uctrl_msg->ctrl_msg_wire;
        iov.iov_len = sizeof(struct udev_ctrl_msg_wire);

        size = recvmsg(conn->sock, &smsg, 0);
        if (size <  0) {
                log_error("unable to receive ctrl message: %m");
                goto err;
        }
        cmsg = CMSG_FIRSTHDR(&smsg);
        cred = (struct ucred *) CMSG_DATA(cmsg);

        if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
                log_error("no sender credentials received, message ignored");
                goto err;
        }

        if (cred->uid != 0) {
                log_error("sender uid=%i, message ignored", cred->uid);
                goto err;
        }

        if (uctrl_msg->ctrl_msg_wire.magic != UDEV_CTRL_MAGIC) {
                log_error("message magic 0x%08x doesn't match, ignore it", uctrl_msg->ctrl_msg_wire.magic);
                goto err;
        }

        return uctrl_msg;
err:
        udev_ctrl_msg_unref(uctrl_msg);
        return NULL;
}

struct udev_ctrl_msg *udev_ctrl_msg_unref(struct udev_ctrl_msg *ctrl_msg)
{
        if (ctrl_msg == NULL)
                return NULL;
        ctrl_msg->refcount--;
        if (ctrl_msg->refcount > 0)
                return ctrl_msg;
        udev_ctrl_connection_unref(ctrl_msg->conn);
        free(ctrl_msg);
        return NULL;
}

int udev_ctrl_get_set_log_level(struct udev_ctrl_msg *ctrl_msg)
{
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_SET_LOG_LEVEL)
                return ctrl_msg->ctrl_msg_wire.intval;
        return -1;
}

int udev_ctrl_get_stop_exec_queue(struct udev_ctrl_msg *ctrl_msg)
{
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_STOP_EXEC_QUEUE)
                return 1;
        return -1;
}

int udev_ctrl_get_start_exec_queue(struct udev_ctrl_msg *ctrl_msg)
{
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_START_EXEC_QUEUE)
                return 1;
        return -1;
}

int udev_ctrl_get_reload(struct udev_ctrl_msg *ctrl_msg)
{
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_RELOAD)
                return 1;
        return -1;
}

const char *udev_ctrl_get_set_env(struct udev_ctrl_msg *ctrl_msg)
{
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_SET_ENV)
                return ctrl_msg->ctrl_msg_wire.buf;
        return NULL;
}

int udev_ctrl_get_set_children_max(struct udev_ctrl_msg *ctrl_msg)
{
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_SET_CHILDREN_MAX)
                return ctrl_msg->ctrl_msg_wire.intval;
        return -1;
}

int udev_ctrl_get_ping(struct udev_ctrl_msg *ctrl_msg)
{
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_PING)
                return 1;
        return -1;
}

int udev_ctrl_get_exit(struct udev_ctrl_msg *ctrl_msg)
{
        if (ctrl_msg->ctrl_msg_wire.type == UDEV_CTRL_EXIT)
                return 1;
        return -1;
}
