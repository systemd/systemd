/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include "macro.h"
#include "time-util.h"

struct udev_ctrl;
struct udev_ctrl *udev_ctrl_new(void);
struct udev_ctrl *udev_ctrl_new_from_fd(int fd);
int udev_ctrl_enable_receiving(struct udev_ctrl *uctrl);
struct udev_ctrl *udev_ctrl_unref(struct udev_ctrl *uctrl);
int udev_ctrl_cleanup(struct udev_ctrl *uctrl);
int udev_ctrl_get_fd(struct udev_ctrl *uctrl);
int udev_ctrl_send_set_log_level(struct udev_ctrl *uctrl, int priority, usec_t timeout);
int udev_ctrl_send_stop_exec_queue(struct udev_ctrl *uctrl, usec_t timeout);
int udev_ctrl_send_start_exec_queue(struct udev_ctrl *uctrl, usec_t timeout);
int udev_ctrl_send_reload(struct udev_ctrl *uctrl, usec_t timeout);
int udev_ctrl_send_ping(struct udev_ctrl *uctrl, usec_t timeout);
int udev_ctrl_send_exit(struct udev_ctrl *uctrl, usec_t timeout);
int udev_ctrl_send_set_env(struct udev_ctrl *uctrl, const char *key, usec_t timeout);
int udev_ctrl_send_set_children_max(struct udev_ctrl *uctrl, int count, usec_t timeout);

struct udev_ctrl_connection;
struct udev_ctrl_connection *udev_ctrl_get_connection(struct udev_ctrl *uctrl);
struct udev_ctrl_connection *udev_ctrl_connection_ref(struct udev_ctrl_connection *conn);
struct udev_ctrl_connection *udev_ctrl_connection_unref(struct udev_ctrl_connection *conn);

struct udev_ctrl_msg;
struct udev_ctrl_msg *udev_ctrl_receive_msg(struct udev_ctrl_connection *conn);
struct udev_ctrl_msg *udev_ctrl_msg_unref(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_set_log_level(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_stop_exec_queue(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_start_exec_queue(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_reload(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_ping(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_exit(struct udev_ctrl_msg *ctrl_msg);
const char *udev_ctrl_get_set_env(struct udev_ctrl_msg *ctrl_msg);
int udev_ctrl_get_set_children_max(struct udev_ctrl_msg *ctrl_msg);

DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_ctrl*, udev_ctrl_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_ctrl_connection*, udev_ctrl_connection_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_ctrl_msg*, udev_ctrl_msg_unref);
