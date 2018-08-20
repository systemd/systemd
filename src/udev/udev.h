/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

/*
 * Copyright © 2003 Greg Kroah-Hartman <greg@kroah.com>
 */

#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include "libudev.h"
#include "sd-netlink.h"

#include "label.h"
#include "libudev-private.h"
#include "macro.h"
#include "strv.h"
#include "util.h"

struct udev_event {
        struct udev_device *dev;
        struct udev_device *dev_parent;
        struct udev_device *dev_db;
        char *name;
        char *program_result;
        mode_t mode;
        uid_t uid;
        gid_t gid;
        struct udev_list seclabel_list;
        struct udev_list run_list;
        int exec_delay;
        usec_t birth_usec;
        sd_netlink *rtnl;
        unsigned int builtin_run;
        unsigned int builtin_ret;
        bool inotify_watch;
        bool inotify_watch_final;
        bool group_set;
        bool group_final;
        bool owner_set;
        bool owner_final;
        bool mode_set;
        bool mode_final;
        bool name_final;
        bool devlink_final;
        bool run_final;
};

/* udev-rules.c */
struct udev_rules;
struct udev_rules *udev_rules_new(int resolve_names);
struct udev_rules *udev_rules_unref(struct udev_rules *rules);
bool udev_rules_check_timestamp(struct udev_rules *rules);
void udev_rules_apply_to_event(struct udev_rules *rules, struct udev_event *event,
                               usec_t timeout_usec, usec_t timeout_warn_usec,
                               struct udev_list *properties_list);
int udev_rules_apply_static_dev_perms(struct udev_rules *rules);

/* udev-event.c */
struct udev_event *udev_event_new(struct udev_device *dev);
void udev_event_unref(struct udev_event *event);
size_t udev_event_apply_format(struct udev_event *event,
                               const char *src, char *dest, size_t size,
                               bool replace_whitespace);
int udev_event_apply_subsys_kernel(struct udev_event *event, const char *string,
                                   char *result, size_t maxsize, int read_value);
int udev_event_spawn(struct udev_event *event,
                     usec_t timeout_usec,
                     usec_t timeout_warn_usec,
                     bool accept_failure,
                     const char *cmd, char *result, size_t ressize);
void udev_event_execute_rules(struct udev_event *event,
                              usec_t timeout_usec, usec_t timeout_warn_usec,
                              struct udev_list *properties_list,
                              struct udev_rules *rules);
void udev_event_execute_run(struct udev_event *event, usec_t timeout_usec, usec_t timeout_warn_usec);
int udev_build_argv(char *cmd, int *argc, char *argv[]);

/* udev-watch.c */
int udev_watch_init(void);
void udev_watch_restore(void);
void udev_watch_begin(struct udev_device *dev);
void udev_watch_end(struct udev_device *dev);
struct udev_device *udev_watch_lookup(int wd);

/* udev-node.c */
void udev_node_add(struct udev_device *dev, bool apply,
                   mode_t mode, uid_t uid, gid_t gid,
                   struct udev_list *seclabel_list);
void udev_node_remove(struct udev_device *dev);
void udev_node_update_old_links(struct udev_device *dev, struct udev_device *dev_old);

/* udev-ctrl.c */
struct udev_ctrl;
struct udev_ctrl *udev_ctrl_new(void);
struct udev_ctrl *udev_ctrl_new_from_fd(int fd);
int udev_ctrl_enable_receiving(struct udev_ctrl *uctrl);
struct udev_ctrl *udev_ctrl_unref(struct udev_ctrl *uctrl);
int udev_ctrl_cleanup(struct udev_ctrl *uctrl);
int udev_ctrl_get_fd(struct udev_ctrl *uctrl);
int udev_ctrl_send_set_log_level(struct udev_ctrl *uctrl, int priority, int timeout);
int udev_ctrl_send_stop_exec_queue(struct udev_ctrl *uctrl, int timeout);
int udev_ctrl_send_start_exec_queue(struct udev_ctrl *uctrl, int timeout);
int udev_ctrl_send_reload(struct udev_ctrl *uctrl, int timeout);
int udev_ctrl_send_ping(struct udev_ctrl *uctrl, int timeout);
int udev_ctrl_send_exit(struct udev_ctrl *uctrl, int timeout);
int udev_ctrl_send_set_env(struct udev_ctrl *uctrl, const char *key, int timeout);
int udev_ctrl_send_set_children_max(struct udev_ctrl *uctrl, int count, int timeout);
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

/* built-in commands */
enum udev_builtin_cmd {
#if HAVE_BLKID
        UDEV_BUILTIN_BLKID,
#endif
        UDEV_BUILTIN_BTRFS,
        UDEV_BUILTIN_HWDB,
        UDEV_BUILTIN_INPUT_ID,
        UDEV_BUILTIN_KEYBOARD,
#if HAVE_KMOD
        UDEV_BUILTIN_KMOD,
#endif
        UDEV_BUILTIN_NET_ID,
        UDEV_BUILTIN_NET_LINK,
        UDEV_BUILTIN_PATH_ID,
        UDEV_BUILTIN_USB_ID,
#if HAVE_ACL
        UDEV_BUILTIN_UACCESS,
#endif
        UDEV_BUILTIN_MAX
};
struct udev_builtin {
        const char *name;
        int (*cmd)(struct udev_device *dev, int argc, char *argv[], bool test);
        const char *help;
        int (*init)(void);
        void (*exit)(void);
        bool (*validate)(void);
        bool run_once;
};
#if HAVE_BLKID
extern const struct udev_builtin udev_builtin_blkid;
#endif
extern const struct udev_builtin udev_builtin_btrfs;
extern const struct udev_builtin udev_builtin_hwdb;
extern const struct udev_builtin udev_builtin_input_id;
extern const struct udev_builtin udev_builtin_keyboard;
#if HAVE_KMOD
extern const struct udev_builtin udev_builtin_kmod;
#endif
extern const struct udev_builtin udev_builtin_net_id;
extern const struct udev_builtin udev_builtin_net_setup_link;
extern const struct udev_builtin udev_builtin_path_id;
extern const struct udev_builtin udev_builtin_usb_id;
extern const struct udev_builtin udev_builtin_uaccess;
void udev_builtin_init(void);
void udev_builtin_exit(void);
enum udev_builtin_cmd udev_builtin_lookup(const char *command);
const char *udev_builtin_name(enum udev_builtin_cmd cmd);
bool udev_builtin_run_once(enum udev_builtin_cmd cmd);
int udev_builtin_run(struct udev_device *dev, enum udev_builtin_cmd cmd, const char *command, bool test);
void udev_builtin_list(void);
bool udev_builtin_validate(void);
int udev_builtin_add_property(struct udev_device *dev, bool test, const char *key, const char *val);
int udev_builtin_hwdb_lookup(struct udev_device *dev, const char *prefix, const char *modalias,
                             const char *filter, bool test);

/* udevadm commands */
struct udevadm_cmd {
        const char *name;
        int (*cmd)(int argc, char *argv[]);
        const char *help;
        int debug;
};
extern const struct udevadm_cmd udevadm_info;
extern const struct udevadm_cmd udevadm_trigger;
extern const struct udevadm_cmd udevadm_settle;
extern const struct udevadm_cmd udevadm_control;
extern const struct udevadm_cmd udevadm_monitor;
extern const struct udevadm_cmd udevadm_hwdb;
extern const struct udevadm_cmd udevadm_test;
extern const struct udevadm_cmd udevadm_test_builtin;
