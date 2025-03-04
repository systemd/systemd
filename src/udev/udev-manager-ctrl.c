/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "sd-daemon.h"
#include "sd-event.h"

#include "syslog-util.h"
#include "udev-ctrl.h"
#include "udev-manager.h"
#include "udev-manager-ctrl.h"

/* receive the udevd message from userspace */
static int on_ctrl_msg(UdevCtrl *uctrl, UdevCtrlMessageType type, const UdevCtrlMessageValue *value, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        assert(value);

        switch (type) {
        case UDEV_CTRL_SET_LOG_LEVEL:
                if (!log_level_is_valid(value->intval)) {
                        log_debug("Received invalid udev control message (SET_LOG_LEVEL, %i), ignoring.", value->intval);
                        break;
                }

                log_debug("Received udev control message (SET_LOG_LEVEL), setting log_level=%i", value->intval);

                manager_set_log_level(manager, value->intval);
                break;
        case UDEV_CTRL_STOP_EXEC_QUEUE:
                log_debug("Received udev control message (STOP_EXEC_QUEUE)");
                manager->stop_exec_queue = true;
                break;
        case UDEV_CTRL_START_EXEC_QUEUE:
                log_debug("Received udev control message (START_EXEC_QUEUE)");
                manager->stop_exec_queue = false;
                /* It is not necessary to call event_queue_start() here, as it will be called in on_post() if necessary. */
                break;
        case UDEV_CTRL_RELOAD:
                log_debug("Received udev control message (RELOAD)");
                manager_reload(manager, /* force = */ true);
                break;
        case UDEV_CTRL_SET_ENV:
                if (!udev_property_assignment_is_valid(value->buf)) {
                        log_debug("Received invalid udev control message(SET_ENV, %s), ignoring.", value->buf);
                        break;
                }

                log_debug("Received udev control message(SET_ENV, %s)", value->buf);
                manager_set_environment(manager, STRV_MAKE(value->buf));
                break;
        case UDEV_CTRL_SET_CHILDREN_MAX:
                if (value->intval < 0) {
                        log_debug("Received invalid udev control message (SET_MAX_CHILDREN, %i), ignoring.", value->intval);
                        return 0;
                }

                log_debug("Received udev control message (SET_MAX_CHILDREN), setting children_max=%i", value->intval);

                manager_set_children_max(manager, value->intval);
                break;
        case UDEV_CTRL_PING:
                log_debug("Received udev control message (PING)");
                break;
        case UDEV_CTRL_EXIT:
                log_debug("Received udev control message (EXIT)");
                manager_exit(manager);
                break;
        default:
                log_debug("Received unknown udev control message, ignoring");
        }

        return 1;
}

int manager_init_ctrl(Manager *manager, int fd) {
        int r;

        assert(manager);

        /* This takes passed file descriptor on success. */

        if (fd >= 0) {
                if (manager->ctrl)
                        return log_warning_errno(SYNTHETIC_ERRNO(EALREADY), "Received multiple control socket (%i), ignoring.", fd);

                r = sd_is_socket(fd, AF_UNIX, SOCK_SEQPACKET, -1);
                if (r < 0)
                        return log_warning_errno(r, "Failed to verify socket type of %i, ignoring: %m", fd);
                if (r == 0)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Received invalid control socket (%i), ignoring.", fd);
        } else {
                if (manager->ctrl)
                        return 0;
        }

        r = udev_ctrl_new_from_fd(&manager->ctrl, fd);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize udev control socket: %m");

        return 0;
}

int manager_start_ctrl(Manager *manager) {
        int r;

        assert(manager);
        assert(manager->event);

        r = manager_init_ctrl(manager, -EBADF);
        if (r < 0)
                return r;

        r = udev_ctrl_enable_receiving(manager->ctrl);
        if (r < 0)
                return log_error_errno(r, "Failed to bind udev control socket: %m");

        r = udev_ctrl_attach_event(manager->ctrl, manager->event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach event to udev control: %m");

        r = udev_ctrl_start(manager->ctrl, on_ctrl_msg, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to start udev control: %m");

        /* This needs to be after the inotify and uevent handling, to make sure that the ping is send back
         * after fully processing the pending uevents (including the synthetic ones we may create due to
         * inotify events). */
        r = sd_event_source_set_priority(udev_ctrl_get_event_source(manager->ctrl), SD_EVENT_PRIORITY_IDLE);
        if (r < 0)
                return log_error_errno(r, "Failed to set IDLE event priority for udev control event source: %m");

        return 0;
}
