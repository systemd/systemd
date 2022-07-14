/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "sd-device.h"

#include "macro.h"

typedef struct Link Link;
typedef struct Manager Manager;

/* The following values are different from the ones defined in linux/rfkill.h. */
typedef enum RFKillState {
        RFKILL_UNKNOWN,
        RFKILL_UNBLOCKED,
        RFKILL_SOFT,
        RFKILL_HARD,
        _RFKILL_STATE_MAX,
        _RFKILL_STATE_INVALID = -EINVAL,
} RFKillState;

typedef struct Wiphy {
        Manager *manager;

        uint32_t index;
        char *name;

        sd_device *dev;
        sd_device *rfkill;
        RFKillState rfkill_state;
} Wiphy;

Wiphy *wiphy_free(Wiphy *w);
DEFINE_TRIVIAL_CLEANUP_FUNC(Wiphy*, wiphy_free);

int wiphy_get_by_index(Manager *manager, uint32_t index, Wiphy **ret);
int wiphy_get_by_name(Manager *manager, const char *name, Wiphy **ret);

int link_rfkilled(Link *link);

int manager_genl_process_nl80211_wiphy(sd_netlink *genl, sd_netlink_message *message, Manager *manager);
int manager_udev_process_wiphy(Manager *m, sd_device *device, sd_device_action_t action);
int manager_udev_process_rfkill(Manager *m, sd_device *device, sd_device_action_t action);

#define log_wiphy_full_errno_zerook(w, level, error, ...)               \
        ({                                                              \
                const Wiphy *_w = (w);                                  \
                log_interface_full_errno_zerook(_w ? _w->name : NULL, level, error, __VA_ARGS__); \
        })

#define log_wiphy_full_errno(w, level, error, ...)                      \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_wiphy_full_errno_zerook(w, level, _error, __VA_ARGS__); \
        })

#define log_wiphy_full(w, level, ...) (void) log_wiphy_full_errno_zerook(w, level, 0, __VA_ARGS__)

#define log_wiphy_debug(w, ...)   log_wiphy_full(w, LOG_DEBUG, __VA_ARGS__)
#define log_wiphy_info(w, ...)    log_wiphy_full(w, LOG_INFO, __VA_ARGS__)
#define log_wiphy_notice(w, ...)  log_wiphy_full(w, LOG_NOTICE, __VA_ARGS__)
#define log_wiphy_warning(w, ...) log_wiphy_full(w, LOG_WARNING, __VA_ARGS__)
#define log_wiphy_error(w, ...)   log_wiphy_full(w, LOG_ERR, __VA_ARGS__)

#define log_wiphy_debug_errno(w, error, ...)   log_wiphy_full_errno(w, LOG_DEBUG, error, __VA_ARGS__)
#define log_wiphy_info_errno(w, error, ...)    log_wiphy_full_errno(w, LOG_INFO, error, __VA_ARGS__)
#define log_wiphy_notice_errno(w, error, ...)  log_wiphy_full_errno(w, LOG_NOTICE, error, __VA_ARGS__)
#define log_wiphy_warning_errno(w, error, ...) log_wiphy_full_errno(w, LOG_WARNING, error, __VA_ARGS__)
#define log_wiphy_error_errno(w, error, ...)   log_wiphy_full_errno(w, LOG_ERR, error, __VA_ARGS__)
