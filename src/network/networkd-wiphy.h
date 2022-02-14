/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <inttypes.h>

#include "sd-device.h"

#include "macro.h"

typedef struct Manager Manager;

typedef struct Wiphy {
        Manager *manager;

        uint32_t index;
        char *name;
} Wiphy;

Wiphy *wiphy_free(Wiphy *w);
DEFINE_TRIVIAL_CLEANUP_FUNC(Wiphy*, wiphy_free);

int wiphy_get_by_index(Manager *manager, uint32_t index, Wiphy **ret);
int wiphy_get_by_name(Manager *manager, const char *name, Wiphy **ret);

int manager_genl_process_nl80211_wiphy(sd_netlink *genl, sd_netlink_message *message, Manager *manager);

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
