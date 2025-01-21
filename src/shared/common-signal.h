/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <syslog.h>

#include "sd-event.h"

/* All our long-running services should implement a SIGRTMIN+18 handler that can be used to trigger certain
 * actions that affect service runtime. The specific action is indicated via the "value integer" you can pass
 * along realtime signals. This is mostly intended for debugging purposes and is entirely asynchronous in
 * nature. Specifically, these are the commands:
 *
 * Currently available operations:
 *
 *         • Change maximum log level
 *         • Change log target
 *         • Invoke memory trimming, like under memory pressure
 *         • Write glibc malloc() allocation info to logs
 *
 * How to use this? Via a command like the following:
 *
 *         /usr/bin/kill -s RTMIN+18 -q 768 1
 *
 *         (This will tell PID 1 to trim its memory use.)
 *
 * or:
 *
 *         systemctl kill --kill-value=0x300 -s RTMIN+18 systemd-journald
 *
 *         (This will tell journald to trim its memory use.)
 */

enum {
        _COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE = 0x100,
        COMMON_SIGNAL_COMMAND_LOG_EMERG       = _COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE + LOG_EMERG,
        COMMON_SIGNAL_COMMAND_LOG_ALERT       = _COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE + LOG_ALERT,
        COMMON_SIGNAL_COMMAND_LOG_CRIT        = _COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE + LOG_CRIT,
        COMMON_SIGNAL_COMMAND_LOG_ERR         = _COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE + LOG_ERR,
        COMMON_SIGNAL_COMMAND_LOG_WARNING     = _COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE + LOG_WARNING,
        COMMON_SIGNAL_COMMAND_LOG_NOTICE      = _COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE + LOG_NOTICE,
        COMMON_SIGNAL_COMMAND_LOG_INFO        = _COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE + LOG_INFO,
        COMMON_SIGNAL_COMMAND_LOG_DEBUG       = _COMMON_SIGNAL_COMMAND_LOG_LEVEL_BASE + LOG_DEBUG,
        _COMMON_SIGNAL_COMMAND_LOG_LEVEL_END  = COMMON_SIGNAL_COMMAND_LOG_DEBUG,

        COMMON_SIGNAL_COMMAND_CONSOLE         = 0x200,
        COMMON_SIGNAL_COMMAND_JOURNAL,
        COMMON_SIGNAL_COMMAND_KMSG,
        COMMON_SIGNAL_COMMAND_NULL,

        COMMON_SIGNAL_COMMAND_MEMORY_PRESSURE = 0x300,
        COMMON_SIGNAL_COMMAND_MALLOC_INFO,

        /* Private signals start at 0x500 */
        _COMMON_SIGNAL_COMMAND_PRIVATE_BASE = 0x500,
        _COMMON_SIGNAL_COMMAND_PRIVATE_END = 0xfff,
};

struct sigrtmin18_info {
        sd_event_handler_t memory_pressure_handler;
        void *memory_pressure_userdata;
};

int sigrtmin18_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata);
