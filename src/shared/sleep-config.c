/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "constants.h"
#include "device-util.h"
#include "devnum-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hibernate-util.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "sleep-config.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

#define DEFAULT_SUSPEND_ESTIMATION_USEC (1 * USEC_PER_HOUR)

static const char* const sleep_operation_table[_SLEEP_OPERATION_MAX] = {
        [SLEEP_SUSPEND]                = "suspend",
        [SLEEP_HIBERNATE]              = "hibernate",
        [SLEEP_HYBRID_SLEEP]           = "hybrid-sleep",
        [SLEEP_SUSPEND_THEN_HIBERNATE] = "suspend-then-hibernate",
};

DEFINE_STRING_TABLE_LOOKUP(sleep_operation, SleepOperation);

static char* const* const sleep_default_state_table[_SLEEP_OPERATION_CONFIG_MAX] = {
        [SLEEP_SUSPEND]      = STRV_MAKE("mem", "standby", "freeze"),
        [SLEEP_HIBERNATE]    = STRV_MAKE("disk"),
        [SLEEP_HYBRID_SLEEP] = STRV_MAKE("disk"),
};

static char* const* const sleep_default_mode_table[_SLEEP_OPERATION_CONFIG_MAX] = {
        /* Not used by SLEEP_SUSPEND */
        [SLEEP_HIBERNATE]    = STRV_MAKE("platform", "shutdown"),
        [SLEEP_HYBRID_SLEEP] = STRV_MAKE("suspend"),
};

SleepConfig* sleep_config_free(SleepConfig *sc) {
        if (!sc)
                return NULL;

        for (SleepOperation i = 0; i < _SLEEP_OPERATION_CONFIG_MAX; i++) {
                strv_free(sc->states[i]);
                strv_free(sc->modes[i]);
        }

        strv_free(sc->mem_modes);

        return mfree(sc);
}

static int config_parse_sleep_mode(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char ***sv = ASSERT_PTR(data);
        _cleanup_strv_free_ char **modes = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                modes = strv_new(NULL);
                if (!modes)
                        return log_oom();
        } else {
                r = strv_split_full(&modes, rvalue, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r < 0)
                        return log_oom();
        }

        return strv_free_and_replace(*sv, modes);
}

static void sleep_config_validate_state_and_mode(SleepConfig *sc) {
        assert(sc);

        /* So we should really not allow setting SuspendState= to 'disk', which means hibernation. We have
         * SLEEP_HIBERNATE for proper hibernation support, which includes checks for resume support (through
         * EFI variable or resume= kernel command line option). It's simply not sensible to call the suspend
         * operation but eventually do an unsafe hibernation. */
        if (strv_contains(sc->states[SLEEP_SUSPEND], "disk")) {
                strv_remove(sc->states[SLEEP_SUSPEND], "disk");
                log_warning("Sleep state 'disk' is not supported by operation %s, ignoring.",
                            sleep_operation_to_string(SLEEP_SUSPEND));
        }
        assert(!sc->modes[SLEEP_SUSPEND]);

        /* People should use hybrid-sleep instead of setting HibernateMode=suspend. Warn about it but don't
         * drop it in this case. */
        if (strv_contains(sc->modes[SLEEP_HIBERNATE], "suspend"))
                log_warning("Sleep mode 'suspend' should not be used by operation %s. Please use %s instead.",
                            sleep_operation_to_string(SLEEP_HIBERNATE), sleep_operation_to_string(SLEEP_HYBRID_SLEEP));
}

int parse_sleep_config(SleepConfig **ret) {
        _cleanup_(sleep_config_freep) SleepConfig *sc = NULL;
        int allow_suspend = -1, allow_hibernate = -1, allow_s2h = -1, allow_hybrid_sleep = -1;

        assert(ret);

        sc = new(SleepConfig, 1);
        if (!sc)
                return log_oom();

        *sc = (SleepConfig) {
                .hibernate_delay_usec  = USEC_INFINITY,
                .hibernate_on_ac_power = true,
        };

        const ConfigTableItem items[] = {
                { "Sleep", "AllowSuspend",              config_parse_tristate,    0,               &allow_suspend               },
                { "Sleep", "AllowHibernation",          config_parse_tristate,    0,               &allow_hibernate             },
                { "Sleep", "AllowSuspendThenHibernate", config_parse_tristate,    0,               &allow_s2h                   },
                { "Sleep", "AllowHybridSleep",          config_parse_tristate,    0,               &allow_hybrid_sleep          },

                { "Sleep", "SuspendState",              config_parse_strv,        0,               sc->states + SLEEP_SUSPEND   },
                { "Sleep", "SuspendMode",               config_parse_warn_compat, DISABLED_LEGACY, NULL                         },

                { "Sleep", "HibernateState",            config_parse_warn_compat, DISABLED_LEGACY, NULL                         },
                { "Sleep", "HibernateMode",             config_parse_sleep_mode,  0,               sc->modes + SLEEP_HIBERNATE  },

                { "Sleep", "HybridSleepState",          config_parse_warn_compat, DISABLED_LEGACY, NULL                         },
                { "Sleep", "HybridSleepMode",           config_parse_warn_compat, DISABLED_LEGACY, NULL                         },

                { "Sleep", "MemorySleepMode",           config_parse_sleep_mode,  0,               &sc->mem_modes               },

                { "Sleep", "HibernateDelaySec",         config_parse_sec,         0,               &sc->hibernate_delay_usec    },
                { "Sleep", "HibernateOnACPower",        config_parse_bool,        0,               &sc->hibernate_on_ac_power   },
                { "Sleep", "SuspendEstimationSec",      config_parse_sec,         0,               &sc->suspend_estimation_usec },
                {}
        };

        (void) config_parse_standard_file_with_dropins(
                        "systemd/sleep.conf",
                        "Sleep\0",
                        config_item_table_lookup, items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL);

        /* use default values unless set */
        sc->allow[SLEEP_SUSPEND] = allow_suspend != 0;
        sc->allow[SLEEP_HIBERNATE] = allow_hibernate != 0;
        sc->allow[SLEEP_HYBRID_SLEEP] = allow_hybrid_sleep >= 0 ? allow_hybrid_sleep
                : (allow_suspend != 0 && allow_hibernate != 0);
        sc->allow[SLEEP_SUSPEND_THEN_HIBERNATE] = allow_s2h >= 0 ? allow_s2h
                : (allow_suspend != 0 && allow_hibernate != 0);

        for (SleepOperation i = 0; i < _SLEEP_OPERATION_CONFIG_MAX; i++) {
                if (!sc->states[i] && sleep_default_state_table[i]) {
                        sc->states[i] = strv_copy(sleep_default_state_table[i]);
                        if (!sc->states[i])
                                return log_oom();
                }

                if (!sc->modes[i] && sleep_default_mode_table[i]) {
                        sc->modes[i] = strv_copy(sleep_default_mode_table[i]);
                        if (!sc->modes[i])
                                return log_oom();
                }
        }

        if (sc->suspend_estimation_usec == 0)
                sc->suspend_estimation_usec = DEFAULT_SUSPEND_ESTIMATION_USEC;

        sleep_config_validate_state_and_mode(sc);

        *ret = TAKE_PTR(sc);
        return 0;
}

int sleep_state_supported(char * const *states) {
        _cleanup_free_ char *supported_sysfs = NULL;
        const char *found;
        int r;

        if (strv_isempty(states))
                return log_debug_errno(SYNTHETIC_ERRNO(ENOMSG), "No sleep state configured.");

        if (access("/sys/power/state", W_OK) < 0)
                return log_debug_errno(errno, "/sys/power/state is not writable: %m");

        r = read_one_line_file("/sys/power/state", &supported_sysfs);
        if (r < 0)
                return log_debug_errno(r, "Failed to read /sys/power/state: %m");

        r = string_contains_word_strv(supported_sysfs, NULL, states, &found);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse /sys/power/state: %m");
        if (r > 0) {
                log_debug("Sleep state '%s' is supported by kernel.", found);
                return true;
        }

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *joined = strv_join(states, " ");
                log_debug("None of the configured sleep states are supported by kernel: %s", strnull(joined));
        }
        return false;
}

int sleep_mode_supported(const char *path, char * const *modes) {
        _cleanup_free_ char *supported_sysfs = NULL;
        int r;

        assert(path);

        /* Unlike state, kernel has its own default choice if not configured */
        if (strv_isempty(modes)) {
                log_debug("No sleep mode configured, using kernel default for %s.", path);
                return true;
        }

        if (access(path, W_OK) < 0)
                return log_debug_errno(errno, "%s is not writable: %m", path);

        r = read_one_line_file(path, &supported_sysfs);
        if (r < 0)
                return log_debug_errno(r, "Failed to read %s: %m", path);

        for (const char *p = supported_sysfs;;) {
                _cleanup_free_ char *word = NULL;
                char *mode;
                size_t l;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse %s: %m", path);
                if (r == 0)
                        break;

                mode = word;
                l = strlen(word);

                if (mode[0] == '[' && mode[l - 1] == ']') {
                        mode[l - 1] = '\0';
                        mode++;
                }

                if (strv_contains(modes, mode)) {
                        log_debug("Sleep mode '%s' is supported by kernel (%s).", mode, path);
                        return true;
                }
        }

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *joined = strv_join(modes, " ");
                log_debug("None of the configured modes are supported by kernel (%s): %s",
                          path, strnull(joined));
        }
        return false;
}

static int sleep_supported_internal(
                const SleepConfig *sleep_config,
                SleepOperation operation,
                bool check_allowed,
                SleepSupport *ret_support);

static int s2h_supported(const SleepConfig *sleep_config, SleepSupport *ret_support) {

        static const SleepOperation operations[] = {
                SLEEP_SUSPEND,
                SLEEP_HIBERNATE,
        };

        SleepSupport support;
        int r;

        assert(sleep_config);
        assert(ret_support);

        if (!clock_supported(CLOCK_BOOTTIME_ALARM)) {
                log_debug("CLOCK_BOOTTIME_ALARM is not supported, can't perform %s.", sleep_operation_to_string(SLEEP_SUSPEND_THEN_HIBERNATE));
                *ret_support = SLEEP_ALARM_NOT_SUPPORTED;
                return false;
        }

        FOREACH_ELEMENT(i, operations) {
                r = sleep_supported_internal(sleep_config, *i, /* check_allowed = */ false, &support);
                if (r < 0)
                        return r;
                if (r == 0) {
                        log_debug("Sleep operation %s is not supported, can't perform %s.",
                                  sleep_operation_to_string(*i), sleep_operation_to_string(SLEEP_SUSPEND_THEN_HIBERNATE));
                        *ret_support = support;
                        return false;
                }
        }

        assert(support == SLEEP_SUPPORTED);
        *ret_support = support;

        return true;
}

static int sleep_supported_internal(
                const SleepConfig *sleep_config,
                SleepOperation operation,
                bool check_allowed,
                SleepSupport *ret_support) {

        int r;

        assert(sleep_config);
        assert(operation >= 0);
        assert(operation < _SLEEP_OPERATION_MAX);
        assert(ret_support);

        if (check_allowed && !sleep_config->allow[operation]) {
                log_debug("Sleep operation %s is disabled by configuration.", sleep_operation_to_string(operation));
                *ret_support = SLEEP_DISABLED;
                return false;
        }

        if (operation == SLEEP_SUSPEND_THEN_HIBERNATE)
                return s2h_supported(sleep_config, ret_support);

        assert(operation < _SLEEP_OPERATION_CONFIG_MAX);

        r = sleep_state_supported(sleep_config->states[operation]);
        if (r == -ENOMSG) {
                *ret_support = SLEEP_NOT_CONFIGURED;
                return false;
        }
        if (r < 0)
                return r;
        if (r == 0) {
                *ret_support = SLEEP_STATE_OR_MODE_NOT_SUPPORTED;
                return false;
        }

        if (SLEEP_NEEDS_MEM_SLEEP(sleep_config, operation)) {
                r = sleep_mode_supported("/sys/power/mem_sleep", sleep_config->mem_modes);
                if (r < 0)
                        return r;
                if (r == 0) {
                        *ret_support = SLEEP_STATE_OR_MODE_NOT_SUPPORTED;
                        return false;
                }
        }

        if (SLEEP_OPERATION_IS_HIBERNATION(operation)) {
                r = sleep_mode_supported("/sys/power/disk", sleep_config->modes[operation]);
                if (r < 0)
                        return r;
                if (r == 0) {
                        *ret_support = SLEEP_STATE_OR_MODE_NOT_SUPPORTED;
                        return false;
                }

                r = hibernation_is_safe();
                switch (r) {

                case -ENOTRECOVERABLE:
                        *ret_support = SLEEP_RESUME_NOT_SUPPORTED;
                        return false;

                case -ESTALE:
                        *ret_support = SLEEP_RESUME_DEVICE_MISSING;
                        return false;

                case -ENOMEDIUM:
                        *ret_support = SLEEP_RESUME_MISCONFIGURED;
                        return false;

                case -ENOSPC:
                        *ret_support = SLEEP_NOT_ENOUGH_SWAP_SPACE;
                        return false;

                default:
                        if (r < 0)
                                return r;
                }
        } else
                assert(!sleep_config->modes[operation]);

        *ret_support = SLEEP_SUPPORTED;
        return true;
}

int sleep_supported_full(SleepOperation operation, SleepSupport *ret_support) {
        _cleanup_(sleep_config_freep) SleepConfig *sleep_config = NULL;
        SleepSupport support;
        int r;

        assert(operation >= 0);
        assert(operation < _SLEEP_OPERATION_MAX);

        r = parse_sleep_config(&sleep_config);
        if (r < 0)
                return r;

        r = sleep_supported_internal(sleep_config, operation, /* check_allowed = */ true, &support);
        if (r < 0)
                return r;

        assert((r > 0) == (support == SLEEP_SUPPORTED));

        if (ret_support)
                *ret_support = support;

        return r;
}
