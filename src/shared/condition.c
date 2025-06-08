/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <fnmatch.h>
#include <gnu/libc-version.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "apparmor-util.h"
#include "architecture.h"
#include "battery-util.h"
#include "bitfield.h"
#include "blockdev-util.h"
#include "capability-list.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "compare-operator.h"
#include "condition.h"
#include "confidential-virt.h"
#include "cpu-set-util.h"
#include "creds-util.h"
#include "efi-loader.h"
#include "efivars.h"
#include "env-file.h"
#include "env-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "glob-util.h"
#include "hostname-setup.h"
#include "id128-util.h"
#include "ima-util.h"
#include "initrd-util.h"
#include "libaudit-util.h"
#include "limits-util.h"
#include "list.h"
#include "log.h"
#include "mountpoint-util.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "percent-util.h"
#include "pidref.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "psi-util.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "special.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "tomoyo-util.h"
#include "tpm2-util.h"
#include "uid-classification.h"
#include "user-util.h"
#include "virt.h"

Condition* condition_new(ConditionType type, const char *parameter, bool trigger, bool negate) {
        Condition *c;

        assert(type >= 0);
        assert(type < _CONDITION_TYPE_MAX);
        assert(parameter);

        c = new(Condition, 1);
        if (!c)
                return NULL;

        *c = (Condition) {
                .type = type,
                .trigger = trigger,
                .negate = negate,
        };

        if (parameter) {
                c->parameter = strdup(parameter);
                if (!c->parameter)
                        return mfree(c);
        }

        return c;
}

Condition* condition_free(Condition *c) {
        assert(c);

        free(c->parameter);
        return mfree(c);
}

Condition* condition_free_list_type(Condition *head, ConditionType type) {
        LIST_FOREACH(conditions, c, head)
                if (type < 0 || c->type == type) {
                        LIST_REMOVE(conditions, head, c);
                        condition_free(c);
                }

        assert(type >= 0 || !head);
        return head;
}

static int condition_test_kernel_command_line(Condition *c, char **env) {
        _cleanup_strv_free_ char **args = NULL;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_KERNEL_COMMAND_LINE);

        r = proc_cmdline_strv(&args);
        if (r < 0)
                return r;

        bool equal = strchr(c->parameter, '=');

        STRV_FOREACH(word, args) {
                bool found;

                if (equal)
                        found = streq(*word, c->parameter);
                else {
                        const char *f;

                        f = startswith(*word, c->parameter);
                        found = f && IN_SET(*f, 0, '=');
                }

                if (found)
                        return true;
        }

        return false;
}

static int condition_test_credential(Condition *c, char **env) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_CREDENTIAL);

        /* For now we'll do a very simple existence check and are happy with either a regular or an encrypted
         * credential. Given that we check the syntax of the argument we have the option to later maybe allow
         * contents checks too without breaking compatibility, but for now let's be minimalistic. */

        if (!credential_name_valid(c->parameter)) /* credentials with invalid names do not exist */
                return false;

        int (*gd)(const char **ret);
        FOREACH_ARGUMENT(gd, get_credentials_dir, get_encrypted_credentials_dir) {
                _cleanup_free_ char *j = NULL;
                const char *cd;

                r = gd(&cd);
                if (r == -ENXIO) /* no env var set */
                        continue;
                if (r < 0)
                        return r;

                j = path_join(cd, c->parameter);
                if (!j)
                        return -ENOMEM;

                r = access_nofollow(j, F_OK);
                if (r >= 0)
                        return true; /* yay! */
                if (r != -ENOENT)
                        return r;

                /* not found in this dir */
        }

        return false;
}

static int condition_test_version_cmp(const char *condition, const char *ver) {
        CompareOperator operator;
        bool first = true;

        assert(ver);

        for (const char *p = condition;;) {
                _cleanup_free_ char *word = NULL;
                const char *s;
                int r;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse condition string \"%s\": %m", p);
                if (r == 0)
                        break;

                s = strstrip(word);
                operator = parse_compare_operator(&s, COMPARE_ALLOW_FNMATCH|COMPARE_EQUAL_BY_STRING);
                if (operator < 0) /* No prefix? Then treat as glob string */
                        operator = COMPARE_FNMATCH_EQUAL;

                s += strspn(s, WHITESPACE);
                if (isempty(s)) {
                        if (first) {
                                /* For backwards compatibility, allow whitespace between the operator and
                                 * value, without quoting, but only in the first expression. */
                                word = mfree(word);
                                r = extract_first_word(&p, &word, NULL, 0);
                                if (r < 0)
                                        return log_debug_errno(r, "Failed to parse condition string \"%s\": %m", p);
                                if (r == 0)
                                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected end of expression: %s", p);
                                s = word;
                        } else
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected end of expression: %s", p);
                }

                r = version_or_fnmatch_compare(operator, ver, s);
                if (r < 0)
                        return r;
                if (!r)
                        return false;

                first = false;
        }

        return true;
}

static int condition_test_version(Condition *c, char **env) {
        int r;

        assert(c);
        assert(c->type == CONDITION_VERSION);

        /* An empty condition is considered true. */
        if (isempty(c->parameter))
                return true;

        const char *p = c->parameter;
        _cleanup_free_ char *word = NULL;
        r = extract_first_word(&p, &word, COMPARE_OPERATOR_WITH_FNMATCH_CHARS WHITESPACE,
                               EXTRACT_DONT_COALESCE_SEPARATORS|EXTRACT_RETAIN_SEPARATORS);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse compare predicate \"%s\": %m", p);
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Missing right operand in condition: %s", c->parameter);

        if (streq(word, "systemd"))
                return condition_test_version_cmp(p, STRINGIFY(PROJECT_VERSION));

        if (streq(word, "glibc")) {
                const char *v = gnu_get_libc_version();
                if (!v)
                        return false; /* built with musl */

                return condition_test_version_cmp(p, v);
        }

        /* if no predicate has been set, default to "kernel" and use the whole parameter as condition */
        if (!streq(word, "kernel"))
                p = c->parameter;

        struct utsname u;
        assert_se(uname(&u) >= 0);
        return condition_test_version_cmp(p, u.release);
}

static int condition_test_osrelease(Condition *c, char **env) {
        int r;

        assert(c);
        assert(c->type == CONDITION_OS_RELEASE);

        for (const char *parameter = ASSERT_PTR(c->parameter);;) {
                _cleanup_free_ char *key = NULL, *condition = NULL, *actual_value = NULL;
                CompareOperator operator;
                const char *word;

                r = extract_first_word(&parameter, &condition, NULL, EXTRACT_UNQUOTE);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse parameter: %m");
                if (r == 0)
                        break;

                /* parse_compare_operator() needs the string to start with the comparators */
                word = condition;
                r = extract_first_word(&word, &key, COMPARE_OPERATOR_WITH_FNMATCH_CHARS, EXTRACT_RETAIN_SEPARATORS);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse parameter: %m");
                /* The os-release spec mandates env-var-like key names */
                if (r == 0 || isempty(word) || !env_name_is_valid(key))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                        "Failed to parse parameter, key/value format expected.");

                /* Do not allow whitespace after the separator, as that's not a valid os-release format */
                operator = parse_compare_operator(&word, COMPARE_ALLOW_FNMATCH|COMPARE_EQUAL_BY_STRING);
                if (operator < 0 || isempty(word) || strchr(WHITESPACE, *word) != NULL)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                        "Failed to parse parameter, key/value format expected.");

                r = parse_os_release(NULL, key, &actual_value);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse os-release: %m");

                /* If not found, use "". This means that missing and empty assignments
                 * in the file have the same result. */
                r = version_or_fnmatch_compare(operator, strempty(actual_value), word);
                if (r < 0)
                        return r;
                if (!r)
                        return false;
        }

        return true;
}

static int condition_test_memory(Condition *c, char **env) {
        CompareOperator operator;
        uint64_t m, k;
        const char *p;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_MEMORY);

        m = physical_memory();

        p = c->parameter;
        operator = parse_compare_operator(&p, 0);
        if (operator < 0)
                operator = COMPARE_GREATER_OR_EQUAL; /* default to >= check, if nothing is specified. */

        r = parse_size(p, 1024, &k);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse size '%s': %m", p);

        return test_order(CMP(m, k), operator);
}

static int condition_test_cpus(Condition *c, char **env) {
        CompareOperator operator;
        const char *p;
        unsigned k;
        int r, n;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_CPUS);

        n = cpus_in_affinity_mask();
        if (n < 0)
                return log_debug_errno(n, "Failed to determine CPUs in affinity mask: %m");

        p = c->parameter;
        operator = parse_compare_operator(&p, 0);
        if (operator < 0)
                operator = COMPARE_GREATER_OR_EQUAL; /* default to >= check, if nothing is specified. */

        r = safe_atou(p, &k);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse number of CPUs: %m");

        return test_order(CMP((unsigned) n, k), operator);
}

static int condition_test_user(Condition *c, char **env) {
        uid_t id;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_USER);

        /* Do the quick&easy comparisons first, and only parse the UID later. */
        if (streq(c->parameter, "root"))
                return getuid() == 0 || geteuid() == 0;
        if (streq(c->parameter, NOBODY_USER_NAME))
                return getuid() == UID_NOBODY || geteuid() == UID_NOBODY;
        if (streq(c->parameter, "@system"))
                return uid_is_system(getuid()) || uid_is_system(geteuid());

        r = parse_uid(c->parameter, &id);
        if (r >= 0)
                return id == getuid() || id == geteuid();

        if (getpid_cached() == 1)  /* We already checked for "root" above, and we know that
                                    * PID 1 is running as root, hence we know it cannot match. */
                return false;

        /* getusername_malloc() may do an nss lookup, which is not allowed in PID 1. */
        _cleanup_free_ char *username = getusername_malloc();
        if (!username)
                return -ENOMEM;

        if (streq(username, c->parameter))
                return 1;

        const char *u = c->parameter;
        r = get_user_creds(&u, &id, NULL, NULL, NULL, USER_CREDS_ALLOW_MISSING);
        if (r < 0)
                return 0;

        return id == getuid() || id == geteuid();
}

static int condition_test_control_group_controller(Condition *c, char **env) {
        CGroupMask system_mask, wanted_mask;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_CONTROL_GROUP_CONTROLLER);

        if (streq(c->parameter, "v2"))
                return true;
        if (streq(c->parameter, "v1"))
                return false;

        r = cg_mask_supported(&system_mask);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine supported controllers: %m");

        r = cg_mask_from_string(c->parameter, &wanted_mask);
        if (r < 0 || wanted_mask <= 0) {
                /* This won't catch the case that we have an unknown controller
                 * mixed in with valid ones -- these are only assessed on the
                 * validity of the valid controllers found. */
                log_debug("Failed to parse cgroup string: %s", c->parameter);
                return true;
        }

        return FLAGS_SET(system_mask, wanted_mask);
}

static int condition_test_group(Condition *c, char **env) {
        gid_t id;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_GROUP);

        r = parse_gid(c->parameter, &id);
        if (r >= 0)
                return in_gid(id);

        /* Avoid any NSS lookups if we are PID1 */
        if (getpid_cached() == 1)
                return streq(c->parameter, "root");

        return in_group(c->parameter) > 0;
}

static int condition_test_virtualization(Condition *c, char **env) {
        Virtualization v;
        int b;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_VIRTUALIZATION);

        if (streq(c->parameter, "private-users"))
                return running_in_userns();

        v = detect_virtualization();
        if (v < 0)
                return v;

        /* First, compare with yes/no */
        b = parse_boolean(c->parameter);
        if (b >= 0)
                return b == (v != VIRTUALIZATION_NONE);

        /* Then, compare categorization */
        if (streq(c->parameter, "vm"))
                return VIRTUALIZATION_IS_VM(v);

        if (streq(c->parameter, "container"))
                return VIRTUALIZATION_IS_CONTAINER(v);

        /* Finally compare id */
        return v != VIRTUALIZATION_NONE && streq(c->parameter, virtualization_to_string(v));
}

static int condition_test_architecture(Condition *c, char **env) {
        Architecture a, b;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_ARCHITECTURE);

        a = uname_architecture();
        if (a < 0)
                return a;

        if (streq(c->parameter, "native"))
                b = native_architecture();
        else {
                b = architecture_from_string(c->parameter);
                if (b < 0) /* unknown architecture? Then it's definitely not ours */
                        return false;
        }

        return a == b;
}

#define DTCOMPAT_FILE "/proc/device-tree/compatible"
static int condition_test_firmware_devicetree_compatible(const char *dtcarg) {
        int r;
        _cleanup_free_ char *dtcompat = NULL;
        _cleanup_strv_free_ char **dtcompatlist = NULL;
        size_t size;

        r = read_full_virtual_file(DTCOMPAT_FILE, &dtcompat, &size);
        if (r < 0) {
                /* if the path doesn't exist it is incompatible */
                if (r != -ENOENT)
                        log_debug_errno(r, "Failed to open '%s', assuming machine is incompatible: %m", DTCOMPAT_FILE);
                return false;
        }

        /* Not sure this can happen, but play safe. */
        if (size == 0) {
                log_debug("%s has zero length, assuming machine is incompatible", DTCOMPAT_FILE);
                return false;
        }

         /* /proc/device-tree/compatible consists of one or more strings, each ending in '\0'.
          * So the last character in dtcompat must be a '\0'. */
        if (dtcompat[size - 1] != '\0') {
                log_debug("%s is in an unknown format, assuming machine is incompatible", DTCOMPAT_FILE);
                return false;
        }

        dtcompatlist = strv_parse_nulstr(dtcompat, size);
        if (!dtcompatlist)
                return -ENOMEM;

        return strv_contains(dtcompatlist, dtcarg);
}

static int condition_test_firmware_smbios_field(const char *expression) {
        _cleanup_free_ char *field = NULL, *expected_value = NULL, *actual_value = NULL;
        CompareOperator operator;
        int r;

        assert(expression);

        /* Parse SMBIOS field */
        r = extract_first_word(&expression, &field, COMPARE_OPERATOR_WITH_FNMATCH_CHARS, EXTRACT_RETAIN_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0 || isempty(expression))
                return -EINVAL;

        /* Remove trailing spaces from SMBIOS field */
        delete_trailing_chars(field, WHITESPACE);

        /* Parse operator */
        operator = parse_compare_operator(&expression, COMPARE_ALLOW_FNMATCH|COMPARE_EQUAL_BY_STRING);
        if (operator < 0)
                return operator;

        /* Parse expected value */
        r = extract_first_word(&expression, &expected_value, NULL, EXTRACT_UNQUOTE);
        if (r < 0)
                return r;
        if (r == 0 || !isempty(expression))
                return -EINVAL;

        /* Read actual value from sysfs */
        if (!filename_is_valid(field))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid SMBIOS field name.");

        const char *p = strjoina("/sys/class/dmi/id/", field);
        r = read_virtual_file(p, SIZE_MAX, &actual_value, NULL);
        if (r < 0) {
                log_debug_errno(r, "Failed to read %s: %m", p);
                if (r == -ENOENT)
                        return false;
                return r;
        }

        /* Remove trailing newline */
        delete_trailing_chars(actual_value, WHITESPACE);

        /* Finally compare actual and expected value */
        return version_or_fnmatch_compare(operator, actual_value, expected_value);
}

static int condition_test_firmware(Condition *c, char **env) {
        sd_char *arg;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_FIRMWARE);

        if (streq(c->parameter, "device-tree")) {
                if (access("/sys/firmware/devicetree/", F_OK) < 0) {
                        if (errno != ENOENT)
                                log_debug_errno(errno, "Unexpected error when checking for /sys/firmware/devicetree/: %m");
                        return false;
                } else
                        return true;
        } else if ((arg = startswith(c->parameter, "device-tree-compatible("))) {
                _cleanup_free_ char *dtc_arg = NULL;
                char *end;

                end = strrchr(arg, ')');
                if (!end || *(end + 1) != '\0') {
                        log_debug("Malformed ConditionFirmware=%s", c->parameter);
                        return false;
                }

                dtc_arg = strndup(arg, end - arg);
                if (!dtc_arg)
                        return -ENOMEM;

                return condition_test_firmware_devicetree_compatible(dtc_arg);
        } else if (streq(c->parameter, "uefi"))
                return is_efi_boot();
        else if ((arg = startswith(c->parameter, "smbios-field("))) {
                _cleanup_free_ char *smbios_arg = NULL;
                char *end;

                end = strrchr(arg, ')');
                if (!end || *(end + 1) != '\0')
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Malformed ConditionFirmware=%s.", c->parameter);

                smbios_arg = strndup(arg, end - arg);
                if (!smbios_arg)
                        return log_oom_debug();

                r = condition_test_firmware_smbios_field(smbios_arg);
                if (r < 0)
                        return log_debug_errno(r, "Malformed ConditionFirmware=%s: %m", c->parameter);
                return r;
        } else {
                log_debug("Unsupported Firmware condition \"%s\"", c->parameter);
                return false;
        }
}

static int condition_test_host(Condition *c, char **env) {
        _cleanup_free_ char *h = NULL;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_HOST);

        sd_id128_t x;
        if (sd_id128_from_string(c->parameter, &x) >= 0) {
                static const struct {
                        const char *name;
                        int (*get_id)(sd_id128_t *ret);
                } table[] = {
                        { "machine ID",   sd_id128_get_machine },
                        { "boot ID",      sd_id128_get_boot    },
                        { "product UUID", id128_get_product    },
                };

                /* If this is a UUID, check if this matches the machine ID, boot ID or product UUID */
                FOREACH_ELEMENT(i, table) {
                        sd_id128_t y;

                        r = i->get_id(&y);
                        if (r < 0)
                                log_debug_errno(r, "Failed to get %s, ignoring: %m", i->name);
                        else if (sd_id128_equal(x, y))
                                return true;
                }

                /* Fall through, also allow setups where people set hostnames to UUIDs. Kinda weird, but no
                 * reason not to allow that */
        }

        h = gethostname_malloc();
        if (!h)
                return -ENOMEM;

        r = fnmatch(c->parameter, h, FNM_CASEFOLD);
        if (r == FNM_NOMATCH)
                return false;
        if (r != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "fnmatch() failed.");

        return true;
}

static int condition_test_ac_power(Condition *c, char **env) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_AC_POWER);

        r = parse_boolean(c->parameter);
        if (r < 0)
                return r;

        return (on_ac_power() != 0) == !!r;
}

static int has_tpm2(void) {
        /* Checks whether the kernel has the TPM subsystem enabled and the firmware reports support. Note
         * we don't check for actual TPM devices, since we might not have loaded the driver for it yet, i.e.
         * during early boot where we very likely want to use this condition check).
         *
         * Note that we don't check if we ourselves are built with TPM2 support here! */

        return FLAGS_SET(tpm2_support_full(TPM2_SUPPORT_SUBSYSTEM|TPM2_SUPPORT_FIRMWARE), TPM2_SUPPORT_SUBSYSTEM|TPM2_SUPPORT_FIRMWARE);
}

static int condition_test_security(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_SECURITY);

        if (streq(c->parameter, "selinux"))
                return mac_selinux_use();
        if (streq(c->parameter, "smack"))
                return mac_smack_use();
        if (streq(c->parameter, "apparmor"))
                return mac_apparmor_use();
        if (streq(c->parameter, "audit"))
                return use_audit();
        if (streq(c->parameter, "ima"))
                return use_ima();
        if (streq(c->parameter, "tomoyo"))
                return mac_tomoyo_use();
        if (streq(c->parameter, "uefi-secureboot"))
                return is_efi_secure_boot();
        if (streq(c->parameter, "tpm2"))
                return has_tpm2();
        if (streq(c->parameter, "cvm"))
                return detect_confidential_virtualization() > 0;
        if (streq(c->parameter, "measured-uki"))
                return efi_measured_uki(LOG_DEBUG);

        return false;
}

static int condition_test_capability(Condition *c, char **env) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_CAPABILITY);

        /* If it's an invalid capability, we don't have it */
        int value = capability_from_name(c->parameter);
        if (value < 0)
                return -EINVAL;

        CapabilityQuintet q;
        r = pidref_get_capability(&PIDREF_MAKE_FROM_PID(getpid_cached()), &q);
        if (r < 0)
                return r;

        return BIT_SET(q.bounding, value);
}

static int condition_test_needs_update(Condition *c, char **env) {
        struct stat usr, other;
        const char *p;
        bool b;
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_NEEDS_UPDATE);

        r = proc_cmdline_get_bool("systemd.condition_needs_update", /* flags = */ 0, &b);
        if (r < 0)
                log_debug_errno(r, "Failed to parse systemd.condition_needs_update= kernel command line argument, ignoring: %m");
        if (r > 0)
                return b;

        if (in_initrd()) {
                log_debug("We are in an initrd, not doing any updates.");
                return false;
        }

        if (!path_is_absolute(c->parameter)) {
                log_debug("Specified condition parameter '%s' is not absolute, assuming an update is needed.", c->parameter);
                return true;
        }

        /* If the file system is read-only we shouldn't suggest an update */
        r = path_is_read_only_fs(c->parameter);
        if (r < 0)
                log_debug_errno(r, "Failed to determine if '%s' is read-only, ignoring: %m", c->parameter);
        if (r > 0)
                return false;

        /* Any other failure means we should allow the condition to be true, so that we rather invoke too
         * many update tools than too few. */

        p = strjoina(c->parameter, "/.updated");
        if (lstat(p, &other) < 0) {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to stat() '%s', assuming an update is needed: %m", p);
                return true;
        }

        if (lstat("/usr/", &usr) < 0) {
                log_debug_errno(errno, "Failed to stat() /usr/, assuming an update is needed: %m");
                return true;
        }

        /*
         * First, compare seconds as they are always accurate...
         */
        if (usr.st_mtim.tv_sec != other.st_mtim.tv_sec)
                return usr.st_mtim.tv_sec > other.st_mtim.tv_sec;

        /*
         * ...then compare nanoseconds.
         *
         * A false positive is only possible when /usr's nanoseconds > 0
         * (otherwise /usr cannot be strictly newer than the target file)
         * AND the target file's nanoseconds == 0
         * (otherwise the filesystem supports nsec timestamps, see stat(2)).
         */
        if (usr.st_mtim.tv_nsec == 0 || other.st_mtim.tv_nsec > 0)
                return usr.st_mtim.tv_nsec > other.st_mtim.tv_nsec;

        _cleanup_free_ char *timestamp_str = NULL;
        r = parse_env_file(NULL, p, "TIMESTAMP_NSEC", &timestamp_str);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse timestamp file '%s', using mtime: %m", p);
                return true;
        }
        if (isempty(timestamp_str)) {
                log_debug("No data in timestamp file '%s', using mtime.", p);
                return true;
        }

        uint64_t timestamp;
        r = safe_atou64(timestamp_str, &timestamp);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse timestamp value '%s' in file '%s', using mtime: %m", timestamp_str, p);
                return true;
        }

        return timespec_load_nsec(&usr.st_mtim) > timestamp;
}

static bool in_first_boot(void) {
        static int first_boot = -1;
        int r;

        if (first_boot >= 0)
                return first_boot;

        const char *e = secure_getenv("SYSTEMD_FIRST_BOOT");
        if (e) {
                r = parse_boolean(e);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse $SYSTEMD_FIRST_BOOT, ignoring: %m");
                else
                        return (first_boot = r);
        }

        r = RET_NERRNO(access("/run/systemd/first-boot", F_OK));
        if (r < 0 && r != -ENOENT)
                log_debug_errno(r, "Failed to check if /run/systemd/first-boot exists, assuming no: %m");
        return r >= 0;
}

static int condition_test_first_boot(Condition *c, char **env) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_FIRST_BOOT);

        // TODO: Parse c->parameter immediately when reading the config.
        //       Apply negation when parsing too.

        r = parse_boolean(c->parameter);
        if (r < 0)
                return r;

        return in_first_boot() == r;
}

static int condition_test_environment(Condition *c, char **env) {
        bool equal;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_ENVIRONMENT);

        equal = strchr(c->parameter, '=');

        STRV_FOREACH(i, env) {
                bool found;

                if (equal)
                        found = streq(c->parameter, *i);
                else {
                        const char *f;

                        f = startswith(*i, c->parameter);
                        found = f && IN_SET(*f, 0, '=');
                }

                if (found)
                        return true;
        }

        return false;
}

static int condition_test_path_exists(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_EXISTS);

        return access(c->parameter, F_OK) >= 0;
}

static int condition_test_path_exists_glob(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_EXISTS_GLOB);

        return glob_exists(c->parameter) > 0;
}

static int condition_test_path_is_directory(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_IS_DIRECTORY);

        return is_dir(c->parameter, true) > 0;
}

static int condition_test_path_is_symbolic_link(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_IS_SYMBOLIC_LINK);

        return is_symlink(c->parameter) > 0;
}

static int condition_test_path_is_mount_point(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_IS_MOUNT_POINT);

        return path_is_mount_point_full(c->parameter, /* root = */ NULL, AT_SYMLINK_FOLLOW) > 0;
}

static int condition_test_path_is_read_write(Condition *c, char **env) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_IS_READ_WRITE);

        r = path_is_read_only_fs(c->parameter);

        return r <= 0 && r != -ENOENT;
}

static int condition_test_cpufeature(Condition *c, char **env) {
        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_CPU_FEATURE);

        return has_cpu_with_flag(ascii_strlower(c->parameter));
}

static int condition_test_path_is_encrypted(Condition *c, char **env) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_PATH_IS_ENCRYPTED);

        r = path_is_encrypted(c->parameter);
        if (r < 0 && r != -ENOENT)
                log_debug_errno(r, "Failed to determine if '%s' is encrypted: %m", c->parameter);

        return r > 0;
}

static int condition_test_directory_not_empty(Condition *c, char **env) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_DIRECTORY_NOT_EMPTY);

        r = dir_is_empty(c->parameter, /* ignore_hidden_or_backup= */ true);
        return r <= 0 && !IN_SET(r, -ENOENT, -ENOTDIR);
}

static int condition_test_file_not_empty(Condition *c, char **env) {
        struct stat st;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_FILE_NOT_EMPTY);

        return (stat(c->parameter, &st) >= 0 &&
                S_ISREG(st.st_mode) &&
                st.st_size > 0);
}

static int condition_test_file_is_executable(Condition *c, char **env) {
        struct stat st;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_FILE_IS_EXECUTABLE);

        return (stat(c->parameter, &st) >= 0 &&
                S_ISREG(st.st_mode) &&
                (st.st_mode & 0111));
}

static int condition_test_psi(Condition *c, char **env) {
        _cleanup_free_ char *first = NULL, *second = NULL, *third = NULL, *fourth = NULL, *pressure_path = NULL;
        const char *p, *value, *pressure_type;
        loadavg_t *current, limit;
        ResourcePressure pressure;
        PressureType preferred_pressure_type = PRESSURE_TYPE_FULL;
        int r;

        assert(c);
        assert(c->parameter);
        assert(IN_SET(c->type, CONDITION_MEMORY_PRESSURE, CONDITION_CPU_PRESSURE, CONDITION_IO_PRESSURE));

        if (!is_pressure_supported()) {
                log_debug("Pressure Stall Information (PSI) is not supported, skipping.");
                return 1;
        }

        pressure_type = c->type == CONDITION_MEMORY_PRESSURE ? "memory" :
                        c->type == CONDITION_CPU_PRESSURE ? "cpu" :
                        "io";

        p = c->parameter;
        r = extract_many_words(&p, ":", 0, &first, &second);
        if (r <= 0)
                return log_debug_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL), "Failed to parse condition parameter %s: %m", c->parameter);
        /* If only one parameter is passed, then we look at the global system pressure rather than a specific cgroup. */
        if (r == 1) {
                /* cpu.pressure 'full' is reported but undefined at system level */
                if (c->type == CONDITION_CPU_PRESSURE)
                        preferred_pressure_type = PRESSURE_TYPE_SOME;

                pressure_path = path_join("/proc/pressure", pressure_type);
                if (!pressure_path)
                        return log_oom_debug();

                value = first;
        } else {
                const char *controller = strjoina(pressure_type, ".pressure");
                _cleanup_free_ char *slice_path = NULL, *root_scope = NULL;
                CGroupMask mask, required_mask;
                char *slice, *e;

                required_mask = c->type == CONDITION_MEMORY_PRESSURE ? CGROUP_MASK_MEMORY :
                                c->type == CONDITION_CPU_PRESSURE ? CGROUP_MASK_CPU :
                                CGROUP_MASK_IO;

                slice = strstrip(first);
                if (!slice)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse condition parameter %s.", c->parameter);

                r = cg_mask_supported(&mask);
                if (r < 0)
                        return log_debug_errno(r, "Failed to get supported cgroup controllers: %m");

                if (!FLAGS_SET(mask, required_mask)) {
                        log_debug("Cgroup %s controller not available, skipping PSI condition check.", pressure_type);
                        return 1;
                }

                r = cg_slice_to_path(slice, &slice_path);
                if (r < 0)
                        return log_debug_errno(r, "Cannot determine slice \"%s\" cgroup path: %m", slice);

                /* We might be running under the user manager, so get the root path and prefix it accordingly. */
                r = cg_pid_get_path(getpid_cached(), &root_scope);
                if (r < 0)
                        return log_debug_errno(r, "Failed to get root cgroup path: %m");

                /* Drop init.scope, we want the parent. We could get an empty or / path, but that's fine,
                 * just skip it in that case. */
                e = endswith(root_scope, "/" SPECIAL_INIT_SCOPE);
                if (e)
                        *e = 0;
                if (!empty_or_root(root_scope)) {
                        _cleanup_free_ char *slice_joined = NULL;

                        slice_joined = path_join(root_scope, slice_path);
                        if (!slice_joined)
                                return log_oom_debug();

                        free_and_replace(slice_path, slice_joined);
                }

                r = cg_get_path(slice_path, controller, &pressure_path);
                if (r < 0)
                        return log_debug_errno(r, "Error getting cgroup pressure path from %s: %m", slice_path);

                value = second;
        }

        /* If a value including a specific timespan (in the intervals allowed by the kernel),
         * parse it, otherwise we assume just a plain percentage that will be checked if it is
         * smaller or equal to the current pressure average over 5 minutes. */
        r = extract_many_words(&value, "/", 0, &third, &fourth);
        if (r <= 0)
                return log_debug_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL), "Failed to parse condition parameter %s: %m", c->parameter);
        if (r == 1)
                current = &pressure.avg300;
        else {
                const char *timespan;

                timespan = skip_leading_chars(fourth, NULL);
                if (!timespan)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse condition parameter %s.", c->parameter);

                if (startswith(timespan, "10sec"))
                        current = &pressure.avg10;
                else if (startswith(timespan, "1min"))
                        current = &pressure.avg60;
                else if (startswith(timespan, "5min"))
                        current = &pressure.avg300;
                else
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse condition parameter %s.", c->parameter);
        }

        value = strstrip(third);
        if (!value)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse condition parameter %s.", c->parameter);

        r = parse_permyriad(value);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse permyriad: %s", c->parameter);

        r = store_loadavg_fixed_point(r / 100LU, r % 100LU, &limit);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse loadavg: %s", c->parameter);

        r = read_resource_pressure(pressure_path, preferred_pressure_type, &pressure);
        /* cpu.pressure 'full' was recently added at cgroup level, fall back to 'some' */
        if (r == -ENODATA && preferred_pressure_type == PRESSURE_TYPE_FULL)
                r = read_resource_pressure(pressure_path, PRESSURE_TYPE_SOME, &pressure);
        if (r == -ENOENT) {
                /* We already checked that /proc/pressure exists, so this means we were given a cgroup
                 * that doesn't exist or doesn't exist any longer. */
                log_debug("\"%s\" not found, skipping PSI check.", pressure_path);
                return 1;
        }
        if (r < 0)
                return log_debug_errno(r, "Error parsing pressure from %s: %m", pressure_path);

        return *current <= limit;
}

static int condition_test_kernel_module_loaded(Condition *c, char **env) {
        int r;

        assert(c);
        assert(c->parameter);
        assert(c->type == CONDITION_KERNEL_MODULE_LOADED);

        /* Checks whether a specific kernel module is fully loaded (i.e. with the full initialization routine
         * complete). */

        _cleanup_free_ char *normalized = strreplace(c->parameter, "-", "_");
        if (!normalized)
                return log_oom_debug();

        if (!filename_is_valid(normalized)) {
                log_debug("Kernel module name '%s' is not valid, hence reporting it to not be loaded.", normalized);
                return false;
        }

        _cleanup_free_ char *p = path_join("/sys/module/", normalized);
        if (!p)
                return log_oom_debug();

        _cleanup_close_ int dir_fd = open(p, O_PATH|O_DIRECTORY|O_CLOEXEC);
        if (dir_fd < 0) {
                if (errno == ENOENT) {
                        log_debug_errno(errno, "'%s/' does not exist, kernel module '%s' not loaded.", p, normalized);
                        return false;
                }

                return log_debug_errno(errno, "Failed to open directory '%s/': %m", p);
        }

        _cleanup_free_ char *initstate = NULL;
        r = read_virtual_file_at(dir_fd, "initstate", SIZE_MAX, &initstate, NULL);
        if (r == -ENOENT) {
                log_debug_errno(r, "'%s/' exists but '%s/initstate' does not, kernel module '%s' is built-in, hence loaded.", p, p, normalized);
                return true;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to open '%s/initstate': %m", p);

        delete_trailing_chars(initstate, WHITESPACE);

        if (!streq(initstate, "live")) {
                log_debug("Kernel module '%s' is reported as '%s', hence not loaded.", normalized, initstate);
                return false;
        }

        log_debug("Kernel module '%s' detected as loaded.", normalized);
        return true;
}

int condition_test(Condition *c, char **env) {

        static int (*const condition_tests[_CONDITION_TYPE_MAX])(Condition *c, char **env) = {
                [CONDITION_PATH_EXISTS]              = condition_test_path_exists,
                [CONDITION_PATH_EXISTS_GLOB]         = condition_test_path_exists_glob,
                [CONDITION_PATH_IS_DIRECTORY]        = condition_test_path_is_directory,
                [CONDITION_PATH_IS_SYMBOLIC_LINK]    = condition_test_path_is_symbolic_link,
                [CONDITION_PATH_IS_MOUNT_POINT]      = condition_test_path_is_mount_point,
                [CONDITION_PATH_IS_READ_WRITE]       = condition_test_path_is_read_write,
                [CONDITION_PATH_IS_ENCRYPTED]        = condition_test_path_is_encrypted,
                [CONDITION_DIRECTORY_NOT_EMPTY]      = condition_test_directory_not_empty,
                [CONDITION_FILE_NOT_EMPTY]           = condition_test_file_not_empty,
                [CONDITION_FILE_IS_EXECUTABLE]       = condition_test_file_is_executable,
                [CONDITION_KERNEL_COMMAND_LINE]      = condition_test_kernel_command_line,
                [CONDITION_VERSION]                  = condition_test_version,
                [CONDITION_CREDENTIAL]               = condition_test_credential,
                [CONDITION_VIRTUALIZATION]           = condition_test_virtualization,
                [CONDITION_SECURITY]                 = condition_test_security,
                [CONDITION_CAPABILITY]               = condition_test_capability,
                [CONDITION_HOST]                     = condition_test_host,
                [CONDITION_AC_POWER]                 = condition_test_ac_power,
                [CONDITION_ARCHITECTURE]             = condition_test_architecture,
                [CONDITION_FIRMWARE]                 = condition_test_firmware,
                [CONDITION_NEEDS_UPDATE]             = condition_test_needs_update,
                [CONDITION_FIRST_BOOT]               = condition_test_first_boot,
                [CONDITION_USER]                     = condition_test_user,
                [CONDITION_GROUP]                    = condition_test_group,
                [CONDITION_CONTROL_GROUP_CONTROLLER] = condition_test_control_group_controller,
                [CONDITION_CPUS]                     = condition_test_cpus,
                [CONDITION_MEMORY]                   = condition_test_memory,
                [CONDITION_ENVIRONMENT]              = condition_test_environment,
                [CONDITION_CPU_FEATURE]              = condition_test_cpufeature,
                [CONDITION_OS_RELEASE]               = condition_test_osrelease,
                [CONDITION_MEMORY_PRESSURE]          = condition_test_psi,
                [CONDITION_CPU_PRESSURE]             = condition_test_psi,
                [CONDITION_IO_PRESSURE]              = condition_test_psi,
                [CONDITION_KERNEL_MODULE_LOADED]     = condition_test_kernel_module_loaded,
        };

        int r, b;

        assert(c);
        assert(c->type >= 0);
        assert(c->type < _CONDITION_TYPE_MAX);

        r = condition_tests[c->type](c, env);
        if (r < 0) {
                c->result = CONDITION_ERROR;
                return r;
        }

        b = (r > 0) == !c->negate;
        c->result = b ? CONDITION_SUCCEEDED : CONDITION_FAILED;
        return b;
}

bool condition_test_list(
                Condition *first,
                char **env,
                condition_to_string_t to_string,
                condition_test_logger_t logger,
                void *userdata) {

        int triggered = -1;

        /* If the condition list is empty, then it is true */
        if (!first)
                return true;

        /* Otherwise, if all of the non-trigger conditions apply and
         * if any of the trigger conditions apply (unless there are
         * none) we return true */
        LIST_FOREACH(conditions, c, first) {
                int r;

                r = condition_test(c, env);

                if (logger) {
                        if (r < 0)
                                logger(userdata, LOG_WARNING, r, PROJECT_FILE, __LINE__, __func__,
                                       "Couldn't determine result for %s=%s%s%s, assuming failed: %m",
                                       to_string(c->type),
                                       c->trigger ? "|" : "",
                                       c->negate ? "!" : "",
                                       c->parameter);
                        else
                                logger(userdata, LOG_DEBUG, 0, PROJECT_FILE, __LINE__, __func__,
                                       "%s=%s%s%s %s.",
                                       to_string(c->type),
                                       c->trigger ? "|" : "",
                                       c->negate ? "!" : "",
                                       c->parameter,
                                       condition_result_to_string(c->result));
                }

                if (!c->trigger && r <= 0)
                        return false;

                if (c->trigger && triggered <= 0)
                        triggered = r > 0;
        }

        return triggered != 0;
}

void condition_dump(Condition *c, FILE *f, const char *prefix, condition_to_string_t to_string) {
        assert(c);
        assert(f);
        assert(to_string);

        prefix = strempty(prefix);

        fprintf(f,
                "%s\t%s: %s%s%s %s\n",
                prefix,
                to_string(c->type),
                c->trigger ? "|" : "",
                c->negate ? "!" : "",
                c->parameter,
                condition_result_to_string(c->result));
}

void condition_dump_list(Condition *first, FILE *f, const char *prefix, condition_to_string_t to_string) {
        LIST_FOREACH(conditions, c, first)
                condition_dump(c, f, prefix, to_string);
}

static const char* const _condition_type_table[_CONDITION_TYPE_MAX] = {
        [CONDITION_ARCHITECTURE]             = "ConditionArchitecture",
        [CONDITION_FIRMWARE]                 = "ConditionFirmware",
        [CONDITION_VIRTUALIZATION]           = "ConditionVirtualization",
        [CONDITION_HOST]                     = "ConditionHost",
        [CONDITION_KERNEL_COMMAND_LINE]      = "ConditionKernelCommandLine",
        [CONDITION_VERSION]                  = "ConditionVersion",
        [CONDITION_CREDENTIAL]               = "ConditionCredential",
        [CONDITION_SECURITY]                 = "ConditionSecurity",
        [CONDITION_CAPABILITY]               = "ConditionCapability",
        [CONDITION_AC_POWER]                 = "ConditionACPower",
        [CONDITION_NEEDS_UPDATE]             = "ConditionNeedsUpdate",
        [CONDITION_FIRST_BOOT]               = "ConditionFirstBoot",
        [CONDITION_PATH_EXISTS]              = "ConditionPathExists",
        [CONDITION_PATH_EXISTS_GLOB]         = "ConditionPathExistsGlob",
        [CONDITION_PATH_IS_DIRECTORY]        = "ConditionPathIsDirectory",
        [CONDITION_PATH_IS_SYMBOLIC_LINK]    = "ConditionPathIsSymbolicLink",
        [CONDITION_PATH_IS_MOUNT_POINT]      = "ConditionPathIsMountPoint",
        [CONDITION_PATH_IS_READ_WRITE]       = "ConditionPathIsReadWrite",
        [CONDITION_PATH_IS_ENCRYPTED]        = "ConditionPathIsEncrypted",
        [CONDITION_DIRECTORY_NOT_EMPTY]      = "ConditionDirectoryNotEmpty",
        [CONDITION_FILE_NOT_EMPTY]           = "ConditionFileNotEmpty",
        [CONDITION_FILE_IS_EXECUTABLE]       = "ConditionFileIsExecutable",
        [CONDITION_USER]                     = "ConditionUser",
        [CONDITION_GROUP]                    = "ConditionGroup",
        [CONDITION_CONTROL_GROUP_CONTROLLER] = "ConditionControlGroupController",
        [CONDITION_CPUS]                     = "ConditionCPUs",
        [CONDITION_MEMORY]                   = "ConditionMemory",
        [CONDITION_ENVIRONMENT]              = "ConditionEnvironment",
        [CONDITION_CPU_FEATURE]              = "ConditionCPUFeature",
        [CONDITION_OS_RELEASE]               = "ConditionOSRelease",
        [CONDITION_MEMORY_PRESSURE]          = "ConditionMemoryPressure",
        [CONDITION_CPU_PRESSURE]             = "ConditionCPUPressure",
        [CONDITION_IO_PRESSURE]              = "ConditionIOPressure",
        [CONDITION_KERNEL_MODULE_LOADED]     = "ConditionKernelModuleLoaded",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(_condition_type, ConditionType);

const char* condition_type_to_string(ConditionType t) {
        return _condition_type_to_string(t);
}

ConditionType condition_type_from_string(const char *s) {
        /* for backward compatibility */
        if (streq_ptr(s, "ConditionKernelVersion"))
                return CONDITION_VERSION;

        return _condition_type_from_string(s);
}

void condition_types_list(void) {
        DUMP_STRING_TABLE(_condition_type, ConditionType, _CONDITION_TYPE_MAX);
}

static const char* const _assert_type_table[_CONDITION_TYPE_MAX] = {
        [CONDITION_ARCHITECTURE]             = "AssertArchitecture",
        [CONDITION_FIRMWARE]                 = "AssertFirmware",
        [CONDITION_VIRTUALIZATION]           = "AssertVirtualization",
        [CONDITION_HOST]                     = "AssertHost",
        [CONDITION_KERNEL_COMMAND_LINE]      = "AssertKernelCommandLine",
        [CONDITION_VERSION]                  = "AssertVersion",
        [CONDITION_CREDENTIAL]               = "AssertCredential",
        [CONDITION_SECURITY]                 = "AssertSecurity",
        [CONDITION_CAPABILITY]               = "AssertCapability",
        [CONDITION_AC_POWER]                 = "AssertACPower",
        [CONDITION_NEEDS_UPDATE]             = "AssertNeedsUpdate",
        [CONDITION_FIRST_BOOT]               = "AssertFirstBoot",
        [CONDITION_PATH_EXISTS]              = "AssertPathExists",
        [CONDITION_PATH_EXISTS_GLOB]         = "AssertPathExistsGlob",
        [CONDITION_PATH_IS_DIRECTORY]        = "AssertPathIsDirectory",
        [CONDITION_PATH_IS_SYMBOLIC_LINK]    = "AssertPathIsSymbolicLink",
        [CONDITION_PATH_IS_MOUNT_POINT]      = "AssertPathIsMountPoint",
        [CONDITION_PATH_IS_READ_WRITE]       = "AssertPathIsReadWrite",
        [CONDITION_PATH_IS_ENCRYPTED]        = "AssertPathIsEncrypted",
        [CONDITION_DIRECTORY_NOT_EMPTY]      = "AssertDirectoryNotEmpty",
        [CONDITION_FILE_NOT_EMPTY]           = "AssertFileNotEmpty",
        [CONDITION_FILE_IS_EXECUTABLE]       = "AssertFileIsExecutable",
        [CONDITION_USER]                     = "AssertUser",
        [CONDITION_GROUP]                    = "AssertGroup",
        [CONDITION_CONTROL_GROUP_CONTROLLER] = "AssertControlGroupController",
        [CONDITION_CPUS]                     = "AssertCPUs",
        [CONDITION_MEMORY]                   = "AssertMemory",
        [CONDITION_ENVIRONMENT]              = "AssertEnvironment",
        [CONDITION_CPU_FEATURE]              = "AssertCPUFeature",
        [CONDITION_OS_RELEASE]               = "AssertOSRelease",
        [CONDITION_MEMORY_PRESSURE]          = "AssertMemoryPressure",
        [CONDITION_CPU_PRESSURE]             = "AssertCPUPressure",
        [CONDITION_IO_PRESSURE]              = "AssertIOPressure",
        [CONDITION_KERNEL_MODULE_LOADED]     = "AssertKernelModuleLoaded",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(_assert_type, ConditionType);

const char* assert_type_to_string(ConditionType t) {
        return _assert_type_to_string(t);
}

ConditionType assert_type_from_string(const char *s) {
        /* for backward compatibility */
        if (streq_ptr(s, "AssertKernelVersion"))
                return CONDITION_VERSION;

        return _assert_type_from_string(s);
}

void assert_types_list(void) {
        DUMP_STRING_TABLE(_assert_type, ConditionType, _CONDITION_TYPE_MAX);
}

static const char* const condition_result_table[_CONDITION_RESULT_MAX] = {
        [CONDITION_UNTESTED]  = "untested",
        [CONDITION_SUCCEEDED] = "succeeded",
        [CONDITION_FAILED]    = "failed",
        [CONDITION_ERROR]     = "error",
};

DEFINE_STRING_TABLE_LOOKUP(condition_result, ConditionResult);
