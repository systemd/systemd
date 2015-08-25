/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/prctl.h>

#ifdef HAVE_SECCOMP
#include <seccomp.h>
#endif

#include "bus-util.h"
#include "missing.h"
#include "ioprio.h"
#include "strv.h"
#include "fileio.h"
#include "execute.h"
#include "capability.h"
#include "env-util.h"
#include "af-list.h"
#include "namespace.h"
#include "path-util.h"
#include "dbus-execute.h"

#ifdef HAVE_SECCOMP
#include "seccomp-util.h"
#endif

BUS_DEFINE_PROPERTY_GET_ENUM(bus_property_get_exec_output, exec_output, ExecOutput);

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_exec_input, exec_input, ExecInput);

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_exec_utmp_mode, exec_utmp_mode, ExecUtmpMode);

static BUS_DEFINE_PROPERTY_GET_ENUM(bus_property_get_protect_home, protect_home, ProtectHome);
static BUS_DEFINE_PROPERTY_GET_ENUM(bus_property_get_protect_system, protect_system, ProtectSystem);

static int property_get_environment_files(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;
        char **j;
        int r;

        assert(bus);
        assert(reply);
        assert(c);

        r = sd_bus_message_open_container(reply, 'a', "(sb)");
        if (r < 0)
                return r;

        STRV_FOREACH(j, c->environment_files) {
                const char *fn = *j;

                r = sd_bus_message_append(reply, "(sb)", fn[0] == '-' ? fn + 1 : fn, fn[0] == '-');
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

static int property_get_rlimit(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        struct rlimit *rl;
        uint64_t u;
        rlim_t x;

        assert(bus);
        assert(reply);
        assert(userdata);

        rl = *(struct rlimit**) userdata;
        if (rl)
                x = rl->rlim_max;
        else {
                struct rlimit buf = {};
                int z;

                z = rlimit_from_string(property);
                assert(z >= 0);

                getrlimit(z, &buf);
                x = buf.rlim_max;
        }

        /* rlim_t might have different sizes, let's map
         * RLIMIT_INFINITY to (uint64_t) -1, so that it is the same on
         * all archs */
        u = x == RLIM_INFINITY ? (uint64_t) -1 : (uint64_t) x;

        return sd_bus_message_append(reply, "t", u);
}

static int property_get_oom_score_adjust(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {


        ExecContext *c = userdata;
        int32_t n;

        assert(bus);
        assert(reply);
        assert(c);

        if (c->oom_score_adjust_set)
                n = c->oom_score_adjust;
        else {
                _cleanup_free_ char *t = NULL;

                n = 0;
                if (read_one_line_file("/proc/self/oom_score_adj", &t) >= 0)
                        safe_atoi(t, &n);
        }

        return sd_bus_message_append(reply, "i", n);
}

static int property_get_nice(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {


        ExecContext *c = userdata;
        int32_t n;

        assert(bus);
        assert(reply);
        assert(c);

        if (c->nice_set)
                n = c->nice;
        else {
                errno = 0;
                n = getpriority(PRIO_PROCESS, 0);
                if (errno != 0)
                        n = 0;
        }

        return sd_bus_message_append(reply, "i", n);
}

static int property_get_ioprio(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {


        ExecContext *c = userdata;
        int32_t n;

        assert(bus);
        assert(reply);
        assert(c);

        if (c->ioprio_set)
                n = c->ioprio;
        else {
                n = ioprio_get(IOPRIO_WHO_PROCESS, 0);
                if (n < 0)
                        n = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 4);
        }

        return sd_bus_message_append(reply, "i", n);
}

static int property_get_cpu_sched_policy(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;
        int32_t n;

        assert(bus);
        assert(reply);
        assert(c);

        if (c->cpu_sched_set)
                n = c->cpu_sched_policy;
        else {
                n = sched_getscheduler(0);
                if (n < 0)
                        n = SCHED_OTHER;
        }

        return sd_bus_message_append(reply, "i", n);
}

static int property_get_cpu_sched_priority(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;
        int32_t n;

        assert(bus);
        assert(reply);
        assert(c);

        if (c->cpu_sched_set)
                n = c->cpu_sched_priority;
        else {
                struct sched_param p = {};

                if (sched_getparam(0, &p) >= 0)
                        n = p.sched_priority;
                else
                        n = 0;
        }

        return sd_bus_message_append(reply, "i", n);
}

static int property_get_cpu_affinity(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;

        assert(bus);
        assert(reply);
        assert(c);

        if (c->cpuset)
                return sd_bus_message_append_array(reply, 'y', c->cpuset, CPU_ALLOC_SIZE(c->cpuset_ncpus));
        else
                return sd_bus_message_append_array(reply, 'y', NULL, 0);
}

static int property_get_timer_slack_nsec(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;
        uint64_t u;

        assert(bus);
        assert(reply);
        assert(c);

        if (c->timer_slack_nsec != NSEC_INFINITY)
                u = (uint64_t) c->timer_slack_nsec;
        else
                u = (uint64_t) prctl(PR_GET_TIMERSLACK);

        return sd_bus_message_append(reply, "t", u);
}

static int property_get_capability_bounding_set(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;

        assert(bus);
        assert(reply);
        assert(c);

        /* We store this negated internally, to match the kernel, but
         * we expose it normalized. */
        return sd_bus_message_append(reply, "t", ~c->capability_bounding_set_drop);
}

static int property_get_capabilities(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;
        _cleanup_cap_free_charp_ char *t = NULL;
        const char *s;

        assert(bus);
        assert(reply);
        assert(c);

        if (c->capabilities)
                s = t = cap_to_text(c->capabilities, NULL);
        else
                s = "";

        if (!s)
                return -ENOMEM;

        return sd_bus_message_append(reply, "s", s);
}

static int property_get_syscall_filter(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;
        _cleanup_strv_free_ char **l = NULL;
        int r;

#ifdef HAVE_SECCOMP
        Iterator i;
        void *id;
#endif

        assert(bus);
        assert(reply);
        assert(c);

        r = sd_bus_message_open_container(reply, 'r', "bas");
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "b", c->syscall_whitelist);
        if (r < 0)
                return r;

#ifdef HAVE_SECCOMP
        SET_FOREACH(id, c->syscall_filter, i) {
                char *name;

                name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, PTR_TO_INT(id) - 1);
                if (!name)
                        continue;

                r = strv_consume(&l, name);
                if (r < 0)
                        return r;
        }
#endif

        strv_sort(l);

        r = sd_bus_message_append_strv(reply, l);
        if (r < 0)
                return r;

        return sd_bus_message_close_container(reply);
}

static int property_get_syscall_archs(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;
        _cleanup_strv_free_ char **l = NULL;
        int r;

#ifdef HAVE_SECCOMP
        Iterator i;
        void *id;
#endif

        assert(bus);
        assert(reply);
        assert(c);

#ifdef HAVE_SECCOMP
        SET_FOREACH(id, c->syscall_archs, i) {
                const char *name;

                name = seccomp_arch_to_string(PTR_TO_UINT32(id) - 1);
                if (!name)
                        continue;

                r = strv_extend(&l, name);
                if (r < 0)
                        return -ENOMEM;
        }
#endif

        strv_sort(l);

        r = sd_bus_message_append_strv(reply, l);
        if (r < 0)
                return r;

        return 0;
}

static int property_get_syscall_errno(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;

        assert(bus);
        assert(reply);
        assert(c);

        return sd_bus_message_append(reply, "i", (int32_t) c->syscall_errno);
}

static int property_get_selinux_context(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;

        assert(bus);
        assert(reply);
        assert(c);

        return sd_bus_message_append(reply, "(bs)", c->selinux_context_ignore, c->selinux_context);
}

static int property_get_apparmor_profile(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;

        assert(bus);
        assert(reply);
        assert(c);

        return sd_bus_message_append(reply, "(bs)", c->apparmor_profile_ignore, c->apparmor_profile);
}

static int property_get_smack_process_label(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;

        assert(bus);
        assert(reply);
        assert(c);

        return sd_bus_message_append(reply, "(bs)", c->smack_process_label_ignore, c->smack_process_label);
}

static int property_get_personality(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;

        assert(bus);
        assert(reply);
        assert(c);

        return sd_bus_message_append(reply, "s", personality_to_string(c->personality));
}

static int property_get_address_families(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ExecContext *c = userdata;
        _cleanup_strv_free_ char **l = NULL;
        Iterator i;
        void *af;
        int r;

        assert(bus);
        assert(reply);
        assert(c);

        r = sd_bus_message_open_container(reply, 'r', "bas");
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "b", c->address_families_whitelist);
        if (r < 0)
                return r;

        SET_FOREACH(af, c->address_families, i) {
                const char *name;

                name = af_to_name(PTR_TO_INT(af));
                if (!name)
                        continue;

                r = strv_extend(&l, name);
                if (r < 0)
                        return -ENOMEM;
        }

        strv_sort(l);

        r = sd_bus_message_append_strv(reply, l);
        if (r < 0)
                return r;

        return sd_bus_message_close_container(reply);
}

const sd_bus_vtable bus_exec_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Environment", "as", NULL, offsetof(ExecContext, environment), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("EnvironmentFiles", "a(sb)", property_get_environment_files, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("UMask", "u", bus_property_get_mode, offsetof(ExecContext, umask), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitCPU", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_CPU]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitFSIZE", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_FSIZE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitDATA", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_DATA]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitSTACK", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_STACK]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitCORE", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_CORE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitRSS", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_RSS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitNOFILE", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_NOFILE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitAS", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_AS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitNPROC", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_NPROC]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitMEMLOCK", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_MEMLOCK]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitLOCKS", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_LOCKS]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitSIGPENDING", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_SIGPENDING]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitMSGQUEUE", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_MSGQUEUE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitNICE", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_NICE]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitRTPRIO", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_RTPRIO]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("LimitRTTIME", "t", property_get_rlimit, offsetof(ExecContext, rlimit[RLIMIT_RTTIME]), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("WorkingDirectory", "s", NULL, offsetof(ExecContext, working_directory), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RootDirectory", "s", NULL, offsetof(ExecContext, root_directory), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OOMScoreAdjust", "i", property_get_oom_score_adjust, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Nice", "i", property_get_nice, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("IOScheduling", "i", property_get_ioprio, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CPUSchedulingPolicy", "i", property_get_cpu_sched_policy, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CPUSchedulingPriority", "i", property_get_cpu_sched_priority, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CPUAffinity", "ay", property_get_cpu_affinity, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TimerSlackNSec", "t", property_get_timer_slack_nsec, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CPUSchedulingResetOnFork", "b", bus_property_get_bool, offsetof(ExecContext, cpu_sched_reset_on_fork), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NonBlocking", "b", bus_property_get_bool, offsetof(ExecContext, non_blocking), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("StandardInput", "s", property_get_exec_input, offsetof(ExecContext, std_input), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("StandardOutput", "s", bus_property_get_exec_output, offsetof(ExecContext, std_output), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("StandardError", "s", bus_property_get_exec_output, offsetof(ExecContext, std_error), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TTYPath", "s", NULL, offsetof(ExecContext, tty_path), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TTYReset", "b", bus_property_get_bool, offsetof(ExecContext, tty_reset), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TTYVHangup", "b", bus_property_get_bool, offsetof(ExecContext, tty_vhangup), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("TTYVTDisallocate", "b", bus_property_get_bool, offsetof(ExecContext, tty_vt_disallocate), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SyslogPriority", "i", bus_property_get_int, offsetof(ExecContext, syslog_priority), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SyslogIdentifier", "s", NULL, offsetof(ExecContext, syslog_identifier), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SyslogLevelPrefix", "b", bus_property_get_bool, offsetof(ExecContext, syslog_level_prefix), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Capabilities", "s", property_get_capabilities, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SecureBits", "i", bus_property_get_int, offsetof(ExecContext, secure_bits), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("CapabilityBoundingSet", "t", property_get_capability_bounding_set, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("User", "s", NULL, offsetof(ExecContext, user), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Group", "s", NULL, offsetof(ExecContext, group), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SupplementaryGroups", "as", NULL, offsetof(ExecContext, supplementary_groups), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PAMName", "s", NULL, offsetof(ExecContext, pam_name), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ReadWriteDirectories", "as", NULL, offsetof(ExecContext, read_write_dirs), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ReadOnlyDirectories", "as", NULL, offsetof(ExecContext, read_only_dirs), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("InaccessibleDirectories", "as", NULL, offsetof(ExecContext, inaccessible_dirs), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MountFlags", "t", bus_property_get_ulong, offsetof(ExecContext, mount_flags), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PrivateTmp", "b", bus_property_get_bool, offsetof(ExecContext, private_tmp), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PrivateNetwork", "b", bus_property_get_bool, offsetof(ExecContext, private_network), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("PrivateDevices", "b", bus_property_get_bool, offsetof(ExecContext, private_devices), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ProtectHome", "s", bus_property_get_protect_home, offsetof(ExecContext, protect_home), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("ProtectSystem", "s", bus_property_get_protect_system, offsetof(ExecContext, protect_system), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SameProcessGroup", "b", bus_property_get_bool, offsetof(ExecContext, same_pgrp), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("UtmpIdentifier", "s", NULL, offsetof(ExecContext, utmp_id), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("UtmpMode", "s", property_get_exec_utmp_mode, offsetof(ExecContext, utmp_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SELinuxContext", "(bs)", property_get_selinux_context, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("AppArmorProfile", "(bs)", property_get_apparmor_profile, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SmackProcessLabel", "(bs)", property_get_smack_process_label, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("IgnoreSIGPIPE", "b", bus_property_get_bool, offsetof(ExecContext, ignore_sigpipe), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("NoNewPrivileges", "b", bus_property_get_bool, offsetof(ExecContext, no_new_privileges), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SystemCallFilter", "(bas)", property_get_syscall_filter, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SystemCallArchitectures", "as", property_get_syscall_archs, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("SystemCallErrorNumber", "i", property_get_syscall_errno, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Personality", "s", property_get_personality, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RestrictAddressFamilies", "(bas)", property_get_address_families, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RuntimeDirectoryMode", "u", bus_property_get_mode, offsetof(ExecContext, runtime_directory_mode), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RuntimeDirectory", "as", NULL, offsetof(ExecContext, runtime_directory), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_VTABLE_END
};

static int append_exec_command(sd_bus_message *reply, ExecCommand *c) {
        int r;

        assert(reply);
        assert(c);

        if (!c->path)
                return 0;

        r = sd_bus_message_open_container(reply, 'r', "sasbttttuii");
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "s", c->path);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(reply, c->argv);
        if (r < 0)
                return r;

        r = sd_bus_message_append(reply, "bttttuii",
                                  c->ignore,
                                  c->exec_status.start_timestamp.realtime,
                                  c->exec_status.start_timestamp.monotonic,
                                  c->exec_status.exit_timestamp.realtime,
                                  c->exec_status.exit_timestamp.monotonic,
                                  (uint32_t) c->exec_status.pid,
                                  (int32_t) c->exec_status.code,
                                  (int32_t) c->exec_status.status);
        if (r < 0)
                return r;

        return sd_bus_message_close_container(reply);
}

int bus_property_get_exec_command(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *ret_error) {

        ExecCommand *c = (ExecCommand*) userdata;
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "(sasbttttuii)");
        if (r < 0)
                return r;

        r = append_exec_command(reply, c);
        if (r < 0)
                return r;

        return sd_bus_message_close_container(reply);
}

int bus_property_get_exec_command_list(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *ret_error) {

        ExecCommand *c = *(ExecCommand**) userdata;
        int r;

        assert(bus);
        assert(reply);

        r = sd_bus_message_open_container(reply, 'a', "(sasbttttuii)");
        if (r < 0)
                return r;

        LIST_FOREACH(command, c, c) {
                r = append_exec_command(reply, c);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}

int bus_exec_context_set_transient_property(
                Unit *u,
                ExecContext *c,
                const char *name,
                sd_bus_message *message,
                UnitSetPropertiesMode mode,
                sd_bus_error *error) {

        int r;

        assert(u);
        assert(c);
        assert(name);
        assert(message);

        if (streq(name, "User")) {
                const char *uu;

                r = sd_bus_message_read(message, "s", &uu);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {

                        if (isempty(uu)) {
                                free(c->user);
                                c->user = NULL;
                        } else {
                                char *t;

                                t = strdup(uu);
                                if (!t)
                                        return -ENOMEM;

                                free(c->user);
                                c->user = t;
                        }

                        unit_write_drop_in_private_format(u, mode, name, "User=%s\n", uu);
                }

                return 1;

        } else if (streq(name, "Group")) {
                const char *gg;

                r = sd_bus_message_read(message, "s", &gg);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {

                        if (isempty(gg)) {
                                free(c->group);
                                c->group = NULL;
                        } else {
                                char *t;

                                t = strdup(gg);
                                if (!t)
                                        return -ENOMEM;

                                free(c->group);
                                c->group = t;
                        }

                        unit_write_drop_in_private_format(u, mode, name, "Group=%s\n", gg);
                }

                return 1;

        } else if (streq(name, "Nice")) {
                int n;

                r = sd_bus_message_read(message, "i", &n);
                if (r < 0)
                        return r;

                if (n < PRIO_MIN || n >= PRIO_MAX)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Nice value out of range");

                if (mode != UNIT_CHECK) {
                        c->nice = n;
                        unit_write_drop_in_private_format(u, mode, name, "Nice=%i\n", n);
                }

                return 1;

        } else if (streq(name, "TTYPath")) {
                const char *tty;

                r = sd_bus_message_read(message, "s", &tty);
                if (r < 0)
                        return r;

                if (!path_is_absolute(tty))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "TTY device not absolute path");

                if (mode != UNIT_CHECK) {
                        char *t;

                        t = strdup(tty);
                        if (!t)
                                return -ENOMEM;

                        free(c->tty_path);
                        c->tty_path = t;

                        unit_write_drop_in_private_format(u, mode, name, "TTYPath=%s\n", tty);
                }

                return 1;

        } else if (streq(name, "StandardInput")) {
                const char *s;
                ExecInput p;

                r = sd_bus_message_read(message, "s", &s);
                if (r < 0)
                        return r;

                p = exec_input_from_string(s);
                if (p < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid standard input name");

                if (mode != UNIT_CHECK) {
                        c->std_input = p;

                        unit_write_drop_in_private_format(u, mode, name, "StandardInput=%s\n", exec_input_to_string(p));
                }

                return 1;


        } else if (streq(name, "StandardOutput")) {
                const char *s;
                ExecOutput p;

                r = sd_bus_message_read(message, "s", &s);
                if (r < 0)
                        return r;

                p = exec_output_from_string(s);
                if (p < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid standard output name");

                if (mode != UNIT_CHECK) {
                        c->std_output = p;

                        unit_write_drop_in_private_format(u, mode, name, "StandardOutput=%s\n", exec_output_to_string(p));
                }

                return 1;

        } else if (streq(name, "StandardError")) {
                const char *s;
                ExecOutput p;

                r = sd_bus_message_read(message, "s", &s);
                if (r < 0)
                        return r;

                p = exec_output_from_string(s);
                if (p < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid standard error name");

                if (mode != UNIT_CHECK) {
                        c->std_error = p;

                        unit_write_drop_in_private_format(u, mode, name, "StandardError=%s\n", exec_output_to_string(p));
                }

                return 1;

        } else if (streq(name, "IgnoreSIGPIPE")) {
                int b;

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        c->ignore_sigpipe = b;

                        unit_write_drop_in_private_format(u, mode, name, "IgnoreSIGPIPE=%s\n", yes_no(b));
                }

                return 1;

        } else if (streq(name, "TTYVHangup")) {
                int b;

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        c->tty_vhangup = b;

                        unit_write_drop_in_private_format(u, mode, name, "TTYVHangup=%s\n", yes_no(b));
                }

                return 1;

        } else if (streq(name, "TTYReset")) {
                int b;

                r = sd_bus_message_read(message, "b", &b);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        c->tty_reset = b;

                        unit_write_drop_in_private_format(u, mode, name, "TTYReset=%s\n", yes_no(b));
                }

                return 1;

        } else if (streq(name, "UtmpIdentifier")) {
                const char *id;

                r = sd_bus_message_read(message, "s", &id);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        if (isempty(id))
                                c->utmp_id = mfree(c->utmp_id);
                        else if (free_and_strdup(&c->utmp_id, id) < 0)
                                return -ENOMEM;

                        unit_write_drop_in_private_format(u, mode, name, "UtmpIdentifier=%s\n", strempty(id));
                }

                return 1;

        } else if (streq(name, "UtmpMode")) {
                const char *s;
                ExecUtmpMode m;

                r = sd_bus_message_read(message, "s", &s);
                if (r < 0)
                        return r;

                m = exec_utmp_mode_from_string(s);
                if (m < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid utmp mode");

                if (mode != UNIT_CHECK) {
                        c->utmp_mode = m;

                        unit_write_drop_in_private_format(u, mode, name, "UtmpMode=%s\n", exec_utmp_mode_to_string(m));
                }

                return 1;

        } else if (streq(name, "PAMName")) {
                const char *n;

                r = sd_bus_message_read(message, "s", &n);
                if (r < 0)
                        return r;

                if (mode != UNIT_CHECK) {
                        if (isempty(n))
                                c->pam_name = mfree(c->pam_name);
                        else if (free_and_strdup(&c->pam_name, n) < 0)
                                return -ENOMEM;

                        unit_write_drop_in_private_format(u, mode, name, "PAMName=%s\n", strempty(n));
                }

                return 1;

        } else if (streq(name, "Environment")) {

                _cleanup_strv_free_ char **l = NULL;

                r = sd_bus_message_read_strv(message, &l);
                if (r < 0)
                        return r;

                if (!strv_env_is_valid(l))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid environment block.");

                if (mode != UNIT_CHECK) {
                        _cleanup_free_ char *joined = NULL;
                        char **e;

                        e = strv_env_merge(2, c->environment, l);
                        if (!e)
                                return -ENOMEM;

                        strv_free(c->environment);
                        c->environment = e;

                        joined = strv_join_quoted(c->environment);
                        if (!joined)
                                return -ENOMEM;

                        unit_write_drop_in_private_format(u, mode, name, "Environment=%s\n", joined);
                }

                return 1;

        } else if (rlimit_from_string(name) >= 0) {
                uint64_t rl;
                rlim_t x;

                r = sd_bus_message_read(message, "t", &rl);
                if (r < 0)
                        return r;

                if (rl == (uint64_t) -1)
                        x = RLIM_INFINITY;
                else {
                        x = (rlim_t) rl;

                        if ((uint64_t) x != rl)
                                return -ERANGE;
                }

                if (mode != UNIT_CHECK) {
                        int z;

                        z = rlimit_from_string(name);

                        if (!c->rlimit[z]) {
                                c->rlimit[z] = new(struct rlimit, 1);
                                if (!c->rlimit[z])
                                        return -ENOMEM;
                        }

                        c->rlimit[z]->rlim_cur = c->rlimit[z]->rlim_max = x;

                        if (x == RLIM_INFINITY)
                                unit_write_drop_in_private_format(u, mode, name, "%s=infinity\n", name);
                        else
                                unit_write_drop_in_private_format(u, mode, name, "%s=%" PRIu64 "\n", name, rl);
                }

                return 1;
        }

        return 0;
}
