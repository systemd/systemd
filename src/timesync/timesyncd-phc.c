/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/ptp_clock.h>
#include <sys/ioctl.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-device.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "log.h"
#include "network-util.h"
#include "path-util.h"
#include "string-util.h"
#include "timesyncd-manager.h"
#include "timesyncd-phc.h"

/* Many hypervisors expose their notion of wallclock time to guests as a PTP hardware clock (PHC):
 * /dev/ptp_kvm on KVM, /dev/ptp_hyperv on Hyper-V/Azure, /dev/ptp_vmware on VMware, and /dev/ptp_ena on
 * AWS. Despite the name these have nothing to do with the PTP network protocol: they are local clock
 * devices that can be read via an ioctl(). This implements a simple reference clock driver: we
 * periodically measure the offset between the PHC and CLOCK_REALTIME, and feed that into the same clock
 * discipline logic we use for NTP. While a PHC is in use NTP servers are not contacted.
 *
 * Which PHCs are suitable is decided by udev rules: we only consider devices tagged "timesync", since only
 * the hypervisor-provided clocks track UTC (PHCs of network interfaces typically run on TAI, and are only
 * meaningful when disciplined via PTP). Alternatively, a device node path may be configured explicitly, in
 * which case we use the device with that node path or symlink, regardless of its tags. */

static int64_t ptp_clock_time_to_nsec(const struct ptp_clock_time *t) {
        assert(t);

        return t->sec * (int64_t) NSEC_PER_SEC + (int64_t) t->nsec;
}

int phc_pick_sample(
                const struct ptp_sys_offset *s,
                int64_t *ret_offset_nsec,
                int64_t *ret_delay_nsec,
                int64_t *ret_device_nsec) {

        int64_t best_offset = 0, best_delay = INT64_MAX, best_device = 0;
        bool found = false;

        assert(s);

        /* PTP_SYS_OFFSET returns n_samples PHC readings, each sandwiched between two CLOCK_REALTIME
         * readings: sys₀, phc₀, sys₁, phc₁, sys₂, …, sysₙ. The sandwich with the smallest width suffered
         * least from scheduling and hypercall latency, hence use that one, and assume the PHC was read
         * right in the middle of it. */

        if (s->n_samples == 0 || s->n_samples > PTP_MAX_SAMPLES)
                return -EINVAL;

        for (unsigned i = 0; i < s->n_samples; i++) {
                int64_t before = ptp_clock_time_to_nsec(s->ts + 2*i),
                        device = ptp_clock_time_to_nsec(s->ts + 2*i + 1),
                        after = ptp_clock_time_to_nsec(s->ts + 2*i + 2);

                /* The system clock was stepped while we were reading, skip this sample */
                if (after < before)
                        continue;

                if (found && after - before >= best_delay)
                        continue;

                best_delay = after - before;
                best_offset = device - (before + best_delay / 2);
                best_device = device;
                found = true;
        }

        if (!found)
                return -ERANGE;

        if (ret_offset_nsec)
                *ret_offset_nsec = best_offset;
        if (ret_delay_nsec)
                *ret_delay_nsec = best_delay;
        if (ret_device_nsec)
                *ret_device_nsec = best_device;

        return 0;
}

static int phc_read_precise(int fd, int64_t *ret_offset_nsec, int64_t *ret_device_nsec) {
        struct ptp_sys_offset_precise p = {};
        int64_t device;

        assert(fd >= 0);
        assert(ret_offset_nsec);
        assert(ret_device_nsec);

        /* Asks the driver for a cross-timestamp, which correlates the PHC with the system clock without any
         * read latency. ptp_kvm supports this on x86 and arm64. */
        if (ioctl(fd, PTP_SYS_OFFSET_PRECISE, &p) < 0)
                return -errno;

        device = ptp_clock_time_to_nsec(&p.device);

        *ret_offset_nsec = device - ptp_clock_time_to_nsec(&p.sys_realtime);
        *ret_device_nsec = device;
        return 0;
}

static int phc_read(int fd, bool *precise, int64_t *ret_offset_nsec, int64_t *ret_delay_nsec) {
        int64_t offset = 0, delay = 0, device = 0;
        int r;

        assert(fd >= 0);
        assert(precise);
        assert(ret_offset_nsec);
        assert(ret_delay_nsec);

        if (*precise) {
                r = phc_read_precise(fd, &offset, &device);
                /* -ENODEV is returned if the current clocksource is not the one the driver can correlate
                 * with, e.g. ptp_kvm while the guest uses the TSC clocksource. */
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r) || r == -ENODEV) {
                        log_debug_errno(r, "PTP hardware clock does not support cross-timestamping, falling back to PTP_SYS_OFFSET.");
                        *precise = false;
                } else if (r < 0)
                        return r;
        }

        if (!*precise) {
                struct ptp_sys_offset s = {
                        .n_samples = PHC_SAMPLES,
                };

                if (ioctl(fd, PTP_SYS_OFFSET, &s) < 0)
                        return -errno;

                r = phc_pick_sample(&s, &offset, &delay, &device);
                if (r < 0)
                        return r;
        }

        /* Refuse clocks that obviously have not been set (e.g. counting from 1970 since host boot) */
        if (device < (int64_t) TIME_EPOCH * (int64_t) NSEC_PER_SEC)
                return -ESTALE;

        *ret_offset_nsec = offset;
        *ret_delay_nsec = delay;
        return 0;
}

static int phc_open(
                sd_device *d,
                int *ret_fd,
                dev_t *ret_devnum,
                char **ret_path,
                char **ret_clock_name,
                bool *ret_precise) {

        _cleanup_free_ char *path = NULL, *clock_name = NULL;
        _cleanup_close_ int fd = -EBADF;
        int64_t offset, delay;
        bool precise = true;
        const char *s;
        dev_t devnum;
        int r;

        assert(d);
        assert(ret_fd);
        assert(ret_devnum);
        assert(ret_path);
        assert(ret_clock_name);
        assert(ret_precise);

        r = sd_device_get_devnum(d, &devnum);
        if (r < 0)
                return r;

        r = sd_device_get_devname(d, &s);
        if (r < 0)
                return r;

        path = strdup(s);
        if (!path)
                return -ENOMEM;

        if (sd_device_get_sysattr_value(d, "clock_name", &s) >= 0) {
                clock_name = strdup(s);
                if (!clock_name)
                        return -ENOMEM;
        }

        /* Read access is sufficient for reading the clock, we never want to adjust it. */
        fd = sd_device_open(d, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return fd;

        /* Do a test read, so that we fail early if this doesn't work, and know whether cross-timestamping
         * is available. */
        r = phc_read(fd, &precise, &offset, &delay);
        if (r < 0)
                return r;

        *ret_fd = TAKE_FD(fd);
        *ret_devnum = devnum;
        *ret_path = TAKE_PTR(path);
        *ret_clock_name = TAKE_PTR(clock_name);
        *ret_precise = precise;
        return 0;
}

bool manager_phc_active(Manager *m) {
        assert(m);

        return m->phc_fd >= 0;
}

static void manager_phc_emit_changed(Manager *m) {
        assert(m);

        if (sd_bus_is_ready(m->bus) <= 0)
                return;

        (void) sd_bus_emit_properties_changed(
                        m->bus,
                        "/org/freedesktop/timesync1",
                        "org.freedesktop.timesync1.Manager",
                        "PHCDevice",
                        "PHCClockName",
                        "NTPMessage",
                        NULL);
}

void manager_phc_stop(Manager *m) {
        assert(m);

        if (!manager_phc_active(m))
                return;

        m->phc_timer = sd_event_source_disable_unref(m->phc_timer);
        m->phc_fd = safe_close(m->phc_fd);
        m->phc_devnum = 0;
        m->phc_path = mfree(m->phc_path);
        m->phc_clock_name = mfree(m->phc_clock_name);
        m->phc_precise = false;
        m->phc_failures = 0;
        m->phc_offset_nsec = m->phc_delay_nsec = 0;

        manager_reset_samples(m);

        /* Make sure manager_begin() starts out with the minimal NTP poll interval again */
        m->poll_interval_usec = 0;

        /* We do not watch for clock changes while using a PHC, hence forget about any jump we did, so that
         * the NTP logic doesn't skip the next clock change event. */
        m->jumped = false;
}

static int manager_phc_try_all(Manager *m, dev_t skip);

static int manager_phc_fallback(Manager *m) {
        dev_t devnum;
        int r;

        assert(m);

        devnum = m->phc_devnum;

        manager_phc_stop(m);
        manager_phc_emit_changed(m);

        /* Try other PHC devices first, and if there are none (or we failed to look for them), go back to
         * NTP */
        r = manager_phc_try_all(m, devnum);
        if (r > 0)
                return 0;

        if (!network_is_online()) {
                (void) sd_notify(/* unset_environment= */ false, "STATUS=Idle.");
                return 0;
        }

        return manager_connect(m);
}

static int on_phc_timer(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int64_t offset_nsec, delay_nsec;
        double offset, delay;
        bool spike;
        int r;

        r = phc_read(m->phc_fd, &m->phc_precise, &offset_nsec, &delay_nsec);
        if (r < 0) {
                m->phc_failures++;
                if (m->phc_failures >= PHC_MAX_FAILURES) {
                        log_warning_errno(r, "Failed to read PTP hardware clock %s %u times in a row, not using it anymore: %m",
                                          m->phc_path, m->phc_failures);
                        return manager_phc_fallback(m);
                }

                log_debug_errno(r, "Failed to read PTP hardware clock %s, ignoring: %m", m->phc_path);
        } else {
                m->phc_failures = 0;
                m->phc_offset_nsec = offset_nsec;
                m->phc_delay_nsec = delay_nsec;

                offset = (double) offset_nsec / NSEC_PER_SEC;
                delay = (double) delay_nsec / NSEC_PER_SEC;

                spike = manager_sample_spike_detection(m, offset, delay);
                m->spike = spike;

                log_debug("PHC %s: offset %+.9fs, delay %.9fs, jitter %.9fs, drift %+"PRIi64"ppm%s",
                          m->phc_path, offset, delay, m->samples_jitter, m->drift_freq / 65536,
                          spike ? " (ignored)" : "");

                /* PHCs carry no leap second information. The PHCs tagged by default all follow the host's
                 * CLOCK_REALTIME (i.e. UTC), hence leap seconds will be stepped over when the host's clock
                 * steps over them. */
                if (!spike)
                        (void) manager_sync_clock(m, offset, /* leap_sec= */ 0, /* persist= */ false);
        }

        r = event_reset_time_relative(
                        m->event,
                        &m->phc_timer,
                        CLOCK_BOOTTIME,
                        m->poll_interval_usec,
                        /* accuracy= */ 0,
                        on_phc_timer,
                        m,
                        SD_EVENT_PRIORITY_NORMAL,
                        "phc-timer",
                        /* force_reset= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to rearm PHC timer: %m");

        return 0;
}

static bool manager_phc_suitable(Manager *m, sd_device *d) {
        const char *s;

        assert(m);
        assert(d);

        /* If a device node path is explicitly configured, use the device with that node path or symlink,
         * regardless of its tags. Otherwise use any device tagged by udev as suitable. */

        if (!m->phc_device_match)
                return sd_device_has_current_tag(d, PHC_UDEV_TAG) > 0;

        if (sd_device_get_devname(d, &s) >= 0 && path_equal(s, m->phc_device_match))
                return true;

        FOREACH_DEVICE_DEVLINK(d, link)
                if (path_equal(link, m->phc_device_match))
                        return true;

        return false;
}

static int manager_phc_try(Manager *m, sd_device *d) {
        _cleanup_free_ char *path = NULL, *clock_name = NULL;
        _cleanup_close_ int fd = -EBADF;
        bool precise = false;
        dev_t devnum = 0;
        int r;

        assert(m);
        assert(d);
        assert(!manager_phc_active(m));

        /* Tries to start using the specified PHC device. Returns > 0 if that worked, 0 if the device is not
         * suitable, < 0 on fatal errors. */

        r = phc_open(d, &fd, &devnum, &path, &clock_name, &precise);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0) {
                log_device_warning_errno(d, r, "Failed to open PTP hardware clock, skipping: %m");
                return 0;
        }

        /* Stop talking NTP */
        manager_set_server_name(m, NULL);
        manager_reset_samples(m);
        m->event_retry = sd_event_source_disable_unref(m->event_retry);
        m->talking = false;
        zero(m->ntpmsg);

        m->phc_fd = TAKE_FD(fd);
        m->phc_devnum = devnum;
        m->phc_path = TAKE_PTR(path);
        m->phc_clock_name = TAKE_PTR(clock_name);
        m->phc_precise = precise;
        m->phc_failures = 0;
        m->poll_interval_usec = PHC_POLL_INTERVAL_USEC;

        log_info("Synchronizing to PTP hardware clock %s (%s)%s.",
                 m->phc_path, strna(m->phc_clock_name),
                 m->phc_precise ? ", using cross-timestamps" : "");
        (void) sd_notifyf(/* unset_environment= */ false,
                          "STATUS=Synchronizing to PTP hardware clock %s (%s).",
                          m->phc_path, strna(m->phc_clock_name));

        manager_phc_emit_changed(m);

        /* Take the first sample right-away */
        r = event_reset_time_relative(
                        m->event,
                        &m->phc_timer,
                        CLOCK_BOOTTIME,
                        /* usec= */ 0,
                        /* accuracy= */ 0,
                        on_phc_timer,
                        m,
                        SD_EVENT_PRIORITY_NORMAL,
                        "phc-timer",
                        /* force_reset= */ true);
        if (r < 0) {
                log_error_errno(r, "Failed to set up PHC timer: %m");
                manager_phc_stop(m);
                manager_phc_emit_changed(m);
                return r;
        }

        return 1;
}

static int manager_phc_try_all(Manager *m, dev_t skip) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert(m);

        /* Tries all suitable PHC devices, and starts using the first one that works. 'skip' may specify a
         * device to not consider, e.g. because we just gave up on it. Returns > 0 if a PHC is in use, 0 if
         * not. */

        if (manager_phc_active(m))
                return 1;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate device enumerator: %m");

        r = sd_device_enumerator_add_match_subsystem(e, "ptp", /* match= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to add subsystem match: %m");

        if (!m->phc_device_match) {
                r = sd_device_enumerator_add_match_tag(e, PHC_UDEV_TAG);
                if (r < 0)
                        return log_error_errno(r, "Failed to add tag match: %m");
        }

        FOREACH_DEVICE(e, d) {
                dev_t devnum;

                if (skip != 0 && sd_device_get_devnum(d, &devnum) >= 0 && devnum == skip)
                        continue;

                /* Note that the tag index is sticky, i.e. also lists devices that had the tag removed,
                 * hence check again that the tag is still set. */
                if (!manager_phc_suitable(m, d))
                        continue;

                r = manager_phc_try(m, d);
                if (r != 0)
                        return r;
        }

        log_debug("No suitable PTP hardware clock found.");
        return 0;
}

static int on_phc_uevent(sd_device_monitor *monitor, sd_device *d, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        sd_device_action_t action;
        dev_t devnum;
        int r;

        r = sd_device_get_action(d, &action);
        if (r < 0) {
                log_device_debug_errno(d, r, "Failed to get uevent action, ignoring: %m");
                return 0;
        }

        if (manager_phc_active(m)) {
                /* Give up on the device we are using if it is removed or is not suitable anymore (i.e. lost
                 * its tag, or the configured symlink) */
                if (sd_device_get_devnum(d, &devnum) < 0 || devnum != m->phc_devnum)
                        return 0;

                if (action == SD_DEVICE_REMOVE)
                        log_info("PTP hardware clock %s has been removed.", m->phc_path);
                else if (!manager_phc_suitable(m, d))
                        log_info("PTP hardware clock %s is not suitable anymore.", m->phc_path);
                else
                        return 0;

                (void) manager_phc_fallback(m);
                return 0;
        }

        /* Pick up the first suitable PHC that shows up, if we don't use one yet */
        if (action == SD_DEVICE_REMOVE || !manager_phc_suitable(m, d))
                return 0;

        (void) manager_phc_try(m, d);
        return 0;
}

static int manager_phc_monitor(Manager *m) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor = NULL;
        int r;

        assert(m);
        assert(!m->phc_monitor);

        r = sd_device_monitor_new(&monitor);
        if (r < 0)
                return r;

        (void) sd_device_monitor_set_description(monitor, "phc");

        r = sd_device_monitor_filter_add_match_subsystem_devtype(monitor, "ptp", /* devtype= */ NULL);
        if (r < 0)
                return r;

        /* The tag is irrelevant if a device node path is configured. Note that the monitor matches against
         * the sticky tags, hence we still see the device we use losing the tag. */
        if (!m->phc_device_match) {
                r = sd_device_monitor_filter_add_match_tag(monitor, PHC_UDEV_TAG);
                if (r < 0)
                        return r;
        }

        r = sd_device_monitor_attach_event(monitor, m->event);
        if (r < 0)
                return r;

        r = sd_device_monitor_start(monitor, on_phc_uevent, m);
        if (r < 0)
                return r;

        m->phc_monitor = TAKE_PTR(monitor);
        return 0;
}

int manager_phc_setup(Manager *m) {
        int r;

        assert(m);

        if (!m->phc_enabled) {
                log_debug("Use of PTP hardware clocks is disabled.");
                return 0;
        }

        if (m->phc_device_match)
                log_debug("Looking for PTP hardware clock %s.", m->phc_device_match);
        else
                log_debug("Looking for PTP hardware clocks tagged \"" PHC_UDEV_TAG "\".");

        /* The PHC drivers might get loaded after we started up, hence watch for them showing up. */
        r = manager_phc_monitor(m);
        if (r < 0)
                log_warning_errno(r, "Failed to watch for PTP hardware clocks, devices showing up later will not be used: %m");

        return manager_phc_try_all(m, /* skip= */ 0);
}
