# SPDX-License-Identifier: LGPL-2.1-or-later

systemctl_sources = files(
        'systemctl-add-dependency.c',
        'systemctl-cancel-job.c',
        'systemctl-clean-or-freeze.c',
        'systemctl-compat-halt.c',
        'systemctl-compat-runlevel.c',
        'systemctl-compat-shutdown.c',
        'systemctl-compat-telinit.c',
        'systemctl-daemon-reload.c',
        'systemctl-edit.c',
        'systemctl-enable.c',
        'systemctl-is-active.c',
        'systemctl-is-enabled.c',
        'systemctl-is-system-running.c',
        'systemctl-kill.c',
        'systemctl-list-dependencies.c',
        'systemctl-list-jobs.c',
        'systemctl-list-machines.c',
        'systemctl-list-unit-files.c',
        'systemctl-list-units.c',
        'systemctl-log-setting.c',
        'systemctl-logind.c',
        'systemctl-mount.c',
        'systemctl-preset-all.c',
        'systemctl-reset-failed.c',
        'systemctl-service-watchdogs.c',
        'systemctl-set-default.c',
        'systemctl-set-environment.c',
        'systemctl-set-property.c',
        'systemctl-show.c',
        'systemctl-start-special.c',
        'systemctl-start-unit.c',
        'systemctl-switch-root.c',
        'systemctl-sysv-compat.c',
        'systemctl-trivial-method.c',
        'systemctl-util.c',
        'systemctl.c',
)

if get_option('link-systemctl-shared')
        systemctl_link_with = [libshared]
else
        systemctl_link_with = [libsystemd_static,
                               libshared_static,
                               libbasic_gcrypt]
endif

fuzzers += [
        {
                'sources' : [
                        files('fuzz-systemctl-parse-argv.c'),
                        systemctl_sources,
                ],
                'link_with' : systemctl_link_with,
                'c_args' : '-DFUZZ_SYSTEMCTL_PARSE_ARGV',
        },
]
