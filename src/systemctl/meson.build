# SPDX-License-Identifier: LGPL-2.1-or-later

systemctl_sources = files(
        'systemctl-add-dependency.c',
        'systemctl-cancel-job.c',
        'systemctl-clean-or-freeze.c',
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
        'systemctl-main.c',
        'systemctl-mount.c',
        'systemctl-preset-all.c',
        'systemctl-reset-failed.c',
        'systemctl-service-watchdogs.c',
        'systemctl-set-default.c',
        'systemctl-set-environment.c',
        'systemctl-set-property.c',
        'systemctl-show.c',
        'systemctl-start-special.c',
        'systemctl-switch-root.c',
        'systemctl-trivial-method.c',
        'systemctl-whoami.c',
)
systemctl_extract_sources = files(
        'systemctl-compat-halt.c',
        'systemctl-compat-shutdown.c',
        'systemctl-daemon-reload.c',
        'systemctl-logind.c',
        'systemctl-start-unit.c',
        'systemctl-sysv-compat.c',
        'systemctl-util.c',
        'systemctl.c',
)

if get_option('link-systemctl-shared')
        systemctl_link_with = [libshared]
else
        systemctl_link_with = [libsystemd_static,
                               libshared_static]
endif

executables += [
        executable_template + {
                'name' : 'systemctl',
                'public' : true,
                'sources' : systemctl_sources + systemctl_extract_sources,
                'extract' : systemctl_extract_sources,
                'link_with' : systemctl_link_with,
                'dependencies' : [
                        libcap,
                        liblz4_cflags,
                        libselinux,
                        libxz_cflags,
                        libzstd_cflags,
                        threads,
                ],
                'install_tag' : 'systemctl',
        },
        fuzz_template + {
                'sources' : files('fuzz-systemctl-parse-argv.c'),
                'objects' : ['systemctl'],
                'link_with' : systemctl_link_with,
        },
]

foreach alias : ['halt', 'poweroff', 'reboot', 'shutdown']
        install_symlink(alias,
                        pointing_to : sbin_to_bin + 'systemctl',
                        install_dir : sbindir)
endforeach
