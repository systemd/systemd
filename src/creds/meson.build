# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-creds',
                'public' : true,
                'sources' : files('creds.c'),
                'dependencies' : [
                        libopenssl,
                        threads,
                ],
        },
]

# Protecting files from the distro in /usr doesn't make sense since they can be trivially accessed otherwise,
# so don't restrict the access mode in /usr. That doesn't apply to /etc, so we do restrict the access mode
# there.
install_emptydir(credstoredir)
if install_sysconfdir
        # Keep in sync with tmpfiles.d/credstore.conf
        install_emptydir(sysconfdir / 'credstore',
                         install_mode : 'rwx------')
        install_emptydir(sysconfdir / 'credstore.encrypted',
                         install_mode : 'rwx------')
endif

install_data('org.freedesktop.creds1.policy', install_dir : polkitpolicydir)
