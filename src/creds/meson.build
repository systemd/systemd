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
meson.add_install_script('sh', '-c', mkdir_p.format(credstoredir))
if install_sysconfdir
        # Keep in sync with tmpfiles.d/credstore.conf
        meson.add_install_script('sh', '-c', mkdir_p_mode.format(sysconfdir / 'credstore', '0700'))
        meson.add_install_script('sh', '-c', mkdir_p_mode.format(sysconfdir / 'credstore.encrypted', '0700'))
endif
