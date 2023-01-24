# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_portabled_sources = files(
        'portable.c',
        'portabled-bus.c',
        'portabled-image-bus.c',
        'portabled-image.c',
        'portabled-operation.c',
        'portabled.c',
)

if conf.get('ENABLE_PORTABLED') == 1
        install_data('org.freedesktop.portable1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.portable1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.portable1.policy',
                     install_dir : polkitpolicydir)

        install_data('profile/default/service.conf', install_dir : profiledir / 'default')
        install_data('profile/nonetwork/service.conf', install_dir : profiledir / 'nonetwork')
        install_data('profile/strict/service.conf', install_dir : profiledir / 'strict')
        install_data('profile/trusted/service.conf', install_dir : profiledir / 'trusted')
endif
