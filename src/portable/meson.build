# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_PORTABLED') != 1
        subdir_done()
endif

systemd_portabled_sources = files(
        'portable.c',
        'portabled-bus.c',
        'portabled-image-bus.c',
        'portabled-image.c',
        'portabled-operation.c',
        'portabled.c',
)

if get_option('link-portabled-shared')
        portabled_link_with = [libshared]
else
        portabled_link_with = [
                libshared_static,
                libsystemd_static,
        ]
endif

executables += [
        libexec_template + {
                'name' : 'systemd-portabled',
                'dbus' : true,
                'sources' : systemd_portabled_sources,
                'link_with' : portabled_link_with,
                'dependencies' : [
                        libcryptsetup_cflags,
                        libmount_cflags,
                        libselinux_cflags,
                        threads,
                ],
        },
        executable_template + {
                'name' : 'portablectl',
                'public' : true,
                'sources' : files('portablectl.c'),
                'link_with' : portabled_link_with,
                'dependencies' : threads,
        },
]

install_data('org.freedesktop.portable1.conf',
             install_dir : dbuspolicydir)
install_data('org.freedesktop.portable1.service',
             install_dir : dbussystemservicedir)
install_data('org.freedesktop.portable1.service-for-session',
             install_dir : dbussessionservicedir,
             rename : 'org.freedesktop.portable1.service')
install_data('org.freedesktop.portable1.policy',
             install_dir : polkitpolicydir)

install_data('profile/system/default/service.conf', install_dir : systemprofiledir / 'default')
install_data('profile/system/nonetwork/service.conf', install_dir : systemprofiledir / 'nonetwork')
install_data('profile/system/strict/service.conf', install_dir : systemprofiledir / 'strict')
install_data('profile/system/trusted/service.conf', install_dir : systemprofiledir / 'trusted')

install_data('profile/user/default/service.conf', install_dir : userprofiledir / 'default')
install_data('profile/user/nonetwork/service.conf', install_dir : userprofiledir / 'nonetwork')
install_data('profile/user/strict/service.conf', install_dir : userprofiledir / 'strict')
install_data('profile/user/trusted/service.conf', install_dir : userprofiledir / 'trusted')
