# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_HOMED') != 1
        subdir_done()
endif

systemd_homed_sources = files(
        'homed-bus.c',
        'homed-conf.c',
        'homed-home-bus.c',
        'homed-home.c',
        'homed-manager-bus.c',
        'homed-manager.c',
        'homed-operation.c',
        'homed-varlink.c',
        'homed.c',
        'user-record-sign.c',
)
systemd_homed_extract_sources = files(
        'home-util.c',
        'user-record-password-quality.c',
        'user-record-util.c',
)

systemd_homework_sources = files(
        'homework.c',
        'homework-blob.c',
        'homework-cifs.c',
        'homework-directory.c',
        'homework-fido2.c',
        'homework-fscrypt.c',
        'homework-luks.c',
        'homework-mount.c',
        'homework-password-cache.c',
        'homework-pkcs11.c',
        'homework-quota.c',
)

homed_gperf_c = custom_target(
        input : 'homed-gperf.gperf',
        output : 'homed-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

generated_sources += [homed_gperf_c]
systemd_homed_sources += [homed_gperf_c]

homectl_sources = files(
        'homectl-fido2.c',
        'homectl-pkcs11.c',
        'homectl-recovery-key.c',
        'homectl.c',
)

pam_systemd_home_sources = files(
        'home-util.c',
        'pam_systemd_home.c',
        'user-record-util.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-homed',
                'dbus' : true,
                'sources' : systemd_homed_sources + systemd_homed_extract_sources,
                'include_directories' : includes +
                                        include_directories('.'),
                'extract' : systemd_homed_extract_sources,
                'dependencies' : [
                        libcrypt,
                        libm,
                        libopenssl,
                        threads,
                ],
        },
        libexec_template + {
                'name' : 'systemd-homework',
                'sources' : systemd_homework_sources,
                'objects' : ['systemd-homed'],
                'link_with' : [
                        libshared,
                        libshared_fdisk
                ],
                'dependencies' : [
                        libblkid_cflags,
                        libcrypt,
                        libfdisk,
                        libopenssl,
                        libp11kit_cflags,
                        threads,
                ],
        },
        executable_template + {
                'name' : 'homectl',
                'public' : true,
                'sources' : homectl_sources,
                'objects' : ['systemd-homed'],
                'dependencies' : [
                        libcrypt,
                        libdl,
                        libopenssl,
                        libp11kit_cflags,
                        threads,
                ],
        },
        test_template + {
                'sources' : files('test-homed-regression-31896.c'),
                'type' : 'manual',
        },
]

modules += [
        pam_template + {
                'name' : 'pam_systemd_home',
                'conditions' : ['HAVE_PAM'],
                'sources' : pam_systemd_home_sources,
                'dependencies' : [
                        libcrypt,
                        libintl,
                        libpam_misc,
                        libpam,
                        threads,
                ],
                'version-script' : meson.current_source_dir() / 'pam_systemd_home.sym',
        },
]

install_data('org.freedesktop.home1.conf',
             install_dir : dbuspolicydir)
install_data('org.freedesktop.home1.service',
             install_dir : dbussystemservicedir)
install_data('org.freedesktop.home1.policy',
             install_dir : polkitpolicydir)

if install_sysconfdir_samples
        install_data('homed.conf',
                     install_dir : pkgconfigfiledir)
endif

install_symlink('systemd-home-fallback-shell',
                pointing_to : 'homectl',
                install_dir : bindir)
