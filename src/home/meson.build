# SPDX-License-Identifier: LGPL-2.1-or-later

home_includes = [includes, include_directories('.')]

systemd_homework_sources = files(
        'home-util.c',
        'homework-cifs.c',
        'homework-directory.c',
        'homework-fscrypt.c',
        'homework-luks.c',
        'homework-mount.c',
        'homework-password-cache.c',
        'homework-quota.c',
        'homework.c',
        'user-record-util.c',
)

if conf.get('HAVE_P11KIT') == 1
        systemd_homework_sources += files('homework-pkcs11.c')
endif
if conf.get('HAVE_LIBFIDO2') == 1
        systemd_homework_sources += files('homework-fido2.c')
endif

systemd_homed_sources = files(
        'home-util.c',
        'homed-bus.c',
        'homed-conf.c',
        'homed-home-bus.c',
        'homed-home.c',
        'homed-manager-bus.c',
        'homed-manager.c',
        'homed-operation.c',
        'homed-varlink.c',
        'homed.c',
        'user-record-pwquality.c',
        'user-record-sign.c',
        'user-record-util.c',
)

homed_gperf_c = custom_target(
        'homed_gperf.c',
        input : 'homed-gperf.gperf',
        output : 'homed-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_homed_sources += [homed_gperf_c]

homectl_sources = files(
        'home-util.c',
        'homectl-fido2.c',
        'homectl-pkcs11.c',
        'homectl-recovery-key.c',
        'homectl.c',
        'user-record-pwquality.c',
        'user-record-util.c',
)

pam_systemd_home_sym = 'src/home/pam_systemd_home.sym'
pam_systemd_home_c = files(
        'home-util.c',
        'pam_systemd_home.c',
        'user-record-util.c',
)

if conf.get('ENABLE_HOMED') == 1
        install_data('org.freedesktop.home1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.home1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.home1.policy',
                     install_dir : polkitpolicydir)

        if install_sysconfdir_samples
                install_data('homed.conf',
                             install_dir : pkgsysconfdir)
        endif
endif
