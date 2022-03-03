# SPDX-License-Identifier: LGPL-2.1-or-later

home_includes = [includes, include_directories('.')]

systemd_homework_sources = files(
        'home-util.c',
        'home-util.h',
        'homework-cifs.c',
        'homework-cifs.h',
        'homework-directory.c',
        'homework-directory.h',
        'homework-fido2.h',
        'homework-fscrypt.c',
        'homework-fscrypt.h',
        'homework-luks.c',
        'homework-luks.h',
        'homework-mount.c',
        'homework-mount.h',
        'homework-password-cache.c',
        'homework-password-cache.h',
        'homework-pkcs11.h',
        'homework-quota.c',
        'homework-quota.h',
        'homework.c',
        'homework.h',
        'user-record-util.c',
        'user-record-util.h',
)

if conf.get('HAVE_P11KIT') == 1
        systemd_homework_sources += files('homework-pkcs11.c')
endif
if conf.get('HAVE_LIBFIDO2') == 1
        systemd_homework_sources += files('homework-fido2.c')
endif

systemd_homed_sources = files(
        'home-util.c',
        'home-util.h',
        'homed-bus.c',
        'homed-bus.h',
        'homed-conf.c',
        'homed-conf.h',
        'homed-home-bus.c',
        'homed-home-bus.h',
        'homed-home.c',
        'homed-home.h',
        'homed-manager-bus.c',
        'homed-manager-bus.h',
        'homed-manager.c',
        'homed-manager.h',
        'homed-operation.c',
        'homed-operation.h',
        'homed-varlink.c',
        'homed-varlink.h',
        'homed.c',
        'user-record-pwquality.c',
        'user-record-pwquality.h',
        'user-record-sign.c',
        'user-record-sign.h',
        'user-record-util.c',
        'user-record-util.h',
)

homed_gperf_c = custom_target(
        'homed_gperf.c',
        input : 'homed-gperf.gperf',
        output : 'homed-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_homed_sources += [homed_gperf_c]

homectl_sources = files(
        'home-util.c',
        'home-util.h',
        'homectl-fido2.c',
        'homectl-fido2.h',
        'homectl-pkcs11.c',
        'homectl-pkcs11.h',
        'homectl-recovery-key.c',
        'homectl-recovery-key.h',
        'homectl.c',
        'user-record-pwquality.c',
        'user-record-pwquality.h',
        'user-record-util.c',
        'user-record-util.h',
)

pam_systemd_home_sym = 'src/home/pam_systemd_home.sym'
pam_systemd_home_c = files(
        'home-util.c',
        'home-util.h',
        'pam_systemd_home.c',
        'user-record-util.c',
        'user-record-util.h',
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
