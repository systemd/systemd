# -*- mode: meson -*-

systemd_localed_sources = files('''
  localed.c
  keymap-util.c
  keymap-util.h
'''.split())

localectl_sources = files('localectl.c')

if conf.get('ENABLE_LOCALED', 0) == 1
  install_data('org.freedesktop.locale1.conf',
               install_dir : dbuspolicydir)
  install_data('org.freedesktop.locale1.service',
               install_dir : dbussystemservicedir)

  custom_target(
    'org.freedesktop.locale1.policy',
    input : 'org.freedesktop.locale1.policy.in',
    output : 'org.freedesktop.locale1.policy',
    command : intltool_command,
    install : true,
    install_dir : polkitpolicydir)
endif

install_data('kbd-model-map',
             'language-fallback-map',
             install_dir : pkgdatadir)
