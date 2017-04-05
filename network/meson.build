# -*- mode: meson -*-

if conf.get('ENABLE_NETWORKD', 0) == 1
  install_data('80-container-host0.network',
               '80-container-ve.network',
               '80-container-vz.network',
               '99-default.link',
               install_dir : networkdir)
endif
