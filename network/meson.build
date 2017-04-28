if conf.get('ENABLE_NETWORKD', false)
        install_data('80-container-host0.network',
                     '80-container-ve.network',
                     '80-container-vz.network',
                     install_dir : networkdir)

        meson.add_install_script('sh', '-c',
                                 mkdir_p.format(join_paths(sysconfdir, 'systemd/network')))
endif

install_data('99-default.link',
             install_dir : networkdir)
