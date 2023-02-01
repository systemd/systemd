# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_NETWORKD') == 1
        install_data('80-6rd-tunnel.network',
                     '80-container-host0.network',
                     '80-container-vb.network',
                     '80-container-ve.network',
                     '80-container-vz.network',
                     '80-ethernet.network.example',
                     '80-vm-vt.network',
                     '80-wifi-adhoc.network',
                     '80-wifi-ap.network.example',
                     '80-wifi-station.network.example',
                     install_dir : networkdir)

        if install_sysconfdir
                meson.add_install_script('sh', '-c',
                                         mkdir_p.format(sysconfdir / 'systemd/network'))
        endif
endif

install_data('99-default.link',
             install_dir : networkdir)
