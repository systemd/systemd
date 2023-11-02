# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_NETWORKD') == 1
        install_data(
                '90-6rd-tunnel.network',
                '90-auto-link-local.network.example',
                '90-container-host0.network',
                '90-container-vb.network',
                '90-container-ve.network',
                '90-container-vz.network',
                '99-ethernet.network.example',
                '90-vm-vt.network',
                '90-wifi-adhoc.network',
                '90-wifi-ap.network.example',
                '90-wifi-station.network.example',
                install_dir : networkdir)

        if install_sysconfdir
                install_emptydir(sysconfdir / 'systemd/network')
        endif
endif

install_data('99-default.link',
             install_dir : networkdir)
