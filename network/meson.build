# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_NETWORKD') == 1
        install_data(
                '80-6rd-tunnel.network',
                '80-6rd-tunnel.link',
                '80-container-host0.network',
                '80-container-host0-tun.network',
                '80-container-vb.network',
                '80-container-vb.link',
                '80-container-ve.network',
                '80-container-ve.link',
                '80-container-vz.network',
                '80-container-vz.link',
                '80-namespace-ns.network',
                '80-namespace-ns.link',
                '80-vm-vt.network',
                '80-vm-vt.link',
                '80-wifi-adhoc.network',
                install_dir : networkdir)

        example_network_files = files(
                '80-auto-link-local.network.example',
                '89-ethernet.network.example',
                '80-wifi-ap.network.example',
                '80-wifi-station.network.example',
        )

        install_data(
                example_network_files,
                install_dir : networkdir)

        if get_option('default-network')
                foreach f : example_network_files
                        install_data(
                                f,
                                rename : fs.replace_suffix(fs.name(f), ''),
                                install_dir : networkdir)
                endforeach
        endif
endif

install_data('99-default.link',
             install_dir : networkdir)

if install_sysconfdir
        install_emptydir(sysconfdir / 'systemd/network')
endif
