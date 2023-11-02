# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_NETWORKD') == 1
        install_data(
                '90-6rd-tunnel.network',
                '90-container-host0.network',
                '90-container-vb.network',
                '90-container-ve.network',
                '90-container-vz.network',
                '90-vm-vt.network',
                '90-wifi-adhoc.network',
                install_dir : networkdir)

        example_network_files = files(
                '90-auto-link-local.network.example',
                '99-ethernet.network.example',
                '90-wifi-ap.network.example',
                '90-wifi-station.network.example',
        )

        if get_option('default-network')
                foreach f : example_network_files
                        install_data(
                                f,
                                rename : fs.replace_suffix(f, ''),
                                install_dir : networkdir)
                endforeach
        else
                install_data(
                        example_network_files,
                        install_dir : networkdir)
        endif

endif

install_data('99-default.link',
             install_dir : networkdir)

if install_sysconfdir
        install_emptydir(sysconfdir / 'systemd/network')
endif
