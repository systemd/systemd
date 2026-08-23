# SPDX-License-Identifier: LGPL-2.1-or-later

files = [ '20-systemd-varlink.conf' ]

foreach f : files
        install_data(f, install_dir : usertmpfilesdir)
endforeach

if install_sysconfdir
        install_emptydir(sysconfdir / 'user-tmpfiles.d')
endif
