# SPDX-License-Identifier: LGPL-2.1-or-later

kernel_install_in = files('kernel-install.in')
loaderentry_install = files('90-loaderentry.install')

if want_kernel_install
        install_data('50-depmod.install',
                     loaderentry_install,
                     install_mode : 'rwxr-xr-x',
                     install_dir : kernelinstalldir)

        install_data('install.conf',
                     install_dir : kerneldir)

        if install_sysconfdir
                meson.add_install_script('sh', '-c',
                                         mkdir_p.format(sysconfdir / 'kernel/install.d'))
        endif

        test_kernel_install_sh = find_program('test-kernel-install.sh')
endif
