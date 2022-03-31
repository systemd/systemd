# SPDX-License-Identifier: LGPL-2.1-or-later

if want_kernel_install
        install_data('kernel-install',
                     install_mode : 'rwxr-xr-x',
                     install_dir : bindir)

        install_data('50-depmod.install',
                     '90-loaderentry.install',
                     install_mode : 'rwxr-xr-x',
                     install_dir : kernelinstalldir)

        install_data('install.conf',
                     install_dir : kerneldir)

        if install_sysconfdir
                meson.add_install_script('sh', '-c',
                                         mkdir_p.format(sysconfdir / 'kernel/install.d'))
        endif

endif
