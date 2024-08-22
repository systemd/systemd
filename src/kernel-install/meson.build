# SPDX-License-Identifier: LGPL-2.1-or-later

want_kernel_install = conf.get('ENABLE_KERNEL_INSTALL') == 1

executables += [
        executable_template + {
                'name' : 'kernel-install',
                'public' : true,
                'conditions' : ['ENABLE_KERNEL_INSTALL'],
                'sources' : files('kernel-install.c'),
        },
]

ukify_install = custom_target(
        '60-ukify.install',
        input : '60-ukify.install.in',
        output : '60-ukify.install',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : want_kernel_install and want_ukify,
        install_mode : 'rwxr-xr-x',
        install_dir : kernelinstalldir)

loaderentry_install = custom_target(
        '90-loaderentry.install',
        input : '90-loaderentry.install.in',
        output : '90-loaderentry.install',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : want_kernel_install,
        install_mode : 'rwxr-xr-x',
        install_dir : kernelinstalldir)

uki_copy_install = files('90-uki-copy.install')

kernel_install_files = uki_copy_install + files(
        '50-depmod.install',
)

if want_kernel_install
        install_data(kernel_install_files,
                     install_mode : 'rwxr-xr-x',
                     install_dir : kernelinstalldir)

        install_data('install.conf',
                     install_dir : kerneldir)
 
        install_data('uki.conf',
                     install_dir : kerneldir)

        if install_sysconfdir
                install_emptydir(sysconfdir / 'kernel/install.d')
        endif
endif

test_kernel_install_sh = find_program('test-kernel-install.sh')
