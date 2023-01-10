# SPDX-License-Identifier: LGPL-2.1-or-later

efi_arch = {
        'aarch64' : 'aa64',
        'arm'     : 'arm',
        'x86_64'  : 'x64',
        'x86'     : 'ia32',
}.get(host_machine.cpu_family(), '')
if efi_arch != ''
        conf.set_quoted('EFI_MACHINE_TYPE_NAME', efi_arch)
endif

if meson.is_cross_build() and get_option('sbat-distro') == 'auto'
        warning('Auto detection of SBAT information not supported when cross-building, disabling SBAT.')
elif get_option('sbat-distro') != ''
        conf.set_quoted('SBAT_PROJECT', meson.project_name())

        if get_option('sbat-distro-generation') < 1
                error('SBAT Distro Generation must be a positive integer')
        endif
        conf.set('SBAT_DISTRO_GENERATION', get_option('sbat-distro-generation'))

        foreach sbatvar : [['sbat-distro', 'ID'],
                           ['sbat-distro-summary', 'NAME'],
                           ['sbat-distro-url', 'BUG_REPORT_URL']]
                value = get_option(sbatvar[0])
                if (value == '' or value == 'auto') and not meson.is_cross_build()
                        cmd = 'if [ -e /etc/os-release ]; then . /etc/os-release; else . /usr/lib/os-release; fi; echo $@0@'.format(sbatvar[1])
                        value = run_command('sh', '-c', cmd, check: true).stdout().strip()
                endif
                if value == ''
                        error('Required @0@ option not set and autodetection failed'.format(sbatvar[0]))
                endif
                conf.set_quoted(sbatvar[0].underscorify().to_upper(), value)
        endforeach

        pkgname = get_option('sbat-distro-pkgname')
        if pkgname == ''
                pkgname = meson.project_name()
        endif
        conf.set_quoted('SBAT_DISTRO_PKGNAME', pkgname)

        pkgver = get_option('sbat-distro-version')
        if pkgver == ''
                conf.set('SBAT_DISTRO_VERSION', 'GIT_VERSION')
                # This is determined during build, not configuration, so we can't display it yet.
                sbat_distro_version_display = '(git version)'
        else
                conf.set_quoted('SBAT_DISTRO_VERSION', pkgver)
                sbat_distro_version_display = pkgver
        endif

        if conf.get('SBAT_DISTRO', '') != ''
                summary({
                        'SBAT distro':              conf.get('SBAT_DISTRO'),
                        'SBAT distro generation':   conf.get('SBAT_DISTRO_GENERATION'),
                        'SBAT distro version':      sbat_distro_version_display,
                        'SBAT distro summary':      conf.get('SBAT_DISTRO_SUMMARY'),
                        'SBAT distro URL':          conf.get('SBAT_DISTRO_URL')},
                        section : 'UEFI Secure Boot Advanced Targeting (SBAT)')
        endif
endif

subdir_done()

conf.set10('ENABLE_TPM', get_option('tpm'))

foreach ctype : ['color-normal', 'color-entry', 'color-highlight', 'color-edit']
        c = get_option('efi-' + ctype).split(',')
        efi_conf.set(ctype.underscorify().to_upper(), 'EFI_TEXT_ATTR(@0@, @1@)'.format(
                'EFI_' + c[0].strip().underscorify().to_upper(),
                'EFI_' + c[1].strip().underscorify().to_upper()))
endforeach
