# SPDX-License-Identifier: LGPL-2.1-or-later

if want_ukify and want_tests != 'false'
        have_pytest_flakes = pymod.find_installation(
                'python3',
                required : false,
                modules : ['pytest_flakes'],
        ).found()

        args = ['-v']
        if have_pytest_flakes
                args += ['--flakes']
        endif

        efi_addon_for_test = ''
        if not meson.is_cross_build() and efi_addon.length() > 0
                efi_addon_for_test = efi_addon[0].full_path()
        endif

        test('test-ukify',
             files('test_ukify.py'),
             args: args,
             env : test_env + {'EFI_ADDON' : efi_addon_for_test},
             timeout : 120,
             suite : 'ukify',
             depends : efi_addon)
endif
