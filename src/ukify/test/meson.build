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

        test('test-ukify',
             files('test_ukify.py'),
             args: args,
             env : test_env + {'EFI_ADDON' : efi_addon.length() > 0 ? efi_addon[0].full_path() : ''},
             timeout : 120,
             suite : 'ukify',
             depends : efi_addon)
endif
