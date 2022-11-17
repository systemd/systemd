# SPDX-License-Identifier: LGPL-2.1-or-later

if get_option('ukify')
        install_data(
                'ukify.py',
                rename : 'ukify',
                install_mode : 'rwxr-xr-x',
                install_dir : rootlibexecdir)

        if want_tests != 'false' and get_option('efi')
                test('test-ukify',
                     files('test_ukify.py'),
                     env : test_env)
        endif
endif
