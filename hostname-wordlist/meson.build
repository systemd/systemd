# SPDX-License-Identifier: LGPL-2.1-or-later

if get_option('hostname-wordlist')
        install_data(
                'adverbs',
                'adjectives',
                'nouns',
                install_dir : libexecdir / 'hostname-wordlist')

        # The '$' hostname tokens look up word lists by position ("1", "2", "3", …); ship those names as
        # symlinks to the semantic lists so the same files back both.
        foreach link : [['1', 'adverbs'], ['2', 'adjectives'], ['3', 'nouns']]
                install_symlink(
                        link[0],
                        install_dir : libexecdir / 'hostname-wordlist',
                        pointing_to : link[1])
        endforeach
endif
