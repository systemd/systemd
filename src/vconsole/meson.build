# SPDX-License-Identifier: LGPL-2.1+

if conf.get('ENABLE_VCONSOLE') == 1
        vconsole_rules = configure_file(
                input : '90-vconsole.rules.in',
                output : '90-vconsole.rules',
                configuration : substs)
        install_data(vconsole_rules,
                     install_dir : udevrulesdir)
endif
