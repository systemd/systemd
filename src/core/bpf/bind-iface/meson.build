# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('BPF_FRAMEWORK') != 1
        subdir_done()
endif

bind_network_interface_bpf_o_unstripped = custom_target(
        input : 'bind-iface.bpf.c',
        output : 'bind-iface.bpf.unstripped.o',
        command : bpf_o_unstripped_cmd)

bind_network_interface_bpf_o = custom_target(
        input : bind_network_interface_bpf_o_unstripped,
        output : 'bind-iface.bpf.o',
        command : bpf_o_cmd)

bind_network_interface_skel_h = custom_target(
        input : bind_network_interface_bpf_o,
        output : 'bind-iface.skel.h',
        command : skel_h_cmd,
        capture : true)

generated_sources += bind_network_interface_skel_h
