#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+

# pylint: disable=missing-docstring,redefined-outer-name,invalid-name
# pylint: disable=unused-import,import-outside-toplevel,useless-else-on-loop

import json
import os
import pathlib
import re
import subprocess
import sys

try:
    import pytest
except ImportError:
    sys.exit(77)

import ukify

def test_guess_efi_arch():
    arch = ukify.guess_efi_arch()
    assert arch in ukify.EFI_ARCHES

def test_shell_join():
    assert ukify.shell_join(['a', 'b', ' ']) == "a b ' '"

def test_round_to_page():
    assert ukify.round_to_page(0) == 0
    assert ukify.round_to_page(4095) == 4096
    assert ukify.round_to_page(4096) == 4096
    assert ukify.round_to_page(4097) == 8192

def test_parse_args_minimal():
    opts = ukify.parse_args('arg1 arg2'.split())
    assert opts.linux == pathlib.Path('arg1')
    assert opts.initrd == pathlib.Path('arg2')
    assert opts.os_release in (pathlib.Path('/etc/os-release'),
                               pathlib.Path('/usr/lib/os-release'))

def test_parse_args_many():
    opts = ukify.parse_args(
        ['/ARG1', '///ARG2',
         '--cmdline=a b c',
         '--os-release=K1=V1\nK2=V2',
         '--devicetree=DDDDTTTT',
         '--splash=splash',
         '--pcrpkey=PATH',
         '--uname=1.2.3',
         '--stub=STUBPATH',
         '--pcr-private-key=PKEY1',
         '--pcr-public-key=PKEY2',
         '--pcr-banks=SHA1,SHA256',
         '--secureboot-engine=ENGINE',
         '--secureboot-private-key=SBKEY',
         '--secureboot-certificate=SBCERT',
         '--sign-kernel',
         '--no-sign-kernel',
         '--tools=TOOLZ///',
         '--output=OUTPUT',
         '--measure',
         '--no-measure',
         ])
    assert opts.linux == pathlib.Path('/ARG1')
    assert opts.initrd == pathlib.Path('/ARG2')
    assert opts.os_release == 'K1=V1\nK2=V2'
    assert opts.devicetree == pathlib.Path('DDDDTTTT')
    assert opts.splash == pathlib.Path('splash')
    assert opts.pcrpkey == pathlib.Path('PATH')
    assert opts.uname == '1.2.3'
    assert opts.stub == pathlib.Path('STUBPATH')
    assert opts.pcr_private_key == pathlib.Path('PKEY1')
    assert opts.pcr_public_key == pathlib.Path('PKEY2')
    assert opts.pcr_banks == ['SHA1', 'SHA256']
    assert opts.sb_engine == 'ENGINE'
    assert opts.sb_key == 'SBKEY'
    assert opts.sb_cert == 'SBCERT'
    assert opts.sign_kernel is False
    assert opts.tools == pathlib.Path('TOOLZ/')
    assert opts.output == pathlib.Path('OUTPUT')
    assert opts.measure is False

def test_parse_sections():
    opts = ukify.parse_args(
        ['/ARG1', '/ARG2',
         '--section=test:TESTTESTTEST',
         '--section=test2:@FILE',
         ])

    assert opts.linux == pathlib.Path('/ARG1')
    assert opts.initrd == pathlib.Path('/ARG2')
    assert len(opts.sections) == 2

    assert opts.sections[0].name == 'test'
    assert isinstance(opts.sections[0].content, pathlib.Path)
    assert opts.sections[0].tmpfile
    assert opts.sections[0].offset is None
    assert opts.sections[0].measure is False

    assert opts.sections[1].name == 'test2'
    assert opts.sections[1].content == pathlib.Path('FILE')
    assert opts.sections[1].tmpfile is None
    assert opts.sections[1].offset is None
    assert opts.sections[1].measure is False

def test_help(capsys):
    with pytest.raises(SystemExit):
        ukify.parse_args(['--help'])
    out = capsys.readouterr()
    assert '--section' in out.out
    assert not out.err

def test_help_error(capsys):
    with pytest.raises(SystemExit):
        ukify.parse_args(['a', 'b', '--no-such-option'])
    out = capsys.readouterr()
    assert not out.out
    assert '--no-such-option' in out.err
    assert len(out.err.splitlines()) == 1

@pytest.fixture(scope='session')
def kernel_initrd():
    text = subprocess.check_output(['bootctl', 'list', '--json=short'],
                                   text=True)
    items = json.loads(text)

    for item in items:
        try:
            linux = f"{item['root']}{item['linux']}"
            initrd = f"{item['root']}{item['initrd'][0]}"
        except (KeyError, IndexError):
            pass
        return [linux, initrd]
    else:
        return None

def test_check_splash():
    try:
        # pyflakes: noqa
        import PIL  # noqa
    except ImportError:
        pytest.skip('PIL not available')

    with pytest.raises(OSError):
        ukify.check_splash(os.devnull)

def test_basic_operation(kernel_initrd, tmpdir):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')

    output = f'{tmpdir}/basic.efi'
    opts = ukify.parse_args(kernel_initrd + [f'--output={output}'])
    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that objdump likes the resulting file
    subprocess.check_output(['objdump', '-h', output])

def test_sections(kernel_initrd, tmpdir):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')

    output = f'{tmpdir}/basic.efi'
    opts = ukify.parse_args([
        *kernel_initrd,
        f'--output={output}',
        '--uname=1.2.3',
        '--cmdline=ARG1 ARG2 ARG3',
        '--os-release=K1=V1\nK2=V2\n',
        '--section=test:CONTENTZ',
    ])

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that objdump likes the resulting file
    dump = subprocess.check_output(['objdump', '-h', output], text=True)

    for sect in 'text osrel cmdline linux initrd uname test'.split():
        assert re.search(fr'^\s*\d+\s+.{sect}\s+0', dump, re.MULTILINE)

def test_signing(kernel_initrd, tmpdir):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')

    ourdir = pathlib.Path(__file__).parent
    cert = ourdir / 'signing.crt'
    key = ourdir / 'signing.key'

    output = f'{tmpdir}/signed.efi'
    opts = ukify.parse_args([
        *kernel_initrd,
        f'--output={output}',
        '--uname=1.2.3',
        '--cmdline=ARG1 ARG2 ARG3',
        f'--secureboot-certificate={cert}',
        f'--secureboot-private-key={key}',
    ])

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that sbverify likes the resulting file
    dump = subprocess.check_output([
        'sbverify',
        '--cert', cert,
        output,
    ], text=True)

    assert 'Signature verification OK' in dump

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
