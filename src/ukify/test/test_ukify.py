#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

# pylint: disable=missing-docstring,redefined-outer-name,invalid-name
# pylint: disable=unused-import,import-outside-toplevel,useless-else-on-loop
# pylint: disable=consider-using-with,wrong-import-position,unspecified-encoding

import base64
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

try:
    import pytest
except ImportError:
    sys.exit(77)

try:
    # pyflakes: noqa
    import pefile  # noqa
except ImportError:
    sys.exit(77)

# We import ukify.py, which is a template file. But only __version__ is
# substituted, which we don't care about here. Having the .py suffix makes it
# easier to import the file.
sys.path.append(os.path.dirname(__file__) + '/..')
import ukify


def test_guess_efi_arch():
    arch = ukify.guess_efi_arch()
    assert arch in ukify.EFI_ARCHES

def test_shell_join():
    assert ukify.shell_join(['a', 'b', ' ']) == "a b ' '"

def test_round_up():
    assert ukify.round_up(0) == 0
    assert ukify.round_up(4095) == 4096
    assert ukify.round_up(4096) == 4096
    assert ukify.round_up(4097) == 8192

def test_parse_args_minimal():
    opts = ukify.parse_args('arg1 arg2'.split())
    assert opts.linux == pathlib.Path('arg1')
    assert opts.initrd == [pathlib.Path('arg2')]
    assert opts.os_release in (pathlib.Path('/etc/os-release'),
                               pathlib.Path('/usr/lib/os-release'))

def test_parse_args_many():
    opts = ukify.parse_args(
        ['/ARG1', '///ARG2', '/ARG3 WITH SPACE',
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
         '--signing-engine=ENGINE',
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
    assert opts.initrd == [pathlib.Path('/ARG2'), pathlib.Path('/ARG3 WITH SPACE')]
    assert opts.os_release == 'K1=V1\nK2=V2'
    assert opts.devicetree == pathlib.Path('DDDDTTTT')
    assert opts.splash == pathlib.Path('splash')
    assert opts.pcrpkey == pathlib.Path('PATH')
    assert opts.uname == '1.2.3'
    assert opts.stub == pathlib.Path('STUBPATH')
    assert opts.pcr_private_keys == [pathlib.Path('PKEY1')]
    assert opts.pcr_public_keys == [pathlib.Path('PKEY2')]
    assert opts.pcr_banks == ['SHA1', 'SHA256']
    assert opts.signing_engine == 'ENGINE'
    assert opts.sb_key == 'SBKEY'
    assert opts.sb_cert == 'SBCERT'
    assert opts.sign_kernel is False
    assert opts.tools == [pathlib.Path('TOOLZ/')]
    assert opts.output == pathlib.Path('OUTPUT')
    assert opts.measure is False

def test_parse_sections():
    opts = ukify.parse_args(
        ['/ARG1', '/ARG2',
         '--section=test:TESTTESTTEST',
         '--section=test2:@FILE',
         ])

    assert opts.linux == pathlib.Path('/ARG1')
    assert opts.initrd == [pathlib.Path('/ARG2')]
    assert len(opts.sections) == 2

    assert opts.sections[0].name == 'test'
    assert isinstance(opts.sections[0].content, pathlib.Path)
    assert opts.sections[0].tmpfile
    assert opts.sections[0].measure is False

    assert opts.sections[1].name == 'test2'
    assert opts.sections[1].content == pathlib.Path('FILE')
    assert opts.sections[1].tmpfile is None
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
    try:
        text = subprocess.check_output(['bootctl', 'list', '--json=short'],
                                       text=True)
    except subprocess.CalledProcessError:
        return None

    items = json.loads(text)

    for item in items:
        try:
            linux = f"{item['root']}{item['linux']}"
            initrd = f"{item['root']}{item['initrd'][0]}"
        except (KeyError, IndexError):
            continue
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
        '--section=.test:CONTENTZ',
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

def test_addon(kernel_initrd, tmpdir):
    output = f'{tmpdir}/addon.efi'
    opts = ukify.parse_args([
        f'--output={output}',
        '--cmdline=ARG1 ARG2 ARG3',
        '--section=.test:CONTENTZ',
    ])

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that objdump likes the resulting file
    dump = subprocess.check_output(['objdump', '-h', output], text=True)

    for sect in 'text cmdline test'.split():
        assert re.search(fr'^\s*\d+\s+.{sect}\s+0', dump, re.MULTILINE)


def unbase64(filename):
    tmp = tempfile.NamedTemporaryFile()
    base64.decode(filename.open('rb'), tmp)
    tmp.flush()
    return tmp


def test_uname_scraping(kernel_initrd):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')

    uname = ukify.Uname.scrape(kernel_initrd[0])
    assert re.match(r'\d+\.\d+\.\d+', uname)

def test_efi_signing(kernel_initrd, tmpdir):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    if not shutil.which('sbsign'):
        pytest.skip('sbsign not found')

    ourdir = pathlib.Path(__file__).parent
    cert = unbase64(ourdir / 'example.signing.crt.base64')
    key = unbase64(ourdir / 'example.signing.key.base64')

    output = f'{tmpdir}/signed.efi'
    opts = ukify.parse_args([
        *kernel_initrd,
        f'--output={output}',
        '--uname=1.2.3',
        '--cmdline=ARG1 ARG2 ARG3',
        f'--secureboot-certificate={cert.name}',
        f'--secureboot-private-key={key.name}',
    ])

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    if shutil.which('sbverify'):
        # let's check that sbverify likes the resulting file
        dump = subprocess.check_output([
            'sbverify',
            '--cert', cert.name,
            output,
        ], text=True)

        assert 'Signature verification OK' in dump

def test_pcr_signing(kernel_initrd, tmpdir):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    if os.getuid() != 0:
        pytest.skip('must be root to access tpm2')
    if subprocess.call(['systemd-creds', 'has-tpm2', '-q']) != 0:
        pytest.skip('tpm2 is not available')

    ourdir = pathlib.Path(__file__).parent
    pub = unbase64(ourdir / 'example.tpm2-pcr-public.pem.base64')
    priv = unbase64(ourdir / 'example.tpm2-pcr-private.pem.base64')

    output = f'{tmpdir}/signed.efi'
    opts = ukify.parse_args([
        *kernel_initrd,
        f'--output={output}',
        '--uname=1.2.3',
        '--cmdline=ARG1 ARG2 ARG3',
        '--os-release=ID=foobar\n',
        '--pcr-banks=sha1',   # use sha1 as that is most likely to be supported
        f'--pcrpkey={pub.name}',
        f'--pcr-public-key={pub.name}',
        f'--pcr-private-key={priv.name}',
    ])

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that objdump likes the resulting file
    dump = subprocess.check_output(['objdump', '-h', output], text=True)

    for sect in 'text osrel cmdline linux initrd uname pcrsig'.split():
        assert re.search(fr'^\s*\d+\s+.{sect}\s+0', dump, re.MULTILINE)

    # objcopy fails when called without an output argument (EPERM).
    # It also fails when called with /dev/null (file truncated).
    # It also fails when called with /dev/zero (because it reads the
    # output file, infinitely in this case.)
    # So let's just call it with a dummy output argument.
    subprocess.check_call([
        'objcopy',
        *(f'--dump-section=.{n}={tmpdir}/out.{n}' for n in (
            'pcrpkey', 'pcrsig', 'osrel', 'uname', 'cmdline')),
        output,
        tmpdir / 'dummy',
    ],
        text=True)

    assert open(tmpdir / 'out.pcrpkey').read() == open(pub.name).read()
    assert open(tmpdir / 'out.osrel').read() == 'ID=foobar\n'
    assert open(tmpdir / 'out.uname').read() == '1.2.3'
    assert open(tmpdir / 'out.cmdline').read() == 'ARG1 ARG2 ARG3'
    sig = open(tmpdir / 'out.pcrsig').read()
    sig = json.loads(sig)
    assert list(sig.keys()) == ['sha1']
    assert len(sig['sha1']) == 4   # four items for four phases

def test_pcr_signing2(kernel_initrd, tmpdir):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    if os.getuid() != 0:
        pytest.skip('must be root to access tpm2')
    if subprocess.call(['systemd-creds', 'has-tpm2', '-q']) != 0:
        pytest.skip('tpm2 is not available')

    ourdir = pathlib.Path(__file__).parent
    pub = unbase64(ourdir / 'example.tpm2-pcr-public.pem.base64')
    priv = unbase64(ourdir / 'example.tpm2-pcr-private.pem.base64')
    pub2 = unbase64(ourdir / 'example.tpm2-pcr-public2.pem.base64')
    priv2 = unbase64(ourdir / 'example.tpm2-pcr-private2.pem.base64')

    # simulate a microcode file
    with open(f'{tmpdir}/microcode', 'wb') as microcode:
        microcode.write(b'1234567890')

    output = f'{tmpdir}/signed.efi'
    opts = ukify.parse_args([
        kernel_initrd[0], microcode.name, kernel_initrd[1],
        f'--output={output}',
        '--uname=1.2.3',
        '--cmdline=ARG1 ARG2 ARG3',
        '--os-release=ID=foobar\n',
        '--pcr-banks=sha1',   # use sha1 as that is most likely to be supported
        f'--pcrpkey={pub2.name}',
        f'--pcr-public-key={pub.name}',
        f'--pcr-private-key={priv.name}',
        '--phases=enter-initrd enter-initrd:leave-initrd',
        f'--pcr-public-key={pub2.name}',
        f'--pcr-private-key={priv2.name}',
        '--phases=sysinit ready shutdown final',  # yes, those phase paths are not reachable
    ])

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that objdump likes the resulting file
    dump = subprocess.check_output(['objdump', '-h', output], text=True)

    for sect in 'text osrel cmdline linux initrd uname pcrsig'.split():
        assert re.search(fr'^\s*\d+\s+.{sect}\s+0', dump, re.MULTILINE)

    subprocess.check_call([
        'objcopy',
        *(f'--dump-section=.{n}={tmpdir}/out.{n}' for n in (
            'pcrpkey', 'pcrsig', 'osrel', 'uname', 'cmdline', 'initrd')),
        output,
        tmpdir / 'dummy',
    ],
        text=True)

    assert open(tmpdir / 'out.pcrpkey').read() == open(pub2.name).read()
    assert open(tmpdir / 'out.osrel').read() == 'ID=foobar\n'
    assert open(tmpdir / 'out.uname').read() == '1.2.3'
    assert open(tmpdir / 'out.cmdline').read() == 'ARG1 ARG2 ARG3'
    assert open(tmpdir / 'out.initrd', 'rb').read(10) == b'1234567890'

    sig = open(tmpdir / 'out.pcrsig').read()
    sig = json.loads(sig)
    assert list(sig.keys()) == ['sha1']
    assert len(sig['sha1']) == 6   # six items for six phases paths

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
