#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Mint the extension-less test certificates embedded in TEST-95-KEYRING-SETUP.unsealed.sh.

The subtests for the serial-number fallback of certificate_description_suffix() need certificates without
a subjectKeyIdentifier extension. OpenSSL's x509 tool adds one to every certificate it signs, no
matter what, so they cannot be produced with it. python-cryptography only adds what is asked for.

The issuing CA pair next to this script was created with
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -subj /CN=keyring-setup-ca -days 36500 \
            -keyout keyring-setup-ca.key -out keyring-setup-ca.crt
and is installed into the trust-anchor hierarchy of the test images by mkosi.finalize. After
rotating the pair, rerun this script and paste the output over the embedded blobs.
"""

import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

here = pathlib.Path(__file__).parent
ca_cert = x509.load_pem_x509_certificate((here / 'keyring-setup-ca.crt').read_bytes())
ca_key = serialization.load_pem_private_key((here / 'keyring-setup-ca.key').read_bytes(), password=None)

for cn, serial in (('noskid', 0x8112131415161718), ('noskid2', 0x11121314)):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(ca_cert.not_valid_before_utc)
        .not_valid_after(ca_cert.not_valid_after_utc)
        .sign(ca_key, hashes.SHA256())
    )
    print(f'# {cn}, serial {serial:#x}')
    print(cert.public_bytes(serialization.Encoding.PEM).decode(), end='')
