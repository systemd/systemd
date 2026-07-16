#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test report signing through the TPM2 backend (systemd-report-sign-tpm2), driven
# via the io.systemd.Report Varlink interface (the GenerateSigned method). This is
# the TPM2 counterpart to the plain software backend test in
# TEST-74-AUX-UTILS.report.sh; it lives here because it needs a real TPM, which
# only the TPM2 integration test provides.
#
# The TPM2 backend returns a set of signed TPM attestations (a PCR quote, one
# NV certification per NvPCR, and a session audit digest), together with the
# signing key's public area and the pcrlock event log. The public area, the
# attestations and the signatures are all serialized as TCG TSS2 JSON. For each
# attestation we rebuild the public key, re-marshal the TPMS_ATTEST that was
# signed, and verify the signature using the embedded Python helper below. The
# helper also cross-checks the parallel PEM encodings (publicKeyPEM and signaturePEM)
# against the JSON encodings. We also confirm the report digest is carried in the
# extraData field of the session audit attestation.
#
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug
# Unset $PAGER so we don't have to use --no-pager everywhere
export PAGER=

# The TPM2 backend is only built/installed with OpenSSL and TPM2 support, so
# skip if the socket isn't present.
if ! systemctl cat systemd-report-sign-tpm2.socket &>/dev/null; then
    echo "systemd-report-sign-tpm2.socket is not installed, skipping TPM2 report signing test."
    exit 0
fi

# We create the EK with tpm2-tools.
if ! command -v tpm2_createek >/dev/null; then
    echo "tpm2-tools not installed, skipping TPM2 report signing test."
    exit 0
fi

# The attestation signatures are verified with the embedded Python helper below,
# which uses the cryptography module.
if ! python3 -c "import cryptography" >/dev/null 2>&1; then
    echo "python3 cryptography module not available, skipping TPM2 report signing test."
    exit 0
fi

WORK="$(mktemp -d)"

at_exit() {
    set +e
    systemctl stop systemd-report.socket systemd-report-sign-tpm2.socket
    rm -rf "$WORK"
}
trap at_exit EXIT

# The TPM2 backend creates its signing key as a child of the TPM's endorsement
# key. In a QEMU/swtpm guest there is no EK certificate, and the backend only
# provisions an EK when a matching certificate is present. Create and persist
# an EK directly. This fails if one already is already present, so ignore that.
if ! tpm2_createek -c 0x81010001 -G ecc; then
    echo "tpm2_createek failed, assuming an EK is already present."
fi

# The TPM2 backend reads the event log from pcrlock's Varlink interface, so make
# sure its socket is up.
systemctl start systemd-pcrlock.socket

systemctl start systemd-report.socket
systemctl start systemd-report-sign-tpm2.socket

# Ask systemd-report to generate a *signed* report over Varlink. The reply
# carries the signed report as base64-encoded JSON-SEQ data.
varlinkctl call /run/systemd/io.systemd.Report io.systemd.Report.GenerateSigned \
    '{"matches":["io.systemd.Manager.UnitsTotal"]}' | jq -r .reportData | base64 -d >"$WORK/report.seq"

# The first JSON-SEQ record is the report itself. This is exactly the byte
# sequence that got signed, including the leading record separator (0x1e) and
# the trailing newline, so 'head -n1' reproduces it verbatim.
head -n1 "$WORK/report.seq" >"$WORK/message.bin"
tr -d '\036' <"$WORK/message.bin" | jq -e '.mediaType == "application/vnd.io.systemd.report"' >/dev/null

# The remaining record(s) are signature objects, one per enabled backend. Pick
# out the one produced by the TPM2 backend (the plain backend may be enabled too).
sig_json=""
while IFS= read -r line; do
    rec="$(echo "$line" | tr -d '\036')"
    [[ -n "$rec" ]] || continue
    if [[ "$(echo "$rec" | jq -r '.mechanism // empty')" == "tpm2" ]]; then
        sig_json="$rec"
    fi
done < <(tail -n +2 "$WORK/report.seq")
test -n "$sig_json"

[ "$(echo "$sig_json" | jq -r .mediaType)" = "application/vnd.io.systemd.report.signature" ]

# The sha256 recorded in the signature must match the digest of the report bytes.
report_digest="$(sha256sum "$WORK/message.bin" | cut -d' ' -f1)"
[ "$(echo "$sig_json" | jq -r .sha256)" = "$report_digest" ]

# Use a python script for verifying the report component signatures because we
# need to reconstruct the TPM2B_ATTEST bytes from the provided TPMS_ATTEST JSON
# encoding, and construct a public key from the provided TPMT_PUBLIC JSON encoding.
VERIFY="$WORK/verify-report-sig.py"
cat >"$VERIFY" <<'EOF'
#!/usr/bin/env python3
"""Verify systemd TPM report signatures."""

import base64
import json
import struct
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

HASH_ALG_ID = {"SHA1": 0x0004, "SHA256": 0x000b, "SHA384": 0x000c, "SHA512": 0x000d}
SIG_ALG_ID = {"RSASSA": 0x0014, "RSAPSS": 0x0016, "ECDSA": 0x0018, "NULL": 0x0010}
PUB_ALG_ID = {"RSA": 0x0001, "ECC": 0x0023}
CURVE_ID = {"NIST_P192": 0x0001, "NIST_P224": 0x0002, "NIST_P256": 0x0003,
            "NIST_P384": 0x0004, "NIST_P521": 0x0005, "BN_P256": 0x0010,
            "BN_P638": 0x0011, "SM2_P256": 0x0020}
ST_ATTEST = {"ATTEST_NV": 0x8014, "ATTEST_SESSION_AUDIT": 0x8016, "ATTEST_QUOTE": 0x8018}
TPM_GENERATED = 0xff544347
ALG_NULL = 0x0010
CC_QUOTE = 0x00000158
CC_NV_CERTIFY = 0x00000184

HASHES = {"SHA1": hashes.SHA1, "SHA256": hashes.SHA256,
          "SHA384": hashes.SHA384, "SHA512": hashes.SHA512}
CURVES = {"NIST_P192": ec.SECP192R1, "NIST_P224": ec.SECP224R1, "NIST_P256": ec.SECP256R1,
          "NIST_P384": ec.SECP384R1, "NIST_P521": ec.SECP521R1}


def hash(alg, data):
    """Digest the supplied data using the specific TPM2 digest algorithm."""
    h = hashes.Hash(HASHES[alg]())
    h.update(data)
    return h.finalize()


def sha256(data):
    """Digest the supplied data using SHA-256."""
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


# Helpers to serialize JSON encodings to the TPM wire format.

def marshal_u8(v):
    return struct.pack(">B", v)


def marshal_u16(v):
    return struct.pack(">H", v)


def marshal_u32(v):
    return struct.pack(">I", v)


def marshal_u64(v):
    return struct.pack(">Q", v)


def marshal_hex_tpm2b(h):
    """Serialize the supplied hex string as a TPM2B_ type."""
    b = bytes.fromhex(h) if h else b""
    return marshal_u16(len(b)) + b


def marshal_bytes_tpm2b(b):
    """Serialize the supplied raw bytes as a TPM2B_ type."""
    return marshal_u16(len(b)) + b


def marshal_tpml_pcr_selection(sel_list):
    """Serialize the supplied JSON encoded TPML_PCR_SELECTION to its wire form."""
    out = marshal_u32(len(sel_list))
    for s in sel_list:
        pcrs = s["pcrSelect"]
        # The TSS2 JSON format doesn't include the sizeOfSelect field, so we
        # reconstruct it here based on the maximum PCR, and assuming that the
        # value of TPM_PT_PCR_SELECT_MIN is 3.
        size = max(3, (max(pcrs) // 8 + 1) if pcrs else 0)
        bm = bytearray(size)
        for p in pcrs:
            bm[p // 8] |= 1 << (p % 8)
        out += marshal_u16(HASH_ALG_ID[s["hash"]]) + marshal_u8(size) + bytes(bm)
    return out


def marshal_tpms_attest(att):
    """Serialize the supplied JSON encoded TPMS_ATTEST structure to its wire form."""
    out = marshal_u32(TPM_GENERATED) # .magic
    out += marshal_u16(ST_ATTEST[att["type"]])
    out += marshal_hex_tpm2b(att.get("qualifiedSigner", ""))
    out += marshal_hex_tpm2b(att.get("extraData", ""))

    # .clockInfo
    ci = att["clockInfo"]
    out += marshal_u64(ci["clock"])
    out += marshal_u32(ci["resetCount"] & 0xffffffff)
    out += marshal_u32(ci["restartCount"] & 0xffffffff)
    out += marshal_u8(1 if ci["safe"] == "YES" else 0)

    out += marshal_u64(att["firmwareVersion"])

    # .attested
    a, t = att["attested"], att["type"]
    if t == "ATTEST_QUOTE":
        out += marshal_tpml_pcr_selection(a["pcrSelect"])
        out += marshal_hex_tpm2b(a["pcrDigest"])
    elif t == "ATTEST_NV":
        out += marshal_hex_tpm2b(a["indexName"])
        out += marshal_u16(a["offset"] & 0xffff)
        out += marshal_hex_tpm2b(a["nvContents"])
    elif t == "ATTEST_SESSION_AUDIT":
        out += marshal_u8(1 if a["exclusiveSession"] == "YES" else 0)
        out += marshal_hex_tpm2b(a["sessionDigest"])
    else:
        sys.exit(f"unsupported attest type {t}")
    return out


def marshal_tpms_nv_public(nv):
    """Serialize the supplied JSON encoded TPMS_NV_PUBLIC to its wire form."""
    out = marshal_u32(nv["nvIndex"] & 0xffffffff)
    out += marshal_u16(HASH_ALG_ID[nv["nameAlg"]])
    out += marshal_u32(nv["attributes"] & 0xffffffff)
    out += marshal_hex_tpm2b(nv.get("authPolicy", ""))
    out += marshal_u16(nv["dataSize"] & 0xffff)
    return out


def digest_bytes_and_marshal_tpmt_ha(alg, data):
    """Digest the suppied data using the specified algorithm and serialize it
    as a TPMT_HA structure in its wire form."""
    return marshal_u16(HASH_ALG_ID[alg]) + hash(alg, data)


def marshal_tpmt_public(pub):
    """Serialize the supplied JSON encoded TPMT_PUBLIC structure to its wire form."""
    typ = pub["type"]

    out = marshal_u16(PUB_ALG_ID[typ])
    out += marshal_u16(HASH_ALG_ID[pub["nameAlg"]])
    out += marshal_u32(pub["objectAttributes"] & 0xffffffff)
    out += marshal_hex_tpm2b(pub.get("authPolicy", ""))

    # .parameters
    parms = pub["parameters"]
    out += marshal_u16(ALG_NULL)                              # .parameters.symmetric.algorithm = TPM_ALG_NULL
    out += marshal_u16(SIG_ALG_ID[parms["scheme"]["scheme"]])
    if parms["scheme"]["scheme"] != "NULL":
        out += marshal_u16(HASH_ALG_ID[parms["scheme"]["details"]["hashAlg"]])
    if typ == "RSA":
        out += marshal_u16(parms["keyBits"] & 0xffff)
        out += marshal_u32(parms["exponent"] & 0xffffffff)
    elif typ == "ECC":
        out += marshal_u16(CURVE_ID[parms["curveID"]])
        out += marshal_u16(ALG_NULL)                    # .parameters.eccDetail.kdf.scheme = TPM_ALG_NULL
    else:
        sys.exit(f"unsupported key type {typ}")

    # .unique
    if typ == "RSA":
        out += marshal_hex_tpm2b(pub["unique"])
    elif typ == "ECC":
        out += marshal_hex_tpm2b(pub["unique"]["x"])
        out += marshal_hex_tpm2b(pub["unique"]["y"])
    else:
        sys.exit(f"unsupported key type {typ}")

    return out


def marshal_tpmt_signature(sig):
    """Serialize the supplied JSON encoded TPMT_SIGNATURE structure to its wire form."""
    alg, s = sig["sigAlg"], sig["signature"]

    out = marshal_u16(SIG_ALG_ID[alg])         # .sigAlg
    out += marshal_u16(HASH_ALG_ID[s["hash"]]) # .siganture.any.hashAlg
    if alg in ("RSASSA", "RSAPSS"):
        return out + marshal_hex_tpm2b(s["sig"])
    if alg == "ECDSA":
        return out + marshal_hex_tpm2b(s["signatureR"]) + marshal_hex_tpm2b(s["signatureS"])
    sys.exit(f"unsupported sigAlg {alg}")


def build_pubkey(pub):
    """Build a public key from the supplied JSON encoded TPMT_PUBLIC structure."""
    if pub["type"] == "RSA":
        e = pub["parameters"]["exponent"] or 65537
        return rsa.RSAPublicNumbers(e, int(pub["unique"], 16)).public_key()
    if pub["type"] == "ECC":
        curve = CURVES[pub["parameters"]["curveID"]]()
        return ec.EllipticCurvePublicNumbers(
            int(pub["unique"]["x"], 16), int(pub["unique"]["y"], 16), curve).public_key()
    sys.exit(f"unsupported key type {pub['type']}")


def json_signature_bytes(sig):
    """Serialize a signature from the supplied JSON encoded TPMT_SIGNATURE structure."""
    alg, s = sig["sigAlg"], sig["signature"]

    if alg in ("RSASSA", "RSAPSS"):
        return bytes.fromhex(s["sig"]), "RSA SIGNATURE"
    if alg == "ECDSA":
        sr, ss = int(s["signatureR"], 16), int(s["signatureS"], 16)
        return encode_dss_signature(sr, ss), "ECDSA SIGNATURE"
    sys.exit(f"unsupported sigAlg {alg}")


def pem_to_der(pem, label):
    """Convert the supplied PEM structure to DER."""
    begin, end = f"-----BEGIN {label}-----", f"-----END {label}-----"
    lines = [ln for ln in pem.strip().splitlines() if ln]
    if not lines or lines[0] != begin or lines[-1] != end:
        sys.exit(f"unexpected PEM envelope, wanted {label!r}")
    return base64.b64decode("".join(lines[1:-1]))


def verify(key, scheme, sig_bytes, message):
    alg = scheme["scheme"]
    h = HASHES[scheme["details"]["hashAlg"]]()
    if alg == "RSASSA":
        key.verify(sig_bytes, message, padding.PKCS1v15(), h)
    elif alg == "RSAPSS":
        key.verify(sig_bytes, message,
                   padding.PSS(mgf=padding.MGF1(h), salt_length=padding.PSS.AUTO), h)
    elif alg == "ECDSA":
        key.verify(sig_bytes, message, ec.ECDSA(h))
    else:
        sys.exit(f"unsupported scheme {alg}")


def check_nvpcr(i, comp):
    """Check the properties of the nvpcr component."""
    nv = comp["nvPublic"]
    att = comp["attestInfo"]["attest"]

    # Make sure that nvPublic is consistent with the indexName in the attestation.
    name = digest_bytes_and_marshal_tpmt_ha(nv["nameAlg"], marshal_tpms_nv_public(nv))
    if name != bytes.fromhex(att["attested"]["indexName"]):
        sys.exit(f"component {i}: nvPublic Name does not match attested indexName")

    # Make sure that the authenticatedData is consistent with the extraData in
    # the attestation.
    extra = digest_bytes_and_marshal_tpmt_ha(nv["nameAlg"], comp["authenticatedData"].encode())
    if extra != bytes.fromhex(att["extraData"]):
        sys.exit(f"component {i}: authenticatedData digest does not match attested extraData")


def check_session_audit(doc, key_name):
    """Check the properties of the session-audit component."""
    digest = b"\x00" * 32 # Starting audit digest

    reported = None
    for comp in doc["components"]:
        # Determine the command code, command handle names and cpBytes.
        att = comp["attestInfo"]["attest"]
        t = comp["type"]
        if t == "pcr":
            cc = CC_QUOTE
            names = key_name                                               # signHandle only
            cp = marshal_hex_tpm2b("")                                     # qualifyingData
            cp += marshal_u16(ALG_NULL)                                    # inScheme.scheme
            cp += marshal_tpml_pcr_selection(att["attested"]["pcrSelect"]) # pcrSelect
        elif t == "nvcpr":
            cc = CC_NV_CERTIFY
            nv_name = digest_bytes_and_marshal_tpmt_ha(comp["nvPublic"]["nameAlg"], marshal_tpms_nv_public(comp["nvPublic"]))
            # Handle area is signHandle, authHandle, nvIndex - we pass the NV index for both
            # the authHandle and nvIndex.
            names = key_name + nv_name + nv_name
            cp = marshal_hex_tpm2b(att["extraData"])        # qualifyingData
            cp += marshal_u16(ALG_NULL)                     # inScheme.scheme
            cp += marshal_u16(comp["nvPublic"]["dataSize"]) # size
            cp += marshal_u16(0)                            # offset
        elif t == "session-audit":
            reported = att["attested"]["sessionDigest"]
            continue                                    # not audited itself
        else:
            sys.exit(f"unsupported component type {t}")

        # Calculate rpBytes.
        rp = marshal_bytes_tpm2b(marshal_tpms_attest(att)) # TPM2B_ATTEST out
        rp += marshal_tpmt_signature(comp["signature"])    # signature

        # Calculate cpHash and rpHash.
        cp_hash = sha256(marshal_u32(cc) + names + cp)
        rp_hash = sha256(marshal_u32(0) + marshal_u32(cc) + rp)

        # Extend the audit digest.
        digest = sha256(digest + cp_hash + rp_hash)

    if reported is None:
        sys.exit("no session audit component present")
    if digest.hex() != reported:
        sys.exit("session audit digest does not match the audited command sequence")


def main():
    report_digest = sys.argv[1]

    full = json.load(sys.stdin)
    data = full["data"]

    # Rebuild the key from the JSON public area.
    key_json = build_pubkey(data["publicKey"])

    # Also load the PEM encoded public key, and make sure they're the same.
    key_pem = serialization.load_pem_public_key(data["publicKeyPEM"].encode())
    if key_json.public_numbers() != key_pem.public_numbers():
        sys.exit("publicKeyPEM does not match the JSON public key")

    saw_report_binding = False
    for i, comp in enumerate(data["components"]):
        scheme = comp["attestInfo"]["sig_scheme"]
        message = marshal_tpms_attest(comp["attestInfo"]["attest"])

        sig = comp["signature"]

        # Make sure that the signature scheme in the attestInfo matches the
        # information in the JSON encoded signature.
        if scheme["scheme"] != sig["sigAlg"] or scheme["details"]["hashAlg"] != sig["signature"]["hash"]:
            sys.exit(f"component {i}: signature scheme inconsistent with signature")

        # Reconstruct the signature from the JSON fields and decode the parallel
        # signaturePEM blob. They should be the same.
        sig_json, label = json_signature_bytes(sig)
        sig_pem = pem_to_der(comp["signaturePEM"], label)
        if sig_pem != sig_json:
            sys.exit(f"component {i}: signaturePEM does not match the JSON signature")

        # Verify using the PEM-loaded key and PEM-decoded signature.
        try:
            verify(key_pem, scheme, sig_pem, message)
        except InvalidSignature:
            sys.exit(f"component {i} ({comp['type']}): signature verification FAILED")

        if comp["type"] == "nvcpr":
            check_nvpcr(i, comp)
        elif comp["type"] == "session-audit":
            # The report digest passed to the signer is the session audit's
            # qualifying data, so it appears as extraData prefixed with the SHA256
            # algorithm id.
            extra = bytes.fromhex(comp["attestInfo"]["attest"]["extraData"])
            if extra != marshal_u16(HASH_ALG_ID["SHA256"]) + bytes.fromhex(report_digest):
                sys.exit(f"component {i}: session audit extraData does not match the report digest")
            saw_report_binding = True

        print(comp["type"])

    if not saw_report_binding:
        sys.exit("no session audit component bound the report digest")

    # The session audit digest must reproduce the audited command sequence that
    # produced the other components.
    key_name = digest_bytes_and_marshal_tpmt_ha(data["publicKey"]["nameAlg"], marshal_tpmt_public(data["publicKey"]))
    check_session_audit(data, key_name)


if __name__ == "__main__":
    main()
EOF

n_components="$(echo "$sig_json" | jq '.data.components | length')"
[ "$n_components" -gt 0 ]

# The backend attests every defined NvPCR. Fetch them via systemd-analyze so we
# know how many components to expect and can cross-check each one's name, index
# and priority below. Columns: name, nvindex (an unsigned integer), priority.
nvpcrs_json="$(systemd-analyze nvpcrs --json=short)"
expected_nvpcrs="$(echo "$nvpcrs_json" | jq 'length')"
[ "$expected_nvpcrs" -gt 0 ]

# Verify every component signature and collect the component types.
echo "$sig_json" | python3 "$VERIFY" "$report_digest" >"$WORK/component-types"
mapfile -t comp_types <"$WORK/component-types"
[ "${#comp_types[@]}" -eq "$n_components" ]

saw_pcr=0
saw_audit=0
n_nvpcr=0

for i in "${!comp_types[@]}"; do
    type="${comp_types[$i]}"
    comp="$(echo "$sig_json" | jq -c ".data.components[$i]")"

    case "$type" in
        pcr)
            saw_pcr=1
            ;;
        nvcpr)
            n_nvpcr=$((n_nvpcr + 1))

            # NvPCR components carry the readable name, the serialized NV public
            # area, and the authenticated data digested into the attestation's
            # qualifying data. Ensure they're populated.
            name="$(echo "$comp" | jq -r '.["nvpcrName"] // empty')"
            [ -n "$name" ]
            [ -n "$(echo "$comp" | jq -r '.["nvPublic"] // empty')" ]
            [ -n "$(echo "$comp" | jq -r '.["authenticatedData"] // empty')" ]

            # The name must be one systemd-analyze knows about.
            expected_nvpcr="$(echo "$nvpcrs_json" | jq -c --arg n "$name" '.[] | select(.name == $n)')"
            [ -n "$expected_nvpcr" ]

            # The certified NV index must match the one systemd-analyze reports.
            [ "$(echo "$comp" | jq -r '.nvPublic.nvIndex')" = "$(echo "$expected_nvpcr" | jq -r '.nvindex')" ]

            # authenticatedData is a JSON string carrying the NvPCR name and
            # priority; both must match this component and systemd-analyze.
            auth="$(echo "$comp" | jq -r '.authenticatedData')"
            [ "$(echo "$auth" | jq -r '.name')" = "$name" ]
            [ "$(echo "$auth" | jq -r '.priority')" = "$(echo "$expected_nvpcr" | jq -r '.priority')" ]
            ;;
        session-audit)
            saw_audit=1
            ;;
    esac
done

# Make sure we saw the expected components.
[ "$saw_pcr" -eq 1 ]
[ "$saw_audit" -eq 1 ]
[ "$n_nvpcr" -eq "$expected_nvpcrs" ]
