#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test report signing through the TPM2 backend (systemd-report-sign-tpm2). This is
# the TPM2 counterpart to the plain software backend test in
# TEST-74-AUX-UTILS.report.sh; it lives here because it needs a real TPM, which
# only the TPM2 integration test provides.
#
# It exercises two Varlink interfaces:
#
#  - io.systemd.Report.TPM2SignerKeyManager for managing signing keys.
#
#  - io.systemd.Report (GenerateSigned) to produce a signed report via
#    systemd-report. The TPM2 backend signs it with every configured key (generating
#    a default one if it has none), returning one signature record for each. Each
#    record carries a set of signed TPM attestations (a PCR quote, one NV
#    certification per NvPCR, and a session audit digest), together with the
#    signing key's public area, the optional voucher for it and the pcrlock event
#    log, all serialized as TCG TSS2 JSON. For each attestation we rebuild the
#    public key, re-marshal the TPMS_ATTEST that was signed, and verify the
#    signature using the embedded Python helper below. The helper also
#    cross-checks the parallel PEM encodings (publicKeyPEM and signaturePEM)
#    against the JSON encodings, and confirms the report digest is carried in the
#    extraData field of the session audit attestation. We also confirm each report
#    was signed by the key we created for it.
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

# The key manager Varlink interface (io.systemd.Report.TPM2SignerKeyManager) is
# exposed on a separate socket. Skip if that's not installed.
if ! systemctl cat systemd-report-sign-tpm2-key-manager.socket &>/dev/null; then
    echo "systemd-report-sign-tpm2-key-manager.socket is not installed, skipping TPM2 report signing test."
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

# The key manager socket. Report signing itself is driven through systemd-report's
# io.systemd.Report.GenerateSigned method.
KEY_MANAGER="/run/systemd/io.systemd.Report.TPM2SignerKeyManager"

# Where the backend keeps its keys and its cached key contexts.
KEY_DIR="/var/lib/systemd/report.sign.tpm2"
CONTEXT_DIR="/run/systemd/report.sign.tpm2"

# A persistent handle used by the "persistent" key tests.
PERSISTENT_HANDLE="0x81020001"

# A persistent handle used as a storage parent for some tests.
PARENT_HANDLE="0x81030001"

EK_HANDLE="0x81010001"

# Remove all keys, cached key contexts, vouchers and created persistent objects,
# so each test starts fresh.
reset_state() {
    tpm2_evictcontrol -C o -c "$PERSISTENT_HANDLE" >/dev/null 2>&1 || true
    tpm2_evictcontrol -C o -c "$PARENT_HANDLE" >/dev/null 2>&1 || true
    rm -f "$KEY_DIR"/* "$CONTEXT_DIR"/* 2>/dev/null || true
}

# Print an identity for each named cached key context that changes whenever the
# file is rewritten. The backend writes a context only when it had to load or
# recreate the key, and does so atomically via rename, so a context whose inode
# is unchanged across a signing request was taken from the cache.
#
# $@: key names.
context_ids() {
    local name

    for name in "$@"; do
        stat -c '%n %i %Y' "$CONTEXT_DIR/$name.context"
    done
}

at_exit() {
    set +e
    # Don't leave the keys we provisioned behind. A default key is generated
    # again on the next signing request. This also evicts any persistent object
    # the persistent-key test may have left behind.
    reset_state
    systemctl stop systemd-report.socket systemd-report-sign-tpm2.socket systemd-report-sign-tpm2-key-manager.socket
    rm -rf "$WORK"
}
trap at_exit EXIT

# The TPM2 backend creates its signing key as a child of the TPM's endorsement
# key. In a QEMU/swtpm guest there is no EK certificate, and the backend only
# provisions an EK when a matching certificate is present. Create and persist
# an EK directly. This fails if one already is already present, so ignore that.
if ! tpm2_createek -c "$EK_HANDLE" -G ecc; then
    echo "tpm2_createek failed, assuming an EK is already present."
fi

# The TPM2 backend reads the event log from pcrlock's Varlink interface, so make
# sure its socket is up.
systemctl start systemd-pcrlock.socket

systemctl start systemd-report.socket
systemctl start systemd-report-sign-tpm2.socket
systemctl start systemd-report-sign-tpm2-key-manager.socket

# Use a python script for verifying the report component signatures because we
# need to reconstruct the TPM2B_ATTEST bytes from the provided TPMS_ATTEST JSON
# encoding, and construct a public key from the provided TPMT_PUBLIC JSON encoding.
# It has two modes: "verify" checks a full report, and "pubkey-crosscheck"
# crosschecks a JSON encoded TPMT_PUBLIC area with a PEM public key.
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


def check_session_audit(alg, doc, key_name):
    """Check the properties of the session-audit component."""
    digest = b"\x00" * HASHES[alg]().digest_size # Starting audit digest

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
        elif t == "nvpcr":
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
        cp_hash = hash(alg, marshal_u32(cc) + names + cp)
        rp_hash = hash(alg, marshal_u32(0) + marshal_u32(cc) + rp)

        # Extend the audit digest.
        digest = hash(alg, digest + cp_hash + rp_hash)

    if reported is None:
        sys.exit("no session audit component present")
    if digest.hex() != reported:
        sys.exit("session audit digest does not match the audited command sequence")


def main():
    mode = sys.argv[1]

    if mode == "pubkey-crosscheck":
        # Check that the JSON TPMT_PUBLIC public area and the PEM public key read
        # from stdin (as {"public": <obj>, "pem": <str>}) describe the same key.
        obj = json.load(sys.stdin)
        key = build_pubkey(obj["public"])
        key_pem = serialization.load_pem_public_key(obj["pem"].encode())
        if key.public_numbers() != key_pem.public_numbers():
            sys.exit("publicPEM does not match public")
        return

    if mode != "verify":
        sys.exit(f"unknown mode {mode!r}")

    report_digest = sys.argv[2]

    data = json.load(sys.stdin)

    # Rebuild the key from the JSON public area.
    key_json = build_pubkey(data["publicKey"])

    # Also load the PEM encoded public key, and make sure they're the same.
    key_pem = serialization.load_pem_public_key(data["publicKeyPEM"].encode())
    if key_json.public_numbers() != key_pem.public_numbers():
        sys.exit("publicKeyPEM does not match the JSON public key")

    saw_report_binding = False
    session_audit_digest_alg = None
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

        if comp["type"] == "nvpcr":
            check_nvpcr(i, comp)
        elif comp["type"] == "session-audit":
            # The report digest passed to the signer is the session audit's
            # qualifying data, so it appears as extraData prefixed with the SHA256
            # algorithm id.
            extra = bytes.fromhex(comp["attestInfo"]["attest"]["extraData"])
            if extra != marshal_u16(HASH_ALG_ID["SHA256"]) + bytes.fromhex(report_digest):
                sys.exit(f"component {i}: session audit extraData does not match the report digest")
            saw_report_binding = True

            # This is hard-coded as SHA256 for now.
            alg = comp.get("sessionAuditHashAlg")
            if alg is None:
                sys.exit(f"component {i}: missing sessionAuditHashAlg field")
            session_audit_digest_alg = alg

        print(comp["type"])

    if not saw_report_binding:
        sys.exit("no session audit component bound the report digest")

    # The session audit digest must reproduce the audited command sequence that
    # produced the other components.
    key_name = digest_bytes_and_marshal_tpmt_ha(data["publicKey"]["nameAlg"], marshal_tpmt_public(data["publicKey"]))
    check_session_audit(session_audit_digest_alg, data, key_name)


if __name__ == "__main__":
    main()
EOF

# The backend attests every defined NvPCR. Fetch them via systemd-analyze so we
# know how many components to expect and can cross-check each one's name, index
# and priority below. Columns: name, nvindex (an unsigned integer), priority.
nvpcrs_json="$(systemd-analyze nvpcrs --json=short)"
expected_nvpcrs="$(echo "$nvpcrs_json" | jq 'length')"
[ "$expected_nvpcrs" -gt 0 ]

# Create a signing key via the key manager.
#
# $1: name.
# $2: JSON parameters (the name is injected).
#
# Prints the reply.
create_key() {
    local name="$1" params="$2"
    varlinkctl call "$KEY_MANAGER" io.systemd.Report.TPM2SignerKeyManager.CreateKey \
        "$(jq -nc --arg name "$name" --argjson p "$params" '$p + {name: $name}')"
}

# Check that a CreateKey reply has the expected parameters.
#
# $1: the reply JSON.
# $2: type (RSA|ECC).
# $3: digest algorithm (SHA256|SHA384|SHA512).
# $4: scheme (RSASSA|RSAPSS|ECDSA).
# $5: RSA key size in bits, or ECC curve ID (NIST_P256|NIST_P384).
check_reply() {
    local reply="$1" kind="$2" name_alg="$3" scheme="$4" param="$5" pub

    pub="$(jq -c .public <<<"$reply")"

    jq -e --arg t "$kind"     '.type == $t'                              <<<"$pub" >/dev/null
    jq -e --arg n "$name_alg" '.nameAlg == $n'                           <<<"$pub" >/dev/null
    jq -e --arg s "$scheme"   '.parameters.scheme.scheme == $s'          <<<"$pub" >/dev/null
    jq -e --arg h "$name_alg" '.parameters.scheme.details.hashAlg == $h' <<<"$pub" >/dev/null

    # FIXEDTPM|FIXEDPARENT|SENSITIVEDATAORIGIN|USERWITHAUTH|RESTRICTED|SIGN_ENCRYPT
    jq -e '.objectAttributes == 327794' <<<"$pub" >/dev/null

    if [ "$kind" = "RSA" ]; then
        jq -e --argjson kb "$param" '.parameters.keyBits == $kb' <<<"$pub" >/dev/null
    else
        jq -e --arg c "$param" '.parameters.curveID == $c' <<<"$pub" >/dev/null
    fi

    # public and publicPEM must be PEM/JSON encodings of the same key.
    jq -c '{public: .public, pem: .publicPEM}' <<<"$reply" | python3 "$VERIFY" pubkey-crosscheck
}

# Ask systemd-report to generate a *signed* report over Varlink. Each TPM2
# signature record is written to $WORK/report.sig.N, one per configured signing
# key. Prints the sha256 of the exact report bytes that were signed.
generate_signed() {
    rm -f "$WORK"/report.sig.*

    # The reply carries the signed report as base64-encoded JSON-SEQ data.
    varlinkctl call /run/systemd/io.systemd.Report io.systemd.Report.GenerateSigned \
        '{"matches":["io.systemd.Manager.UnitsTotal"]}' | jq -r .reportData | base64 -d >"$WORK/report.seq"

    # The first JSON-SEQ record is the report itself. This is exactly the byte
    # sequence that got signed, including the leading record separator (0x1e) and
    # the trailing newline, so 'head -n1' reproduces it verbatim.
    head -n1 "$WORK/report.seq" >"$WORK/message.bin"
    tr -d '\036' <"$WORK/message.bin" | jq -e '.mediaType == "application/vnd.io.systemd.report"' >/dev/null

    # The remaining record(s) are signature objects, one per signature returned by
    # an enabled backend. Write out the ones produced by the TPM2 backend, one
    # per configured signing key.
    local line rec n=0
    while IFS= read -r line; do
        rec="$(echo "$line" | tr -d '\036')"
        [[ -n "$rec" ]] || continue
        if [[ "$(jq -r '.mechanism // empty' <<<"$rec")" == "tpm2" ]]; then
            echo "$rec" >"$WORK/report.sig.$n"
            n=$((n + 1))
        fi
    done < <(tail -n +2 "$WORK/report.seq")

    sha256sum "$WORK/message.bin" | cut -d' ' -f1
}

# Verify a single TPM2 signature record read from file $1.
#
# $1: signature record file.
# $2: report digest.
#
# Prints the JSON public key that produced it.
verify_tpm2_sig() {
    local sig_file="$1" digest="$2" report

    [ "$(jq -r .mediaType "$sig_file")" = "application/vnd.io.systemd.report.signature" ]
    [ "$(jq -r .sha256 "$sig_file")" = "$digest" ]

    report="$(jq -c .data "$sig_file")"

    local n_components comp_types
    n_components="$(jq '.components | length' <<<"$report")"
    [ "$n_components" -gt 0 ]

    # Verify every component signature and collect the component types.
    python3 "$VERIFY" verify "$digest" <<<"$report" >"$WORK/component-types"
    mapfile -t comp_types <"$WORK/component-types"
    [ "${#comp_types[@]}" -eq "$n_components" ]

    local saw_pcr=0 saw_audit=0 n_nvpcr=0 i type comp name auth expected_nvpcr
    for i in "${!comp_types[@]}"; do
        type="${comp_types[$i]}"
        comp="$(jq -c ".components[$i]" <<<"$report")"

        case "$type" in
            pcr)
                saw_pcr=1
                ;;
            nvpcr)
                n_nvpcr=$((n_nvpcr + 1))

                # NvPCR components carry the readable name, the serialized NV
                # public area, and the authenticated data digested into the
                # attestation's qualifying data. Ensure they're populated.
                name="$(jq -r '.["nvpcrName"] // empty' <<<"$comp")"
                [ -n "$name" ]
                [ -n "$(jq -r '.["nvPublic"] // empty' <<<"$comp")" ]
                [ -n "$(jq -r '.["authenticatedData"] // empty' <<<"$comp")" ]

                # The name must be one systemd-analyze knows about.
                expected_nvpcr="$(jq -c --arg n "$name" '.[] | select(.name == $n)' <<<"$nvpcrs_json")"
                [ -n "$expected_nvpcr" ]

                # The certified NV index must match the one systemd-analyze reports.
                [ "$(jq -r '.nvPublic.nvIndex' <<<"$comp")" = "$(jq -r '.nvindex' <<<"$expected_nvpcr")" ]

                # authenticatedData is a JSON string carrying the NvPCR name and
                # priority; both must match this component and systemd-analyze.
                auth="$(jq -r '.authenticatedData' <<<"$comp")"
                [ "$(jq -r '.name' <<<"$auth")" = "$name" ]
                [ "$(jq -r '.priority' <<<"$auth")" = "$(jq -r '.priority' <<<"$expected_nvpcr")" ]
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

    jq -Sc '.publicKey' <<<"$report"
}

# Create a single key, check the reply, then generate a signed report and verify
# the signature produced with it.
#
# $1: signing key name.
# $2: signing key JSON parameters (the name is injected).
# $3: expected type (RSA|ECC).
# $4: expected digest algorithm (SHA256|SHA384|SHA512).
# $5: expected scheme (RSASSA|RSAPSS|ECDSA).
# $6: expected RSA key size in bits, or ECC curve ID (NIST_P256|NIST_P384).
test_single_key() {
    local name="$1" params="$2" kind="$3" name_alg="$4" scheme="$5" param="$6"

    # Make sure the TPM supports the requested parameters.
    local tp_type
    if [ "$kind" = "RSA" ]; then
        tp_type="rsa$param"
    else
        tp_type="ecc_${param,,}"
    fi
    if ! tpm2_supports_params "$tp_type" "${scheme,,}-${name_alg,,}"; then
        echo "TPM does not support ${tp_type}:${scheme,,}-${name_alg,,}, skipping test '$name'."
        return 0
    fi

    local reply
    reset_state
    reply="$(create_key "$name" "$params")"
    check_reply "$reply" "$kind" "$name_alg" "$scheme" "$param"

    # Check the key was stored under the requested name.
    test -e "$KEY_DIR/$name.key"

    local created_pub digest signed_pub
    local -a sig_files
    created_pub="$(jq -Sc .public <<<"$reply")"

    digest="$(generate_signed)"
    mapfile -t sig_files < <(find "$WORK" -maxdepth 1 -name 'report.sig.*' | sort)

    # There should only be a single signature.
    [ "${#sig_files[@]}" -eq 1 ]

    signed_pub="$(verify_tpm2_sig "${sig_files[0]}" "$digest")"

    # The report must be signed by exactly the key we created.
    [ "$signed_pub" = "$created_pub" ]

    echo "OK: single-key test '$name'"
}

# 0) With no signing keys provisioned, the backend generates a default one and
#    signs the report with it.
test_default_key() {
    local digest pub ctx_before
    local -a sig_files

    reset_state

    digest="$(generate_signed)"
    mapfile -t sig_files < <(find "$WORK" -maxdepth 1 -name 'report.sig.*' | sort)

    # A single signing key means a single signature record.
    [ "${#sig_files[@]}" -eq 1 ]

    pub="$(verify_tpm2_sig "${sig_files[0]}" "$digest")"

    # The generated key and its cached context must both use the default name.
    test -e "$KEY_DIR/default.key"
    test -e "$CONTEXT_DIR/default.context"

    # We installed no voucher for it, so the signature must not carry one.
    jq -e '.data.voucher == null' "${sig_files[0]}" >/dev/null

    # Signing again must reuse the cached key context rather than load the key
    # into the TPM again. The default key is an ordinary object protected by the
    # EK, so this covers the cache path taken for those.
    ctx_before="$(context_ids default)"

    digest="$(generate_signed)"
    mapfile -t sig_files < <(find "$WORK" -maxdepth 1 -name 'report.sig.*' | sort)
    [ "${#sig_files[@]}" -eq 1 ]

    # Same key, and the context was taken from the cache: a miss would have
    # loaded the key again and rewritten the context.
    [ "$(verify_tpm2_sig "${sig_files[0]}" "$digest")" = "$pub" ]
    [ "$(context_ids default)" = "$ctx_before" ]

    echo "OK: default key test"
}
test_default_key

# 1) RSA, RSASSA, 2048-bit, SHA-256 (primary key).
test_single_key "rsa-rsassa-2048-sha256" \
    '{"type":"primary","scheme":"rsassa","hashAlg":"sha256","rsaKeyBits":2048,"hierarchy":"owner"}' \
    RSA SHA256 RSASSA 2048

# 2) RSA, RSAPSS, 3072-bit, SHA-384 (primary key).
test_single_key "rsa-rsapss-3072-sha384" \
    '{"type":"primary","scheme":"rsapss","hashAlg":"sha384","rsaKeyBits":3072,"hierarchy":"owner"}' \
    RSA SHA384 RSAPSS 3072

# 3) ECC, ECDSA, NIST P-256, SHA-256 (primary key).
test_single_key "ecc-ecdsa-p256-sha256" \
    '{"type":"primary","scheme":"ecdsa","hashAlg":"sha256","eccCurve":"nistp256","hierarchy":"owner"}' \
    ECC SHA256 ECDSA NIST_P256

# 4) ECC, ECDSA, NIST P-384, SHA-512 (primary key).
test_single_key "ecc-ecdsa-p384-sha512" \
    '{"type":"primary","scheme":"ecdsa","hashAlg":"sha512","eccCurve":"nistp384","hierarchy":"owner"}' \
    ECC SHA512 ECDSA NIST_P384

# 5) RSA, RSASSA, 2048-bit, SHA-256 (primary key, EH).
test_single_key "rsa-rsassa-2048-sha256" \
    '{"type":"primary","scheme":"rsassa","hashAlg":"sha256","rsaKeyBits":2048,"hierarchy":"endorsement"}' \
    RSA SHA256 RSASSA 2048

# 6) RSA, RSASSA, 2048-bit, SHA-256 (primary key, NH).
test_single_key "rsa-rsassa-2048-sha256" \
    '{"type":"primary","scheme":"rsassa","hashAlg":"sha256","rsaKeyBits":2048,"hierarchy":"null"}' \
    RSA SHA256 RSASSA 2048

# 7) An ordinary key, as a child of the EK.
test_single_key "ordinary-ecdsa-p256" \
    "$(jq -nc --argjson ph "$((EK_HANDLE))" '{"type":"ordinary", "scheme":"ecdsa", "hashAlg":"sha256", "eccCurve":"nistp256", "parentHandle":$ph}')" \
    ECC SHA256 ECDSA NIST_P256

# 8) A persistent key created as a primary object in the owner hierarchy.
test_single_key "persistent-rsassa-2048" \
    "$(jq -nc --argjson ph "$((PERSISTENT_HANDLE))" '{"type":"persistent", "scheme":"rsassa", "hashAlg":"sha256", "rsaKeyBits":2048, "hierarchy":"owner", "persistentHandle":$ph}')" \
    RSA SHA256 RSASSA 2048

# 9) Multiple keys: the report must be signed with each configured key, i.e. we
#    get one TPM2 signature record per key, and each key has its own cached key
#    context and its own voucher.
test_multi_key() {
    if ! tpm2_supports_params rsa2048 rsassa-sha256 || ! tpm2_supports_params ecc_nist_p384 ecdsa-sha384; then
        echo "TPM does not support the multi-key test parameters, skipping."
        return 0
    fi

    local reply pub_rsa pub_ecc digest sig pub voucher ctx_before created_sorted report_sorted
    local -a sig_files report_pubs

    reset_state

    reply="$(create_key "multi-rsa" '{"type":"primary","scheme":"rsassa","hashAlg":"sha256","rsaKeyBits":2048,"hierarchy":"owner"}')"
    pub_rsa="$(jq -Sc .public <<<"$reply")"

    reply="$(create_key "multi-ecc" '{"type":"primary","scheme":"ecdsa","hashAlg":"sha384","eccCurve":"nistp384","hierarchy":"owner"}')"
    pub_ecc="$(jq -Sc .public <<<"$reply")"

    test -e "$KEY_DIR/multi-rsa.key"
    test -e "$KEY_DIR/multi-ecc.key"

    # Only multi-ecc gets a voucher, so we can tell that each signature carries
    # the voucher belonging to the key that produced it, and only that one.
    voucher="voucher for multi-ecc"
    printf '%s' "$voucher" >"$KEY_DIR/multi-ecc.voucher"

    digest="$(generate_signed)"
    mapfile -t sig_files < <(find "$WORK" -maxdepth 1 -name 'report.sig.*' | sort)

    # One TPM2 signature record per configured key.
    [ "${#sig_files[@]}" -eq 2 ]

    # We provisioned our own keys, so no default key may have been generated.
    test ! -e "$KEY_DIR/default.key"

    # Each key gets its own cached key context, named after the key.
    test -e "$CONTEXT_DIR/multi-rsa.context"
    test -e "$CONTEXT_DIR/multi-ecc.context"

    report_pubs=()
    for sig in "${sig_files[@]}"; do
        pub="$(verify_tpm2_sig "$sig" "$digest")"
        report_pubs+=("$pub")

        case "$pub" in
            "$pub_rsa")
                # multi-rsa has no voucher.
                jq -e '.data.voucher == null' "$sig" >/dev/null
                ;;
            "$pub_ecc")
                # multi-ecc's voucher is attached verbatim, base64 encoded.
                [ "$(jq -r '.data.voucher' "$sig")" = "$(printf '%s' "$voucher" | base64 -w0)" ]
                ;;
            *)
                echo "report signed by an unexpected key" >&2
                return 1
                ;;
        esac
    done

    # The two reports must be signed by exactly the two (distinct) keys we created.
    [ "$pub_rsa" != "$pub_ecc" ]
    created_sorted="$(printf '%s\n' "$pub_rsa" "$pub_ecc" | sort)"
    report_sorted="$(printf '%s\n' "${report_pubs[@]}" | sort)"
    [ "$created_sorted" = "$report_sorted" ]

    # Signing again must reuse the cached key contexts, and still produce one
    # signature per key, signed by the same two keys. Both keys are primary
    # objects recreated from a template, so this covers the cache path taken for
    # those.
    ctx_before="$(context_ids multi-rsa multi-ecc)"

    digest="$(generate_signed)"
    mapfile -t sig_files < <(find "$WORK" -maxdepth 1 -name 'report.sig.*' | sort)
    [ "${#sig_files[@]}" -eq 2 ]

    report_pubs=()
    for sig in "${sig_files[@]}"; do
        report_pubs+=("$(verify_tpm2_sig "$sig" "$digest")")
    done
    [ "$(printf '%s\n' "${report_pubs[@]}" | sort)" = "$created_sorted" ]

    # A cache miss would have recreated both keys and rewritten their contexts.
    [ "$(context_ids multi-rsa multi-ecc)" = "$ctx_before" ]

    echo "OK: multi-key test"
}
test_multi_key

# 10) Creating a key with an existing name must fail with KeyExists rather than
#    overwriting it.
test_key_exists() {
    if ! tpm2_supports_params ecc_nist_p256 ecdsa-sha256; then
        echo "TPM does not support the KeyExists test parameters, skipping."
        return 0
    fi

    local dup_err

    reset_state
    create_key "dup-key" '{"type":"primary","scheme":"ecdsa","hashAlg":"sha256","eccCurve":"nistp256","hierarchy":"owner"}' >/dev/null
    dup_err="$(varlinkctl call "$KEY_MANAGER" io.systemd.Report.TPM2SignerKeyManager.CreateKey \
        '{"name":"dup-key","type":"primary","scheme":"ecdsa","hashAlg":"sha256","eccCurve":"nistp256","hierarchy":"owner"}' 2>&1 || true)"
    echo "$dup_err" | grep "io.systemd.Report.TPM2SignerKeyManager.KeyExists" >/dev/null

    echo "OK: KeyExists test"
}
test_key_exists

# 11) A voucher for the default key with no matching key must not cause a default
#    key to be generated. A voucher certifies the key it was issued for, but is
#    paired to it by file name alone, so a generated key would end up shipping a
#    voucher that certifies a different key.
test_voucher_without_key() {
    reset_state

    printf '%s' "voucher for a key we no longer have" >"$KEY_DIR/default.voucher"

    # The backend refuses the request, which fails signing in requireAll mode.
    (! varlinkctl call /run/systemd/io.systemd.Report io.systemd.Report.GenerateSigned \
        '{"matches":["io.systemd.Manager.UnitsTotal"],"mode":"requireAll"}' >/dev/null)

    # No key may have been generated for the stray voucher.
    test ! -e "$KEY_DIR/default.key"
    test ! -e "$CONTEXT_DIR/default.context"

    echo "OK: voucher without key test"
}
test_voucher_without_key

# Delete a signing key via the key manager.
#
# $1: the name of the key to delete.
delete_key() {
    varlinkctl call "$KEY_MANAGER" io.systemd.Report.TPM2SignerKeyManager.DeleteKey \
        "$(jq -nc --arg name "$1" '{name: $name}')"
}

# 12) Deleting a key removes all associated files.
test_delete_key() {
    if ! tpm2_supports_params ecc_nist_p256 ecdsa-sha256; then
        echo "TPM does not support the delete-key test parameters, skipping."
        return 0
    fi

    reset_state
    create_key "delete-me" '{"type":"primary","scheme":"ecdsa","hashAlg":"sha256","eccCurve":"nistp256","hierarchy":"owner"}' >/dev/null

    # Signing caches a key context in the runtime directory.
    generate_signed >/dev/null

    # Drop a dummy voucher next to the key, to confirm it's removed too.
    echo "dummy voucher" >"$KEY_DIR/delete-me.voucher"

    test -e "$KEY_DIR/delete-me.key"
    test -e "$KEY_DIR/delete-me.voucher"
    test -e "$CONTEXT_DIR/delete-me.context"

    delete_key "delete-me" >/dev/null

    # All of the key's files must be gone.
    test ! -e "$KEY_DIR/delete-me.key"
    test ! -e "$KEY_DIR/delete-me.voucher"
    test ! -e "$CONTEXT_DIR/delete-me.context"

    echo "OK: delete-key test"
}
test_delete_key

# 13) Deleting a persistent key also evicts its object from the TPM.
test_delete_persistent_key() {
    if ! tpm2_supports_params rsa2048 rsassa-sha256; then
        echo "TPM does not support the delete-persistent test parameters, skipping."
        return 0
    fi

    reset_state
    create_key "delete-persistent" \
        "$(jq -nc --argjson ph "$((PERSISTENT_HANDLE))" '{"type":"persistent", "scheme":"rsassa", "hashAlg":"sha256", "rsaKeyBits":2048, "hierarchy":"owner", "persistentHandle":$ph}')" >/dev/null

    test -e "$KEY_DIR/delete-persistent.key"
    # The persistent object must exist in the TPM.
    tpm2_readpublic -c "$PERSISTENT_HANDLE" >/dev/null

    delete_key "delete-persistent" >/dev/null

    test ! -e "$KEY_DIR/delete-persistent.key"
    # ...and its persistent object must have been evicted.
    assert_fail tpm2_readpublic -c "$PERSISTENT_HANDLE"

    echo "OK: delete-persistent-key test"
}
test_delete_persistent_key

# 14) Deleting a key that doesn't exist must fail with NoSuchKey.
test_delete_no_such_key() {
    local err

    reset_state
    err="$(varlinkctl call "$KEY_MANAGER" io.systemd.Report.TPM2SignerKeyManager.DeleteKey \
        '{"name":"does-not-exist"}' 2>&1 || true)"
    echo "$err" | grep "io.systemd.Report.TPM2SignerKeyManager.NoSuchKey" >/dev/null

    echo "OK: delete-no-such-key test"
}
test_delete_no_such_key

# List signing keys via the key manager.
#
# $1: optional JSON parameters.
#
# Prints one JSON object per key.
list_keys() {
    local params="${1:-}"
    [ -n "$params" ] || params='{}'

    # 'varlinkctl --more' emits its replies as JSON-SEQ (each object prefixed with
    # an ASCII record separator, 0x1e), so strip those before handing the stream
    # to jq. Also drop the terminating empty reply, which has no 'name'.
    varlinkctl call --more "$KEY_MANAGER" io.systemd.Report.TPM2SignerKeyManager.ListKeys "$params" \
        | tr -d '\036' \
        | jq -c 'select(.name != null)'
}

# Assert that a list entry public key matches the one obtained from CreateKey.
#
# $1: ListKeys entry.
# $2: CreateKey reply.
assert_public_matches() {
    local listed="$1" created="$2"

    # The JSON public areas must match.
    [ "$(jq -Sc .public <<<"$listed")" = "$(jq -Sc .public <<<"$created")" ]

    # The entry's public and publicPEM must be PEM/JSON encodings of the same key.
    jq -c '{public: .public, pem: .publicPEM}' <<<"$listed" | python3 "$VERIFY" pubkey-crosscheck
}

# 14) List keys of different types, and check the reported properties.
test_list_keys() {
    if ! tpm2_supports_params ecc_nist_p256 ecdsa-sha256 || ! tpm2_supports_params rsa2048 rsassa-sha256; then
        echo "TPM does not support the list-keys test parameters, skipping."
        return 0
    fi

    local ordinary_reply primary_reply persistent_reply
    reset_state
    ordinary_reply="$(create_key "list-ordinary" \
        "$(jq -nc --argjson ph "$((EK_HANDLE))" '{"type":"ordinary","scheme":"ecdsa","hashAlg":"sha256","eccCurve":"nistp256","parentHandle":$ph}')")"
    primary_reply="$(create_key "list-primary" \
        '{"type":"primary","scheme":"ecdsa","hashAlg":"sha256","eccCurve":"nistp256","hierarchy":"owner"}')"
    persistent_reply="$(create_key "list-persistent" \
        "$(jq -nc --argjson ph "$((PERSISTENT_HANDLE))" '{"type":"persistent","scheme":"rsassa","hashAlg":"sha256","rsaKeyBits":2048,"hierarchy":"owner","persistentHandle":$ph}')")"

    # Drop a voucher next to one key, to confirm it's returned (base64 encoded).
    # We use some binary content to make sure the encoding round-trips faithfully.
    local voucher
    voucher="$(printf '\x00\x01\x02voucher\xff')"
    printf '%s' "$voucher" >"$KEY_DIR/list-ordinary.voucher"

    local keys ordinary primary persistent
    keys="$(list_keys)"

    ordinary="$(jq -c 'select(.name == "list-ordinary")' <<<"$keys")"
    primary="$(jq -c 'select(.name == "list-primary")' <<<"$keys")"
    persistent="$(jq -c 'select(.name == "list-persistent")' <<<"$keys")"
    [ -n "$ordinary" ]
    [ -n "$primary" ]
    [ -n "$persistent" ]

    # Ordinary key: no hierarchy or persistentHandle.
    [ "$(jq -r .type <<<"$ordinary")" = "ordinary" ]
    [ "$(jq -r .status <<<"$ordinary")" = "available" ]
    [ "$(jq -r '.public.type' <<<"$ordinary")" = "ECC" ]
    [ -z "$(jq -r '.hierarchy // empty' <<<"$ordinary")" ]
    [ -z "$(jq -r '.persistentHandle // empty' <<<"$ordinary")" ]
    assert_public_matches "$ordinary" "$ordinary_reply"
    # The voucher we dropped is returned, base64 encoded.
    [ "$(jq -r .voucher <<<"$ordinary" | base64 -d)" = "$voucher" ]

    # Primary key: owner hierarchy is set, and no persistentHandle.
    [ "$(jq -r .type <<<"$primary")" = "primary" ]
    [ "$(jq -r .status <<<"$primary")" = "available" ]
    [ "$(jq -r .hierarchy <<<"$primary")" = "owner" ]
    [ "$(jq -r '.public.type' <<<"$primary")" = "ECC" ]
    assert_public_matches "$primary" "$primary_reply"
    # No voucher was created for this key, so none is reported.
    [ -z "$(jq -r '.voucher // empty' <<<"$primary")" ]

    # Persistent key: persistentHandle is set, and no hierarchy.
    [ "$(jq -r .type <<<"$persistent")" = "persistent" ]
    [ "$(jq -r .status <<<"$persistent")" = "available" ]
    [ "$(jq -r .persistentHandle <<<"$persistent")" = "$((PERSISTENT_HANDLE))" ]
    [ "$(jq -r '.public.type' <<<"$persistent")" = "RSA" ]
    assert_public_matches "$persistent" "$persistent_reply"
    [ -z "$(jq -r '.voucher // empty' <<<"$persistent")" ]

    echo "OK: list-keys test"
}
test_list_keys

# 15) The filter argument selects keys by name.
test_list_keys_filter() {
    if ! tpm2_supports_params ecc_nist_p256 ecdsa-sha256; then
        echo "TPM does not support the list-keys-filter test parameters, skipping."
        return 0
    fi

    local name
    reset_state
    for name in filter-aaa filter-bbb other; do
        create_key "$name" \
            '{"type":"primary","scheme":"ecdsa","hashAlg":"sha256","eccCurve":"nistp256","hierarchy":"owner"}' >/dev/null
    done

    local keys
    keys="$(list_keys '{"filter":"filter-*"}')"

    # Only the two filter-* keys must be returned.
    [ "$(jq -s 'length' <<<"$keys")" -eq 2 ]
    [ -n "$(jq -c 'select(.name == "filter-aaa")' <<<"$keys")" ]
    [ -n "$(jq -c 'select(.name == "filter-bbb")' <<<"$keys")" ]
    [ -z "$(jq -c 'select(.name == "other")' <<<"$keys")" ]

    echo "OK: list-keys-filter test"
}
test_list_keys_filter

# 16) A persistent key whose TPM object has gone away is reported as unavailable.
test_list_keys_unavailable() {
    if ! tpm2_supports_params rsa2048 rsassa-sha256; then
        echo "TPM does not support the list-keys-unavailable test parameters, skipping."
        return 0
    fi

    reset_state
    create_key "gone-persistent" \
        "$(jq -nc --argjson ph "$((PERSISTENT_HANDLE))" '{"type":"persistent","scheme":"rsassa","hashAlg":"sha256","rsaKeyBits":2048,"hierarchy":"owner","persistentHandle":$ph}')" >/dev/null

    # Evict the persistent object out from under the key, so it can no longer be loaded.
    tpm2_evictcontrol -C o -c "$PERSISTENT_HANDLE" >/dev/null

    local keys key
    keys="$(list_keys)"

    key="$(jq -c 'select(.name == "gone-persistent")' <<<"$keys")"
    [ -n "$key" ]
    [ "$(jq -r .status <<<"$key")" = "unavailable" ]
    # No public area is reported for an unavailable persistent key...
    [ -z "$(jq -r '.public // empty' <<<"$key")" ]
    # ...but the persistent handle it was stored at still is.
    [ "$(jq -r .persistentHandle <<<"$key")" = "$((PERSISTENT_HANDLE))" ]

    echo "OK: list-keys-unavailable test"
}
test_list_keys_unavailable

# 17) An ordinary key whose parent object is incorrect is reported as unavailable.
test_list_keys_ordinary_unavailable() {
    if ! tpm2_supports_params ecc_nist_p256 ecdsa-sha256; then
        echo "TPM does not support the list-keys-ordinary-unavailable test parameters, skipping."
        return 0
    fi

    reset_state
    # Start from a clean parent handle.
    tpm2_evictcontrol -C o -c "$PARENT_HANDLE" >/dev/null 2>&1 || true

    # Create a temporary persistent storage key to act as the ordinary key's parent.
    tpm2_createprimary -C o -G ecc -c "$WORK/parent.ctx" >/dev/null
    tpm2_evictcontrol -C o -c "$WORK/parent.ctx" "$PARENT_HANDLE" >/dev/null
    rm -f "$WORK/parent.ctx"

    local reply created_public
    reply="$(create_key "orphan-ordinary" \
        "$(jq -nc --argjson ph "$((PARENT_HANDLE))" '{"type":"ordinary","scheme":"ecdsa","hashAlg":"sha256","eccCurve":"nistp256","parentHandle":$ph}')")"
    created_public="$(jq -Sc .public <<<"$reply")"

    # Replace the object at the parent handle with a different one, so the ordinary
    # key can no longer be loaded. This simulates, eg, trying to load a key under
    # the SRK after a TPM2_Clear.
    tpm2_evictcontrol -C o -c "$PARENT_HANDLE" >/dev/null
    tpm2_createprimary -C o -G rsa -c "$WORK/parent.ctx" >/dev/null
    tpm2_evictcontrol -C o -c "$WORK/parent.ctx" "$PARENT_HANDLE" >/dev/null
    rm -f "$WORK/parent.ctx"

    local keys key
    keys="$(list_keys)"
    key="$(jq -c 'select(.name == "orphan-ordinary")' <<<"$keys")"
    [ -n "$key" ]
    [ "$(jq -r .status <<<"$key")" = "unavailable" ]
    # Even when unavailable, an ordinary key's public area is reported, as it's
    # stored in the key file.
    [ -n "$(jq -r '.public // empty' <<<"$key")" ]
    [ "$(jq -Sc .public <<<"$key")" = "$created_public" ]

    tpm2_evictcontrol -C o -c "$PARENT_HANDLE" >/dev/null

    echo "OK: list-keys-ordinary-unavailable test"
}
test_list_keys_ordinary_unavailable

# 18) A primary key whose recreated object no longer matches the stored name
#     (e.g. because the hierarchy seed changed) is unavailable.
test_list_keys_primary_unavailable() {
    if ! tpm2_supports_params ecc_nist_p256 ecdsa-sha256; then
        echo "TPM does not support the list-keys-primary-unavailable test parameters, skipping."
        return 0
    fi

    reset_state
    mkdir -p "$KEY_DIR"

    # A marshaled TPM2B_PUBLIC for a restricted ECDSA/SHA-256 signing key with NIST
    # P-256 and an empty unique area.
    local template
    template="$(echo "00180023000b00050072000000100018000b0003001000000000" | basenc --base16 -d | basenc --base64)"
    # A bogus expected name that the recreated key will never match.
    local bogus_name="000b0000000000000000000000000000000000000000000000000000000000000000"

    jq -nc --arg t "$template" --arg n "$bogus_name" \
        '{type: "primary", hierarchy: "owner", template: $t, name: $n}' >"$KEY_DIR/bogus-primary.key"

    local keys key
    keys="$(list_keys)"
    key="$(jq -c 'select(.name == "bogus-primary")' <<<"$keys")"
    [ -n "$key" ]
    [ "$(jq -r .status <<<"$key")" = "unavailable" ]
    # No public area is reported for an unavailable primary key...
    [ -z "$(jq -r '.public // empty' <<<"$key")" ]
    # ...but the hierarchy it lives in still is.
    [ "$(jq -r .hierarchy <<<"$key")" = "owner" ]

    echo "OK: list-keys-primary-unavailable test"
}
test_list_keys_primary_unavailable
