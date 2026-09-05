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
# NV certification per NvPCR, and a session audit digest), a set of unsigned TPM
# capability readings (a few TPM properties and the hierarchy auth policies),
# together with the signing key's public area and the pcrlock event log. The
# public area, the attestations, the capabilities and the signatures are all
# serialized as TCG TSS2 JSON. For each attestation we rebuild the public key,
# re-marshal the TPMS_ATTEST that was signed, and verify the signature using the
# embedded Python helper below. The helper also cross-checks the parallel PEM
# encodings (publicKeyPEM and signaturePEM) against the JSON encodings. We also
# confirm the report digest is carried in the extraData field of the session audit
# attestation.
#
# The capability components carry no signature of their own. They are bound to the
# report by the session audit digest, which covers every command issued inside
# the audit session, including the TPM2_GetCapability commands.
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

# See below - we temporarily give the lockout hierarchy an authorization value and
# a policy.
LOCKOUT_AUTH="systemd-report-sign-test"
lockout_modified=0

at_exit() {
    set +e

    if [ "$lockout_modified" -eq 1 ]; then
        tpm2_changeauth -c lockout -p "$LOCKOUT_AUTH" ""
    fi
    tpm2_setprimarypolicy -C lockout

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

# None of the hierarchies have an authorization value or a policy in the test
# environment, so every auth policy the backend reports would be empty and the
# TPMA_PERMANENT it reports would carry none of the *AuthSet flags. Give the
# lockout hierarchy both for the duration of the test so that the non-empty cases
# actually get exercised. We pick the lockout hierarchy because, unlike the owner
# and endorsement hierarchies, nothing else here makes use of it.
LOCKOUT_POLICY="$(python3 -c 'import hashlib, sys
digest = hashlib.sha256(b"systemd report signing test").digest()
open(sys.argv[1], "wb").write(digest)
print(digest.hex())' "$WORK/lockout.policy")"

tpm2_setprimarypolicy -C lockout -L "$WORK/lockout.policy" -g sha256
tpm2_changeauth -c lockout "$LOCKOUT_AUTH"
lockout_modified=1

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

# Both python helpers below need the same TPM2 identifier tables, so write them
# out once as a module the helpers import rather than repeating them in each.
cat >"$WORK/tpm2_ids.py" <<'EOF'
"""TPM2 identifiers, named as in the TCG TSS2 JSON format."""

HASH_ALG_ID = {"SHA1": 0x0004, "SHA256": 0x000b, "SHA384": 0x000c, "SHA512": 0x000d,
               "NULL": 0x0010}
SIG_ALG_ID = {"RSASSA": 0x0014, "RSAPSS": 0x0016, "ECDSA": 0x0018, "NULL": 0x0010}
PUB_ALG_ID = {"RSA": 0x0001, "ECC": 0x0023}
CURVE_ID = {"NIST_P192": 0x0001, "NIST_P224": 0x0002, "NIST_P256": 0x0003,
            "NIST_P384": 0x0004, "NIST_P521": 0x0005, "BN_P256": 0x0010,
            "BN_P638": 0x0011, "SM2_P256": 0x0020}
ST_ATTEST = {"ATTEST_NV": 0x8014, "ATTEST_SESSION_AUDIT": 0x8016, "ATTEST_QUOTE": 0x8018}
TPM_PT_ID = {"PERMANENT": 0x00000200, "MAX_AUTH_FAIL": 0x0000020f,
             "LOCKOUT_INTERVAL": 0x00000210, "LOCKOUT_RECOVERY": 0x00000211}
TPM_HANDLE_ID = {"OWNER": 0x40000001, "LOCKOUT": 0x4000000a, "ENDORSEMENT": 0x4000000b}

# Derived rather than typed out a second time, so the two directions can't drift apart.
HASH_ALG_NAME = {v: k for k, v in HASH_ALG_ID.items()}

TPM_GENERATED = 0xff544347
ALG_NULL = 0x0010
ST_NO_SESSIONS = 0x8001
CC_QUOTE = 0x00000158
CC_GET_CAPABILITY = 0x0000017a
CC_NV_CERTIFY = 0x00000184
CAP_TPM_PROPERTIES = 0x00000006
CAP_AUTH_POLICIES = 0x00000009
EOF

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

from tpm2_ids import (ALG_NULL, CAP_AUTH_POLICIES, CAP_TPM_PROPERTIES, CC_GET_CAPABILITY,
                      CC_NV_CERTIFY, CC_QUOTE, CURVE_ID, HASH_ALG_ID, PUB_ALG_ID,
                      SIG_ALG_ID, ST_ATTEST, TPM_GENERATED, TPM_HANDLE_ID, TPM_PT_ID)

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


def tpm_pt_id(prop):
    """Decode the JSON encoding of a TPM2_PT, which is either the property name with
    the TPM2_PT_ prefix dropped, or a plain integer for properties that the encoder
    doesn't know a name for."""
    if isinstance(prop, int):
        return prop
    if prop not in TPM_PT_ID:
        sys.exit(f"unsupported TPM property {prop}")
    return TPM_PT_ID[prop]


def tpm_handle_id(handle):
    """Decode the JSON encoding of a TPM2_HANDLE, which is either the handle name with
    the TPM2_RH_ prefix dropped, or a plain integer for handles that the encoder
    doesn't know a name for."""
    if isinstance(handle, int):
        return handle
    if handle not in TPM_HANDLE_ID:
        sys.exit(f"unsupported TPM handle {handle}")
    return TPM_HANDLE_ID[handle]


# Helpers to serialize JSON encodings to the TPM wire format.


def marshal_bool(v):
    return marshal_u8(1 if v else 0)


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


def marshal_tpmt_ha(ha):
    """Serialize the supplied JSON encoded TPMT_HA to its wire form. The digest is
    a fixed size union member, so it carries no size prefix, and it is absent for
    a null algorithm."""
    out = marshal_u16(HASH_ALG_ID[ha["hashAlg"]])
    if ha["hashAlg"] != "NULL":
        out += bytes.fromhex(ha["digest"])
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


def marshal_attestation_rp(comp):
    """Serialize the response parameter area of an audited attestation command."""
    out = marshal_bytes_tpm2b(marshal_tpms_attest(comp["attestInfo"]["attest"])) # TPM2B_ATTEST out
    out += marshal_tpmt_signature(comp["signature"])                             # signature
    return out


def marshal_capability_rp(moreData, cap, entry):
    """Serialize the response parameter area of an audited TPM2_GetCapability
    command that returned the single supplied capability list entry."""
    out = marshal_bool(moreData) # moreData
    out += marshal_u32(cap)      # capabilityData.capability
    out += marshal_u32(1)        # capabilityData.data.<list>.count
    return out + entry


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
    nv = comp.get("nvPublic")
    if nv is None:
        sys.exit(f"component {i}: no nvPublic")

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


def check_capability_common(i, comp):
    moreData = comp.get("capabilityMoreData")
    if moreData is None:
        sys.exit(f"component {i}: no capabilityMoreData")

    if not isinstance(moreData, bool):
        sys.exit(f"component {i}: capabilityMoreData is not a boolean")


def check_tpm_property(i, comp):
    """Check the properties of the capability-tpm-property component."""
    prop = comp.get("tpmProperty")
    if prop is None:
        sys.exit(f"component {i}: no tpmProperty")

    # The property must be one we know how to marshal for the audit digest check
    # below, and its value must be a plain integer.
    tpm_pt_id(prop["property"])
    if not isinstance(prop["value"], int):
        sys.exit(f"component {i}: tpmProperty value is not an integer")

    check_capability_common(i, comp)


def check_auth_policy(i, comp):
    """Check the properties of the capability-auth-policy component."""
    policy = comp.get("authPolicy")
    if policy is None:
        sys.exit(f"component {i}: no authPolicy")

    # The handle must be one we know how to marshal for the audit digest check below.
    tpm_handle_id(policy["handle"])

    # A hierarchy without an auth policy is reported as a TPMT_HA with a null
    # algorithm and no digest. Anything else must carry a digest of the length
    # implied by the algorithm.
    ha = policy["policyHash"]
    alg = ha["hashAlg"]
    if alg == "NULL":
        if "digest" in ha:
            sys.exit(f"component {i}: policyHash has no algorithm but carries a digest")
    elif alg not in HASHES:
        sys.exit(f"component {i}: unsupported policyHash algorithm {alg}")
    elif len(bytes.fromhex(ha["digest"])) != HASHES[alg]().digest_size:
        sys.exit(f"component {i}: policyHash digest doesn't match algorithm {alg}")

    check_capability_common(i, comp)


def check_session_audit(doc, key_name):
    """Check the properties of the session-audit component."""
    digest = b"\x00" * 32 # Starting audit digest

    reported = None
    for comp in doc["components"]:
        # Determine the command code, command handle names, cpBytes and rpBytes.
        t = comp["type"]
        if t == "pcr":
            att = comp["attestInfo"]["attest"]
            cc = CC_QUOTE
            names = key_name                                               # signHandle only
            cp = marshal_hex_tpm2b("")                                     # qualifyingData
            cp += marshal_u16(ALG_NULL)                                    # inScheme.scheme
            cp += marshal_tpml_pcr_selection(att["attested"]["pcrSelect"]) # pcrSelect
            rp = marshal_attestation_rp(comp)
        elif t == "nvpcr":
            att = comp["attestInfo"]["attest"]
            cc = CC_NV_CERTIFY
            nv_name = digest_bytes_and_marshal_tpmt_ha(comp["nvPublic"]["nameAlg"], marshal_tpms_nv_public(comp["nvPublic"]))
            # Handle area is signHandle, authHandle, nvIndex - we pass the NV index for both
            # the authHandle and nvIndex.
            names = key_name + nv_name + nv_name
            cp = marshal_hex_tpm2b(att["extraData"])        # qualifyingData
            cp += marshal_u16(ALG_NULL)                     # inScheme.scheme
            cp += marshal_u16(comp["nvPublic"]["dataSize"]) # size
            cp += marshal_u16(0)                            # offset
            rp = marshal_attestation_rp(comp)
        elif t == "capability-tpm-property":
            prop = tpm_pt_id(comp["tpmProperty"]["property"])
            cc = CC_GET_CAPABILITY
            names = b""                          # no command handles
            cp = marshal_u32(CAP_TPM_PROPERTIES) # capability
            cp += marshal_u32(prop)              # property
            cp += marshal_u32(1)                 # propertyCount
            rp = marshal_capability_rp(
                    comp["capabilityMoreData"],
                    CAP_TPM_PROPERTIES,
                    marshal_u32(prop) + marshal_u32(comp["tpmProperty"]["value"]))
        elif t == "capability-auth-policy":
            handle = tpm_handle_id(comp["authPolicy"]["handle"])
            cc = CC_GET_CAPABILITY
            names = b""                         # no command handles
            cp = marshal_u32(CAP_AUTH_POLICIES) # capability
            cp += marshal_u32(handle)           # property
            cp += marshal_u32(1)                # propertyCount
            rp = marshal_capability_rp(
                    comp["capabilityMoreData"],
                    CAP_AUTH_POLICIES,
                    marshal_u32(handle) + marshal_tpmt_ha(comp["authPolicy"]["policyHash"]))
        elif t == "session-audit":
            reported = comp["attestInfo"]["attest"]["attested"]["sessionDigest"]
            continue                                    # not audited itself
        else:
            sys.exit(f"unsupported component type {t}")

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
        if comp["type"] in ("capability-tpm-property", "capability-auth-policy"):
            # The capability components are read inside the audit session but are not
            # signed individually, so they are bound to the report solely by the session
            # audit digest, which is checked below.
            for field in ("attestInfo", "signature", "signaturePEM"):
                if field in comp:
                    sys.exit(f"component {i}: capability component carries a {field} field")
        else:
            for field in ("attestInfo", "signature", "signaturePEM"):
                if field not in comp:
                    sys.exit(f"component {i}: component does not carry a {field} field")

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

        # Perform some checks specific to each component now.
        if comp["type"] == "nvpcr":
            check_nvpcr(i, comp)
        elif comp["type"] == "capability-tpm-property":
            check_tpm_property(i, comp)
        elif comp["type"] == "capability-auth-policy":
            check_auth_policy(i, comp)
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

# The backend also reports a fixed set of TPM properties and hierarchy auth
# policies, read with TPM2_GetCapability inside the audit session.
expected_props=(PERMANENT MAX_AUTH_FAIL LOCKOUT_INTERVAL LOCKOUT_RECOVERY)
expected_policies=(OWNER LOCKOUT ENDORSEMENT)

# TPMA_PERMANENT.lockoutAuthSet, i.e. bit 2.
TPMA_PERMANENT_LOCKOUT_AUTH_SET=$((1 << 2))

# The values the backend reports for those must be the ones the TPM reports now,
# so we have to query them ourselves. tpm2_getcap can't do that for us: it has no
# way to query TPM2_CAP_AUTH_POLICIES at all, and it prints TPM2_PT_PERMANENT
# decomposed into its individual flags rather than as a value. So assemble the
# TPM2_GetCapability commands by hand and push them through the TPM with tpm2_send.
GETCAP="$WORK/tpm-getcap.py"
cat >"$GETCAP" <<'EOF'
#!/usr/bin/env python3
"""Print a single TPM capability value, as named in the TCG TSS2 JSON format.

For 'property' this prints the value of the named TPM2_PT as a decimal number, for
'auth-policy' the policy digest of the named permanent handle as the hash algorithm
followed by the digest in hex (the digest is empty for a null algorithm, i.e. when
the hierarchy has no policy set)."""

import struct
import subprocess
import sys

from tpm2_ids import (CAP_AUTH_POLICIES, CAP_TPM_PROPERTIES, CC_GET_CAPABILITY,
                      HASH_ALG_NAME, ST_NO_SESSIONS, TPM_HANDLE_ID, TPM_PT_ID)


def get_capability(capability, prop):
    """Run a TPM2_GetCapability for a single property, returning the one entry of
    the returned capability list."""
    body = struct.pack(">III", capability, prop, 1) # capability, property, propertyCount
    cmd = struct.pack(">HII", ST_NO_SESSIONS, 10 + len(body), CC_GET_CAPABILITY) + body

    rsp = subprocess.run(["tpm2_send"], input=cmd, stdout=subprocess.PIPE, check=True).stdout

    _, _, rc = struct.unpack(">HII", rsp[:10])
    if rc != 0:
        sys.exit(f"TPM2_GetCapability failed with response code {rc:#010x}")

    # The response parameters are moreData followed by a TPMS_CAPABILITY_DATA, i.e.
    # the capability, the number of list entries and the entries themselves.
    _, cap, count = struct.unpack(">BII", rsp[10:19])
    if cap != capability or count != 1:
        sys.exit(f"TPM2_GetCapability returned capability {cap:#010x} with {count} entries")

    return rsp[19:]


def main():
    kind, name = sys.argv[1], sys.argv[2]

    if kind == "property":
        # TPMS_TAGGED_PROPERTY
        prop, value = struct.unpack(">II", get_capability(CAP_TPM_PROPERTIES, TPM_PT_ID[name]))
        if prop != TPM_PT_ID[name]:
            sys.exit(f"TPM reported property {prop:#010x} instead of {name}")
        print(value)
    elif kind == "auth-policy":
        # TPMS_TAGGED_POLICY, whose policyHash is a TPMT_HA: the digest is a fixed
        # size union member, so the rest of the entry is the digest.
        entry = get_capability(CAP_AUTH_POLICIES, TPM_HANDLE_ID[name])
        handle, alg = struct.unpack(">IH", entry[:6])
        if handle != TPM_HANDLE_ID[name]:
            sys.exit(f"TPM reported handle {handle:#010x} instead of {name}")
        if alg not in HASH_ALG_NAME:
            sys.exit(f"TPM reported unknown hash algorithm id {alg:#06x}")
        print(HASH_ALG_NAME[alg], entry[6:].hex())
    else:
        sys.exit(f"unsupported capability kind {kind}")


if __name__ == "__main__":
    main()
EOF

# Verify every component signature and collect the component types.
echo "$sig_json" | python3 "$VERIFY" "$report_digest" >"$WORK/component-types"
mapfile -t comp_types <"$WORK/component-types"
[ "${#comp_types[@]}" -eq "$n_components" ]

saw_pcr=0
saw_audit=0
n_nvpcr=0
seen_props=()
seen_policies=()

for i in "${!comp_types[@]}"; do
    type="${comp_types[$i]}"
    comp="$(echo "$sig_json" | jq -c ".data.components[$i]")"

    case "$type" in
        pcr)
            saw_pcr=1
            ;;
        nvpcr)
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
        capability-tpm-property)
            prop="$(echo "$comp" | jq -r '.tpmProperty.property')"
            value="$(echo "$comp" | jq -r '.tpmProperty.value')"
            seen_props+=("$prop")

            # The reported value must be the one the TPM reports for this property.
            [ "$value" -eq "$(python3 "$GETCAP" property "$prop")" ]

            # We gave the lockout hierarchy an authorization value above, so the
            # reported TPMA_PERMANENT must carry lockoutAuthSet.
            if [ "$prop" = "PERMANENT" ]; then
                [ $((value & TPMA_PERMANENT_LOCKOUT_AUTH_SET)) -ne 0 ]
            fi
            ;;
        capability-auth-policy)
            handle="$(echo "$comp" | jq -r '.authPolicy.handle')"
            alg="$(echo "$comp" | jq -r '.authPolicy.policyHash.hashAlg')"
            # A hierarchy with no policy set is reported with a null algorithm and
            # no digest at all, so this may legitimately be empty.
            digest="$(echo "$comp" | jq -r '.authPolicy.policyHash.digest // ""')"
            seen_policies+=("$handle")

            # The reported policy hash must be the one the TPM reports for this
            # hierarchy, digest included.
            read -r expected_alg expected_digest <<<"$(python3 "$GETCAP" auth-policy "$handle")"
            [ "$alg" = "$expected_alg" ]
            [ "$digest" = "$expected_digest" ]

            # We set a policy on the lockout hierarchy above, so that one must be
            # reported as the digest we installed rather than as an empty policy.
            if [ "$handle" = "LOCKOUT" ]; then
                [ "$alg" = "SHA256" ]
                [ "$digest" = "$LOCKOUT_POLICY" ]
            fi
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
diff <(printf '%s\n' "${expected_props[@]}" | sort) <(printf '%s\n' "${seen_props[@]}" | sort)
diff <(printf '%s\n' "${expected_policies[@]}" | sort) <(printf '%s\n' "${seen_policies[@]}" | sort)
