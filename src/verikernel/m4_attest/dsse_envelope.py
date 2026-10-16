"""Dsse envelope."""
from __future__ import annotations
import base64
import binascii
import hashlib
import hmac
import json
from .pqc_signer import MLDSA65Signer
from verikernel.type_boundaries import DSSEEnvelopeDict, validate_dsse_dict

PAYLOAD_TYPE = "application/vnd.in-toto+json"


def pae(payload_type: str, payload: bytes) -> bytes:
    """Encode the DSSE payload type and payload with byte-counted framing. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    typ = payload_type.encode()
    return b"DSSEv1 " + str(len(typ)).encode() + b" " + typ + b" " + str(len(payload)).encode() + b" " + payload


def seal(statement: object, signer: object) -> object:
    """Sign a canonical statement and return its DSSE envelope. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    signature = signer.sign(pae(PAYLOAD_TYPE, payload))
    return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(), "signatures": [{"keyid": hashlib.sha256(signer.public_key).hexdigest(), "sig": base64.b64encode(signature).decode()}]}


def verify(envelope: DSSEEnvelopeDict, public_key: bytes) -> bool:
    """Validate the captured evidence and return the verification result. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    try:
        envelope = validate_dsse_dict(envelope)
        payload = base64.b64decode(envelope["payload"], validate=True)
        signatures = envelope["signatures"]
        keyid = hashlib.sha256(public_key).hexdigest()
        if len(signatures)!=1:
            return False
        key_matches = hmac.compare_digest(signatures[0]['keyid'],keyid)
        signature_valid = MLDSA65Signer.verify(public_key, pae(envelope["payloadType"], payload), base64.b64decode(signatures[0]["sig"], validate=True))
        return bool(key_matches & signature_valid)
    except (KeyError, TypeError, ValueError, binascii.Error):
        return False


def statement_payload(envelope: object) -> object:
    """Decode the JSON statement carried by a DSSE envelope. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    return json.loads(base64.b64decode(envelope["payload"], validate=True))
