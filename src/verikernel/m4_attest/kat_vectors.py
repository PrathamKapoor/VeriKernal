"""Fixed SHA-256/FIPS 204 answers; verification uses O(n) time and space."""
import hashlib
import hmac


def verify_known_answers() -> dict[str,object]:
    """Check five frozen vectors with independent FIPS reference; O(n) time/space."""
    from dilithium_py.ml_dsa import ML_DSA_65
    from verikernel.schemas import KernelTelemetryEvent
    from verikernel.omnibor import gitoid_sha256
    from verikernel.rust_bridge import BatchEngine
    from .merkle_tiles import mth,prove_inclusion,sha256_digest
    from .dsse_envelope import pae
    from .pqc_signer import MLDSA65Signer
    payload = b'VeriKernel-KAT-Payload\n'
    if not hmac.compare_digest(gitoid_sha256(payload),VECTORS['gitoid']):
        raise ValueError('KAT-1 rejected')
    wire = bytes.fromhex(VECTORS['wire'])
    event = KernelTelemetryEvent(seq_no=7,timestamp_ns=100,pid=9,tid=10,syscall_nr=2,fault_injected=-28,dev_id=1,inode_nr=2,mtime_ns=3,call_stack_hash=4,target_digest=bytes(range(32)),ratchet_tag=bytes(range(32)))
    if event!=KernelTelemetryEvent.from_bytes(wire) or not hmac.compare_digest(event.to_bytes(),wire):
        raise ValueError('KAT-2 rejected')
    packed = bytearray(b''.join(KernelTelemetryEvent(seq_no=i,timestamp_ns=100+i,pid=7,tid=8,syscall_nr=2,target_digest=bytes([i])*32).to_bytes() for i in range(3)))
    c0,kn = BatchEngine().seal(packed,bytes([66])*32)
    if not hmac.compare_digest(c0.hex(),VECTORS['commitment']) or not hmac.compare_digest(kn.hex(),VECTORS['terminal']) or any(not hmac.compare_digest(packed[i*128+96:i*128+128].hex(),VECTORS['tags'][i]) for i in range(3)):
        raise ValueError('KAT-3 rejected')
    leaves = [f'leaf-{i}'.encode() for i in range(5)]
    proof = prove_inclusion(3,leaves,sha256_digest)
    if not hmac.compare_digest(mth(leaves,sha256_digest).hex(),VECTORS['tree_root']) or [v.hex() for v in proof]!=VECTORS['proof']:
        raise ValueError('KAT-4 rejected')
    message = pae('application/vnd.in-toto+json',payload)
    signer = MLDSA65Signer(seed=bytes([153])*32)
    signature = signer.sign(message)
    public,secret = ML_DSA_65.key_derive(bytes([153])*32)
    if not hmac.compare_digest(message.hex(),VECTORS['pae']) or not hmac.compare_digest(hashlib.sha256(signer.public_key).hexdigest(),VECTORS['public_key_sha256']) or not hmac.compare_digest(hashlib.sha256(secret).hexdigest(),VECTORS['secret_key_sha256']) or not hmac.compare_digest(hashlib.sha256(signature).hexdigest(),VECTORS['signature_sha256']) or not ML_DSA_65.verify(public,message,signature):
        raise ValueError('KAT-5 rejected')
    return {'verified':5,'independent_signature_reference':True,'hash_profile':'sha256','encoding':'FIPS 204 ML-DSA-65'}

VECTORS = {'gitoid': 'gitoid:blob:sha256:38edb772866ab7ec6a7209575d8763d4ef138baa5fd6398d9f5d818ed6b202a3', 'wire': '07000000000000006400000000000000090000000a00000002000000e4ffffff0100000000000000020000000000000003000000000000000400000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'commitment': '46105e8e72f394c74d9829ede92c3a1937c5c723823a20df5ac2f92cc6097f9c', 'tags': ['525f58ed0d384cf98a9981a41fa6a56f9a57a17792e93f33d49f3696e5731602', 'a7d49ab30916e222ea5c26b49cedd66cb8d3fece385e069d4ac3a202daca3ead', 'ca2d98c7765b52b26a2e29bc0d02bfd7dc7461ae350ee588ec5ada9c1fbe9c66'], 'terminal': '81a737e5b8f72bb390321add5bc41cb25f5b4e5c351c827ccb1501b56ec9b6e9', 'tree_root': '00d21829a5503145348abcf712513eacf2a274211ad83e970202bb5b6d80b286', 'proof': ['fca89f57c9f8c8eb4047a7ff9d333acf9e0f3384b20b255bceab0f216dcca267', '60a53eed0de87a90c8e59427c59c46253c33a76a09502a51801300927b7e6bdc', 'ea9fc1a1b6e191b460d0d6306e3e870c173f39330f13cda1b70cfc72bdc398ba'], 'pae': '445353457631203238206170706c69636174696f6e2f766e642e696e2d746f746f2b6a736f6e20323320566572694b65726e656c2d4b41542d5061796c6f61640a', 'public_key_sha256': '0404577438edbddd1cbf4a38bd3f2263d61ccd0f572f07d25227d7deb0a55e67', 'secret_key_sha256': 'd90e3f3a1a507cd21a5bf607744c32f95e23643c66149547b799274294244c59', 'signature_sha256': '069e654a66300c8bfeec4277362c0c678841ba368446fb2b224a727042926ae7'}
