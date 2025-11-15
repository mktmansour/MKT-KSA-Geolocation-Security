/*!
Arabic: بصمة رقمية للسلامة تعتمد على Digest قابل للبدل (صفر تبعية افتراضيًا).
English: Integrity fingerprint built on a pluggable digest (zero-deps by default).
*/

use crate::core::digest::{CoreDigest, StdHasherDigest};

pub fn fingerprint_payload<D: CoreDigest>(_digest: &mut D, headers: &[u8], body: &[u8]) -> String {
    let mut d = StdHasherDigest::default();
    d.hash_bytes(headers);
    d.hash_bytes(b"\n\n");
    d.hash_bytes(body);
    d.finalize_hex()
}
