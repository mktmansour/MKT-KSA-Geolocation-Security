/*! Arabic: تطبيع AAD بسيط (JCS-like) لضمان ثبات توقيع الظرف
English: Simple AAD canonicalization (JCS-like) for stable envelope signatures */

pub fn canonicalize_pairs(pairs: &[(&str, &str)]) -> String {
    let mut v: Vec<(&str, &str)> = pairs.to_vec();
    v.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = String::new();
    for (i, (k, val)) in v.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(val);
    }
    out
}
