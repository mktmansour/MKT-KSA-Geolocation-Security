// Arabic: أدوات مساعدة بسيطة لاستخراج القيم من السطر الاستعلامي
// English: Small helpers to extract values from query-like strings

pub(crate) fn extract_u64(path: &str, key: &str) -> Option<u64> {
    if let Some(pos) = path.find(key) {
        let s = &path[pos + key.len()..];
        let n: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(v) = n.parse() {
            return Some(v);
        }
    }
    None
}

pub(crate) fn extract_u8(path: &str, key: &str) -> Option<u8> {
    if let Some(pos) = path.find(key) {
        let s = &path[pos + key.len()..];
        let n: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(v) = n.parse() {
            return Some(v);
        }
    }
    None
}

pub(crate) fn extract_str(path: &str, key: &str) -> Option<String> {
    if let Some(pos) = path.find(key) {
        let s = &path[pos + key.len()..];
        let val: String = s.chars().take_while(|c| *c != '&').collect();
        if !val.is_empty() {
            return Some(val);
        }
    }
    None
}
