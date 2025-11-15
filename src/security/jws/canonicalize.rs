use serde_json::{Map, Value};

/// Arabic: تطبيع JSON بسيط (JCS-like): ترتيب مفاتيح القواميس وطباعة مضغوطة
/// English: Simple JSON canonicalization (JCS-like): sort object keys, compact print
pub fn canonicalize_json_compact(v: &Value) -> Result<Vec<u8>, serde_json::Error> {
    fn sort_value(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<_> = m.keys().cloned().collect();
                keys.sort();
                let mut out = Map::new();
                for k in keys {
                    out.insert(k.clone(), sort_value(&m[&k]));
                }
                Value::Object(out)
            }
            Value::Array(arr) => Value::Array(arr.iter().map(sort_value).collect()),
            _ => v.clone(),
        }
    }
    let sorted = sort_value(v);
    let s = serde_json::to_string(&sorted)?;
    Ok(s.into_bytes())
}
