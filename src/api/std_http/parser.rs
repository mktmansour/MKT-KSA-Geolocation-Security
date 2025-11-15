// Arabic: دوال تحليل بسيطة للـ URL والاستعلام والنماذج (صفر تبعيات)
// English: Small parsing helpers for URL, query and form params (zero-deps)

pub(crate) fn parse_query_params(path: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();

    if let Some(query_start) = path.find('?') {
        let query = &path[query_start + 1..];
        for param in query.split('&') {
            if let Some(eq_pos) = param.find('=') {
                let key = url_decode(&param[..eq_pos]);
                let value = url_decode(&param[eq_pos + 1..]);
                params.insert(key, value);
            }
        }
    }

    params
}

pub(crate) fn parse_form_params(body: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();

    for param in body.split('&') {
        if let Some(eq_pos) = param.find('=') {
            let key = url_decode(&param[..eq_pos]);
            let value = url_decode(&param[eq_pos + 1..]);
            params.insert(key, value);
        }
    }

    params
}

pub(crate) fn url_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut bytes = input.as_bytes().iter().copied().peekable();
    while let Some(b) = bytes.next() {
        match b {
            b'+' => out.push(' '),
            b'%' => {
                let hi = bytes.next();
                let lo = bytes.next();
                if let (Some(h), Some(l)) = (hi, lo) {
                    let hex = [h, l];
                    let as_str = core::str::from_utf8(&hex).unwrap_or("00");
                    if let Ok(v) = u8::from_str_radix(as_str, 16) {
                        out.push(v as char);
                    } else {
                        out.push('%');
                        out.push(h as char);
                        out.push(l as char);
                    }
                } else {
                    out.push('%');
                }
            }
            _ => out.push(b as char),
        }
    }
    out
}
