use actix_web::http::header::{HeaderMap, CONTENT_LENGTH, TRANSFER_ENCODING};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestFramingError {
    AmbiguousContentLength,
    ConflictingMessageFraming,
    UnsupportedTransferEncoding,
}

fn normalize_header_values(
    headers: &HeaderMap,
    header_name: actix_web::http::header::HeaderName,
) -> Vec<String> {
    headers
        .get_all(header_name)
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

pub fn validate_request_framing(headers: &HeaderMap) -> Result<(), RequestFramingError> {
    let content_lengths = normalize_header_values(headers, CONTENT_LENGTH);
    let transfer_encodings = normalize_header_values(headers, TRANSFER_ENCODING);

    if content_lengths.len() > 1 {
        return Err(RequestFramingError::AmbiguousContentLength);
    }

    if !content_lengths.is_empty() && !transfer_encodings.is_empty() {
        return Err(RequestFramingError::ConflictingMessageFraming);
    }

    if transfer_encodings.len() > 1 {
        return Err(RequestFramingError::UnsupportedTransferEncoding);
    }

    if let Some(value) = transfer_encodings.first() {
        if value != "chunked" && value != "identity" {
            return Err(RequestFramingError::UnsupportedTransferEncoding);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::{HeaderValue, CONTENT_LENGTH, TRANSFER_ENCODING};

    #[test]
    fn accepts_single_content_length() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("42"));
        assert_eq!(validate_request_framing(&headers), Ok(()));
    }

    #[test]
    fn rejects_conflicting_content_length_and_transfer_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("42"));
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert_eq!(
            validate_request_framing(&headers),
            Err(RequestFramingError::ConflictingMessageFraming)
        );
    }

    #[test]
    fn rejects_ambiguous_content_length_values() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("42"));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("43"));
        assert_eq!(
            validate_request_framing(&headers),
            Err(RequestFramingError::AmbiguousContentLength)
        );
    }
}
