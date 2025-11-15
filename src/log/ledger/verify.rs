use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use super::digest::Digest;
use super::entry::LedgerEntry;
use super::errors::LedgerError;
use super::writer::decode_line; // use internal codec

/// Arabic: يتحقق من سلامة سلسلة السجل، ويعيد (آخر فهرس، آخر تجزئة)
/// English: Verifies the ledger chain integrity, returning (last index, last hash)
pub fn verify_file_chain<D: Digest + Default>(path: &Path) -> Result<(u64, String), LedgerError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut expected_prev = String::new();
    let mut last_index: u64 = 0;
    let mut last_hash = String::new();

    for (line_no, line_res) in reader.lines().enumerate() {
        let line = line_res?;
        if line.trim().is_empty() { continue; }
        let entry: LedgerEntry = decode_line(&line)?;
        // Recompute hash over canonical raw tuple
        let raw = format!("{}|{}|{}|{}", entry.ts_ms, entry.index, entry.prev_hash, entry.event);
        let mut d = D::default();
        d.hash_bytes(raw.as_bytes());
        let recomputed = d.finalize_hex();

        if !expected_prev.is_empty() && entry.prev_hash != expected_prev {
            return Err(LedgerError::Integrity(format!(
                "prev_hash mismatch at line {} (index {}): expected {}, got {}",
                line_no + 1,
                entry.index,
                expected_prev,
                entry.prev_hash
            )));
        }
        if recomputed != entry.hash {
            return Err(LedgerError::Integrity(format!(
                "hash mismatch at line {} (index {}): computed {}, stored {}",
                line_no + 1,
                entry.index,
                recomputed,
                entry.hash
            )));
        }
        expected_prev = entry.hash.clone();
        last_index = entry.index;
        last_hash = entry.hash;
    }

    Ok((last_index, last_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    use crate::log::ledger::writer::{append_entry, append_entry_auto};

    #[cfg(feature = "ledger_blake3")]
    #[test]
    fn chain_roundtrip_blake3() {
        let tmp = NamedTempFile::new().unwrap();
        let p = tmp.path().to_path_buf();

        let e0 = append_entry::<crate::log::ledger::digest::blake3_impl::Blake3Digest>(&p, "", 0, "{\"ev\":1}").unwrap();
        let _e1 = append_entry_auto::<crate::log::ledger::digest::blake3_impl::Blake3Digest>(&p, "{\"ev\":2}").unwrap();

        let (last_idx, _last_hash) = verify_file_chain::<crate::log::ledger::digest::blake3_impl::Blake3Digest>(&p).unwrap();
        assert_eq!(last_idx, 1);
        assert!(!_last_hash.is_empty());
        assert!(!e0.hash.is_empty());
    }
}
