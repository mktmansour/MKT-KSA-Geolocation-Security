use std::fs::{OpenOptions, File};
use std::io::{Write, BufWriter, BufRead, BufReader};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::digest::Digest;
use super::entry::LedgerEntry;
use super::errors::LedgerError;

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
}

// Simple escaping for event field (we assume UTF-8 JSON string provided by caller)
fn escape_event(s: &str) -> String {
    s.replace("|", "%7C").replace("\n", "%0A")
}

fn unescape_event(s: &str) -> String {
    s.replace("%7C", "|").replace("%0A", "\n")
}

// line format: ts_ms|index|prev_hash|event|hash\n
fn encode_line(entry: &LedgerEntry) -> String {
    format!("{}|{}|{}|{}|{}\n", entry.ts_ms, entry.index, entry.prev_hash, escape_event(&entry.event), entry.hash)
}

fn decode_line(line: &str) -> Result<LedgerEntry, LedgerError> {
    let parts: Vec<&str> = line.trim_end().split('|').collect();
    if parts.len() != 5 { return Err(LedgerError::Format("bad columns".into())); }
    let ts_ms: u128 = parts[0].parse().map_err(|_| LedgerError::Format("bad ts".into()))?;
    let index: u64 = parts[1].parse().map_err(|_| LedgerError::Format("bad index".into()))?;
    let prev_hash = parts[2].to_string();
    let event = unescape_event(parts[3]);
    let hash = parts[4].to_string();
    Ok(LedgerEntry { ts_ms, index, prev_hash, event, hash })
}

pub fn append_entry<D: Digest + Default>(path: &Path, prev_hash: &str, index: u64, event_json: &str) -> Result<LedgerEntry, LedgerError> {
    let ts_ms = now_ms();
    // compute hash over canonical raw tuple
    let raw = format!("{}|{}|{}|{}", ts_ms, index, prev_hash, event_json);
    let mut d = D::default();
    d.hash_bytes(raw.as_bytes());
    let hash = d.finalize_hex();
    let entry = LedgerEntry { ts_ms, index, prev_hash: prev_hash.to_string(), event: event_json.to_string(), hash };
    let mut f = BufWriter::new(OpenOptions::new().create(true).append(true).open(path)?);
    f.write_all(encode_line(&entry).as_bytes())?;
    f.flush()?;
    Ok(entry)
}

pub fn read_last_entry(path: &Path) -> Result<Option<LedgerEntry>, LedgerError> {
    if !path.exists() { return Ok(None); }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut last_non_empty = None;
    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() { last_non_empty = Some(line); }
    }
    match last_non_empty {
        None => Ok(None),
        Some(line) => decode_line(&line).map(Some),
    }
}

pub fn append_entry_auto<D: Digest + Default>(path: &Path, event_json: &str) -> Result<LedgerEntry, LedgerError> {
    let (prev_hash, next_index) = match read_last_entry(path)? {
        None => (String::new(), 0u64),
        Some(last) => (last.hash, last.index.saturating_add(1)),
    };
    append_entry::<D>(path, &prev_hash, next_index, event_json)
}


