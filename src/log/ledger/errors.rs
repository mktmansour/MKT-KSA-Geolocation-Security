use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum LedgerError {
    Io(std::io::Error),
    Integrity(String),
    Format(String),
}

impl Display for LedgerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::Io(e) => write!(f, "io: {}", e),
            LedgerError::Integrity(m) => write!(f, "integrity: {}", m),
            LedgerError::Format(m) => write!(f, "format: {}", m),
        }
    }
}

impl Error for LedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            LedgerError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for LedgerError {
    fn from(e: std::io::Error) -> Self { LedgerError::Io(e) }
}


