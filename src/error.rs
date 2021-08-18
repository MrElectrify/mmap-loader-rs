/// There is no enumeration because none of these
/// errors are recoverable
#[derive(Debug)]
pub struct Error {
    pub err: &'static str,
}

impl From<&'static str> for Error {
    fn from(err: &'static str) -> Self {
        Error { err }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.err)
    }
}

impl std::error::Error for Error {}
