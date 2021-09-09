#[derive(Debug, PartialEq)]
pub enum Err {
    FileNotFound,
    DOSOutOfBounds,
    NTOutOfBounds,
    UnsupportedArch,
    SectOutOfBounds,
    EPOutOfBounds,
    IDOutOfBounds,
    LibNameOutOfBounds,
    IATOutOfBounds,
    ProcNameOutOfBounds,
    TLSOutOfBounds,
    CallbackOutOfBounds,
    ExceptionTableOutOfBounds,
    TLSData,
    ExceptionTableEntry,
    NullProcName,
    NtDllNotLoaded,
    NtDllDebugType,
    NtDllRsdsSig,
    LdrEntry,
}

#[derive(Debug)]
pub struct Error(pub Err);

impl Error {
    pub fn err_str(&self) -> &str {
        match self.0 {
            Err::FileNotFound => "The file path was not resolved",
            Err::DOSOutOfBounds => "The DOS header was out of bounds",
            Err::NTOutOfBounds => "The NT header was out of bounds",
            Err::UnsupportedArch => {
                "The architecture was unsupported. Only ARM64/x86-64 is supported."
            }
            Err::SectOutOfBounds => "A section header was out of bounds",
            Err::EPOutOfBounds => "The entry point was out of bounds",
            Err::IDOutOfBounds => "The import descriptor was out of bounds",
            Err::LibNameOutOfBounds => "The IAT library name was out of bounds",
            Err::IATOutOfBounds => "The IAT thunk was out of bounds",
            Err::ProcNameOutOfBounds => "The procedure name was out of bounds",
            Err::TLSOutOfBounds => "The TLS directory was out of bounds",
            Err::CallbackOutOfBounds => "The TLS callback was out of bounds",
            Err::ExceptionTableOutOfBounds => "The exception handler table was out of bounds",
            Err::TLSData => "The system failed to handle TLS data",
            Err::ExceptionTableEntry => "The exception table entry failed",
            Err::NullProcName => "The procedure name was null",
            Err::NtDllNotLoaded => "NTDLL was not loaded",
            Err::NtDllDebugType => "NTDLL debug info was missing",
            Err::NtDllRsdsSig => "NTDLL RSDS signature was missing",
            Err::LdrEntry => "The loader entry failed to initialize",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl std::error::Error for Error {}
