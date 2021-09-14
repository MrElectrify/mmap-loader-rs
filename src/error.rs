#[derive(Debug, thiserror::Error, PartialEq)]
/// An error code associated with loading a PE file
pub enum Error {
    #[error("The DOS header was out of bounds")]
    DOSOutOfBounds,
    #[error("The NT header was out of bounds")]
    NTOutOfBounds,
    #[error("The architecture was unsupported. Only ARM64/x86-64 is supported")]
    UnsupportedArch,
    #[error("A section header was out of bounds")]
    SectOutOfBounds,
    #[error("The entry point was out of bounds")]
    EPOutOfBounds,
    #[error("The import descriptor was out of bounds")]
    IDOutOfBounds,
    #[error("The IAT library name was out of bounds")]
    LibNameOutOfBounds,
    #[error("The IAT thunk was out of bounds")]
    IATOutOfBounds,
    #[error("The procedure name was out of bounds")]
    ProcNameOutOfBounds,
    #[error("The TLS directory was out of bounds")]
    TLSOutOfBounds,
    #[error("The TLS callback was out of bounds")]
    CallbackOutOfBounds,
    #[error("The exception handler table was out of bounds")]
    ExceptionTableOutOfBounds,
    #[error("The system failed to handle TLS data")]
    TLSData,
    #[error("The exception table entry failed")]
    ExceptionTableEntry,
    #[error("The procedure name was null")]
    NullProcName,
    #[error("NTDLL was not loaded")]
    NtDllNotLoaded,
    #[error("NTDLL debug info was missing")]
    NtDllDebugType,
    #[error("NTDLL RSDS signature was missing")]
    NtDllRsdsSig,
    #[error("The loader entry failed to initialize")]
    LdrEntry,
}
