pub fn to_wide(string: &str) -> Vec<u16> {
    string.encode_utf16().chain(std::iter::once(0)).collect()
}
