fn main() {
    windows::build! {
        Windows::Win32::Foundation::{CloseHandle, HANDLE},
        Windows::Win32::Storage::FileSystem::CreateFileA,
        Windows::Win32::System::Threading::GetCurrentProcess
    }
}
